"""Registration contract and three-layer scaffold for Sophos Firewall MCP tools.

Every domain module (#27-#31 and later phase-2 domains) registers its tools through this
module. Nothing here
creates an HTTP client, reads the environment or touches the network: the server factory
in :mod:`sophos_firewall_mcp.server` owns the lifespan, and this module owns the shape
that domain modules must follow.

Three layers (PLAN.md section 3)
--------------------------------
1. **MCP handler** -- a typed ``async def`` registered with :func:`register_tool`. It
   takes a Pydantic input model (closed with ``extra="forbid"`` where the Sophos
   operation is closed) and a typed ``Context[AppContext]`` injected by the SDK. It
   validates the model-facing contract, resolves the application context and delegates
   to a domain adapter. The ``Context`` parameter never appears in the published input
   schema.
2. **Domain adapter** -- a :class:`DomainAdapter` subclass. It owns the ``/``-prefixed
   API path constants and the Pydantic models of one domain, calls the shared REST
   client and projects Sophos payloads into bounded MCP output DTOs. It must not create
   an HTTP client and must not accept a path, URL or header from a tool argument.
3. **REST transport** -- the single :class:`~sophos_firewall_mcp.client.SophosRestClient`
   created by the lifespan and reached through
   ``ctx.request_context.lifespan_context.client``.

Registration contract
---------------------
Every domain module exposes exactly one function with this signature::

    def register_<domain>_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
        ...

and registers each tool through :func:`register_tool`. Issue #26 illustrates the second
parameter as a ``Callable[[], AppContext]``; this project uses the SDK's typed
``Context[AppContext]`` injection instead, because the pinned SDK v2 lifespan guide makes
that the documented way to reach the lifespan object and the issue requires it. The
read-only flag is passed explicitly because the tool set is fixed at construction, before
the lifespan creates the client. :data:`DomainRegistrar` is the protocol every domain
module implements.

Read-only mode
--------------
``SOPHOS_READ_ONLY_MODE=true`` is resolved by the server factory before any domain
registers a tool and is passed to every registration function. :func:`register_tool`
refuses to register a :attr:`ToolKind.MUTATION` tool when ``read_only`` is true: the
handler is returned unchanged and never reaches the SDK tool registry, so a read-only
deployment does not merely hide mutation tools -- it does not have them. This is defense
in depth on top of a Sophos administrator profile with ``Read-only`` permissions, not a
substitute for it.

Errors
------
:func:`tool_error` maps the typed transport failures from
:mod:`sophos_firewall_mcp.errors` to sanitized :class:`~mcp.server.mcpserver.exceptions.ToolError`
messages the model can act on. Unexpected exceptions are deliberately not caught: they
propagate to the SDK, which logs the traceback on the server and reports only
``Error executing tool <name>`` to the model. ``CancelledError`` is never swallowed.

Argument validation
-------------------
The SDK validates a call against an argument model it derives from the handler signature,
before the handler runs, and renders a failure with the raw pydantic dump: the internal
argument-model name, the rejected input values and a documentation URL. :func:`register_tool`
replaces that model with a closed, sanitized subclass, so an unknown argument is rejected
instead of silently dropped and the model only sees the field path and the rule. The
replacement reaches the registered tool through the SDK's private registry; see the seam
note above :func:`_registered_tool` for the pinned version and the exact attributes.

The same registration step documents the ``request`` wrapper: the SDK's single-argument
convention is unusual for MCP, where flat arguments are the norm, and the domain
descriptions only describe the inner fields. :func:`register_tool` appends one sentence to
the description of every tool whose published input schema declares the wrapper, so the
convention is explained once instead of in every domain module.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Callable, Protocol, Self, TypeVar, cast

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.tools import Tool
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, ValidationError

from sophos_firewall_mcp.client import SophosRestClient
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import (
    SophosAmbiguousWriteError,
    SophosAPIError,
    SophosAuthError,
    SophosConflictError,
    SophosNotFoundError,
    SophosTransportError,
    SophosValidationError,
)

__all__ = [
    "DomainAdapter",
    "DomainRegistrar",
    "ToolKind",
    "register_tool",
    "tool_error",
]

#: Tool names are lower snake_case and at most 64 characters (MCP tool-name guidance).
_TOOL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

#: Upper bound for a model-facing error message, in characters.
_MAX_ERROR_LENGTH = 300

#: Characters that may appear in an appliance error code before it reaches a message.
_ERROR_CODE_PATTERN = re.compile(r"[^A-Za-z0-9_.:-]")

#: Angle brackets are dropped from model-facing error text so a host cannot render an
#: appliance-supplied value as HTML.
_UNSAFE_CHARACTERS = frozenset("<>")

#: Model-facing text for HTTP 401: the key itself is the problem, not the profile.
_AUTHENTICATION_DETAIL = (
    "authentication failed: the API key is missing, invalid or expired; check "
    "SOPHOS_API_KEY or SOPHOS_API_KEY_FILE"
)

#: Model-facing text for HTTP 403: the key is valid but the profile forbids the operation.
_AUTHORIZATION_DETAIL = (
    "the Sophos administrator associated with this API key is not allowed to perform "
    "this operation; check its profile permissions"
)

#: Model-facing text for an auth failure whose status is neither 401 nor 403.
_AUTH_DETAIL = (
    "authentication or authorization failed; check the API key and the administrator "
    "profile permissions"
)

#: Model-facing rule for the pydantic error types an argument model can raise. The
#: pydantic ``msg`` is used for a type that is not listed; it never echoes the rejected
#: value, only the rule.
_ARGUMENT_RULES: dict[str, str] = {
    "missing": "is required",
    "extra_forbidden": "is not an accepted argument",
    "literal_error": "must be one of {expected}",
    "enum": "must be one of {expected}",
    "int_parsing": "must be an integer",
    "int_type": "must be an integer",
    "int_from_float": "must be an integer",
    "bool_parsing": "must be a boolean",
    "bool_type": "must be a boolean",
    "string_type": "must be a string",
    "list_type": "must be a list",
    "dict_type": "must be an object",
    "greater_than_equal": "must be greater than or equal to {ge}",
    "less_than_equal": "must be less than or equal to {le}",
    "greater_than": "must be greater than {gt}",
    "less_than": "must be less than {lt}",
    "string_too_short": "must be at least {min_length} characters long",
    "string_too_long": "must be at most {max_length} characters long",
}

#: Sentence appended to the description of every tool whose input schema declares the
#: ``request`` wrapper. The wrapper is the SDK's single-argument convention and is unusual
#: for MCP, where flat arguments are the norm, so a model that follows a description such
#: as "Inputs: optional ip_family" calls the tool with flat arguments and is rejected with
#: a bare "request is required". Explaining it once, centrally, keeps every domain
#: description free of boilerplate and cannot drift from the published schema.
#:
#: The example is deliberately neutral -- ``{"request": {...}}`` -- and names no field.
#: The sentence is shared by 144 tools whose request models have different fields, so any
#: single named field is wrong for most of them: the previous hard-coded
#: ``{"request": {"page": 1}}`` named a field only 41 tools accept and told the model to
#: send an argument the other 103 reject. The inner fields are already documented by each
#: tool's own description and published schema, so this sentence only has to show the
#: nesting. ``tests/test_server.py`` sweeps every wrapped tool and fails if the example
#: ever names a field that tool does not accept.
_REQUEST_WRAPPER_NOTE = (
    "Arguments are passed inside a `request` object, for example "
    '`{"request": {...}}`, not at the top level.'
)

ToolHandlerT = TypeVar("ToolHandlerT", bound=Callable[..., Any])
"""A registered tool function: a typed ``async def`` with an optional ``Context``."""

ModelT = TypeVar("ModelT", bound=BaseModel)
"""A pydantic model class, used to keep the argument-model swap type-preserving."""


class ToolKind(Enum):
    """Whether a tool only reads from the appliance or mutates it.

    The classification is mandatory at registration because it drives two decisions:
    the read-only filter (a mutation tool is not registered in read-only mode) and the
    annotation policy (write hints are meaningless on a read-only tool).
    """

    READ = "read"
    MUTATION = "mutation"


class DomainRegistrar(Protocol):
    """The signature every ``register_<domain>_tools`` function implements.

    The server factory calls it once per domain, before the lifespan starts, with the
    read-only mode resolved from ``SOPHOS_READ_ONLY_MODE``. The implementation registers
    its tools through :func:`register_tool` and returns nothing.
    """

    def __call__(self, server: MCPServer[AppContext], *, read_only: bool) -> None: ...


class DomainAdapter:
    """Base class for the domain adapter layer.

    A domain adapter sits between an MCP handler and the REST transport. It owns the API
    path constants and the Pydantic models of one domain, calls the shared
    :class:`~sophos_firewall_mcp.client.SophosRestClient` and projects Sophos payloads
    into bounded MCP DTOs. It never creates an HTTP client: the client comes from the
    :class:`~sophos_firewall_mcp.context.AppContext` the lifespan created.

    Example::

        class FirewallAdapter(DomainAdapter):
            RULES_PATH = "/firewall/rules/ipv4"

            async def list_rules(self, page: int) -> ListRulesOutput:
                try:
                    payload = await self.client.get_page(self.RULES_PATH, page=page)
                except SophosAPIError as exc:
                    raise tool_error(exc) from exc
                return ListRulesOutput(items=[...])

        async def list_rules(request: ListRulesInput, ctx: Context[AppContext]) -> ListRulesOutput:
            return await FirewallAdapter.from_context(ctx).list_rules(request.page)
    """

    def __init__(self, context: AppContext) -> None:
        if not isinstance(context, AppContext):
            raise TypeError("context must be an AppContext")
        self._context = context

    @property
    def context(self) -> AppContext:
        """The shared application context for this request."""
        return self._context

    @property
    def client(self) -> SophosRestClient:
        """The process-wide REST client; never create another one."""
        return self._context.client

    @property
    def read_only(self) -> bool:
        """Whether the server was started in read-only mode."""
        return self._context.read_only

    @classmethod
    def from_context(cls, ctx: Context[AppContext]) -> Self:
        """Build the adapter for the current request from the SDK-injected context."""
        return cls(ctx.request_context.lifespan_context)


def register_tool(
    server: MCPServer[AppContext],
    *,
    read_only: bool,
    kind: ToolKind,
    name: str,
    title: str,
    description: str,
    annotations: ToolAnnotations | None = None,
) -> Callable[[ToolHandlerT], ToolHandlerT]:
    """Register one tool under the project's contract.

    Args:
        server: The server built by :func:`sophos_firewall_mcp.server.create_server`.
        read_only: The mode resolved from ``SOPHOS_READ_ONLY_MODE``. When true, a
            :attr:`ToolKind.MUTATION` tool is not registered at all.
        kind: Read-only or mutation classification; drives filtering and annotations.
        name: Lower snake_case tool name, at most 64 characters.
        title: Human-readable title shown to the model.
        description: What the tool does, when to use it, required identifiers, side
            effects and limitations. Must be actionable on its own.
        annotations: Optional annotations. For a mutation tool ``destructive_hint`` and
            ``idempotent_hint`` are mandatory; for a read-only tool write hints are
            rejected. ``title``, ``read_only_hint`` and ``open_world_hint`` are filled in
            by this helper.

    Returns:
        A decorator that registers the function and returns it unchanged, so the handler
        stays directly callable in tests.

    The registered tool accepts exactly the arguments its signature declares: the SDK's
    argument model is closed (``extra="forbid"``) and its validation failures are
    sanitized, so a misspelled argument is reported instead of silently ignored and the
    model never sees the internal model name or a pydantic URL.

    A tool that takes arguments also gets one sentence appended to its published
    description explaining the ``request`` wrapper (see :data:`_REQUEST_WRAPPER_NOTE`).
    The caller's ``description`` is not modified in place and no domain has to repeat the
    sentence.

    Raises:
        ValueError: The metadata is invalid or the annotations contradict the kind.
    """
    _check_metadata(name=name, title=title, description=description)
    resolved_annotations = _build_annotations(kind=kind, annotations=annotations, title=title)

    if kind is ToolKind.MUTATION and read_only:
        # Read-only deployment: the mutation handler is never added to the registry.
        def skip(fn: ToolHandlerT) -> ToolHandlerT:
            return fn

        return skip

    def decorator(fn: ToolHandlerT) -> ToolHandlerT:
        server.add_tool(
            fn,
            name=name,
            title=title,
            description=description,
            annotations=resolved_annotations,
        )
        tool = _close_argument_model(server, name)
        _document_request_wrapper(tool)
        return fn

    return decorator


def _auth_detail(status: int | None) -> str:
    """Pick the model-facing text for an auth failure from its HTTP status.

    A 401 and a 403 are different failures with different fixes, so they must not share a
    message: reporting a bad key as a permission problem sends the caller to change the
    administrator profile instead of the key.
    """
    if status == 401:
        return _AUTHENTICATION_DETAIL
    if status == 403:
        return _AUTHORIZATION_DETAIL
    return _AUTH_DETAIL


def tool_error(exc: SophosAPIError) -> ToolError:
    """Translate a typed Sophos transport failure into a sanitized ``ToolError``.

    The message is built from the exception type, status and appliance error code -- not
    from the raw response body, the API key or any header -- so the model receives a
    clear, actionable failure it can recover from. The original exception is kept as the
    cause (``raise tool_error(exc) from exc``) for server-side logs.

    Args:
        exc: Any exception from the :class:`~sophos_firewall_mcp.errors.SophosAPIError`
            hierarchy raised by the shared client.

    Returns:
        A :class:`~mcp.server.mcpserver.exceptions.ToolError` whose message names the
        failure class and the operation, without secrets or raw payloads.
    """
    if isinstance(exc, SophosNotFoundError):
        detail = "the requested Sophos object does not exist; check the name or id"
    elif isinstance(exc, SophosAuthError):
        detail = _auth_detail(exc.status)
    elif isinstance(exc, SophosValidationError):
        detail = "the firewall rejected the request as invalid; check the field values"
    elif isinstance(exc, SophosConflictError):
        detail = "the request conflicts with the current firewall state; re-read and retry"
    elif isinstance(exc, SophosAmbiguousWriteError):
        detail = "the write may or may not have been applied; read the object back before retrying"
    elif isinstance(exc, SophosTransportError):
        detail = "the firewall could not be reached or did not answer in time; retry the read"
    else:
        detail = "the firewall returned an unexpected error"

    status = f" (HTTP {exc.status})" if exc.status is not None else ""
    operation = ""
    if exc.method and exc.path:
        operation = f" [{exc.method} {exc.path}]"
    elif exc.path:
        operation = f" [{exc.path}]"
    error_code = ""
    if exc.error_code:
        sanitized_code = _ERROR_CODE_PATTERN.sub("", exc.error_code.strip())[:64]
        if sanitized_code:
            error_code = f" [error: {sanitized_code}]"

    return ToolError(_sanitize(f"{detail}{status}{operation}{error_code}"))


class _SanitizedArgumentError(ValidationError):
    """A ``ValidationError`` whose ``str()`` is the sanitized, model-facing message.

    The SDK renders an argument-validation failure with ``str(exc)`` and catches
    ``ValidationError`` to report it as an anticipated failure. Subclassing keeps both
    behaviours -- ``Tool.run`` still catches it and ``__cause__.errors()`` still works --
    while the model only sees the sanitized line instead of the raw pydantic dump.
    """

    _sanitized_message: str = ""

    def __str__(self) -> str:
        return self._sanitized_message


# -- Private SDK seam: closing a registered tool's argument model ----------------------
#
# Pinned SDK: mcp 2.3.0 (pyproject.toml declares mcp>=2.3.0,<3; uv.lock pins 2.3.0).
#
# mcp 2.3.0 exposes no public way to close the argument model of a tool that is already
# registered:
#   * MCPServer.add_tool() returns None, so the Tool it built is not handed back;
#   * MCPServer.list_tools() returns the wire MCPTool, which carries the JSON schema but
#     not the pydantic argument model;
#   * MCPServer has no public get_tool();
#   * Tool.from_function()/func_metadata() accept no argument-model override.
# The only route is the private attribute below, so it is confined to one accessor.
#
# Exact private surface this module depends on (mcp 2.3.0):
#   MCPServer._tool_manager       private attribute, set in MCPServer.__init__
#   ToolManager.get_tool(name)    public method on that private object
#   Tool.fn_metadata.arg_model    read by Tool.run -> FuncMetadata.validate_arguments
#   Tool.parameters               returned as input_schema by MCPServer.list_tools
# If any of these moves, _registered_tool raises and tests/test_server.py fails.
def _registered_tool(server: MCPServer[AppContext], name: str) -> Tool | None:
    """Return the SDK's internal ``Tool`` for ``name`` through the pinned private seam.

    This is the only place in the package that touches ``MCPServer._tool_manager``; see
    the seam note above for the pinned version and the exact attributes it relies on.
    """
    manager = getattr(server, "_tool_manager", None)
    if manager is None:
        raise RuntimeError(
            "the pinned MCP SDK seam moved: MCPServer._tool_manager is missing (expected "
            "mcp 2.3.0). Argument validation for every tool depends on it; see the seam "
            "note in sophos_firewall_mcp.tools."
        )
    return cast(Tool | None, manager.get_tool(name))


def _close_argument_model(server: MCPServer[AppContext], name: str) -> Tool | None:
    """Replace a registered tool's argument model with the closed, sanitized subclass.

    The SDK derives one argument model per tool from the handler signature and validates
    every call against it before the handler runs. That model is the only seam: it accepts
    unknown top-level arguments (``extra`` defaults to ``ignore``) and renders a failure as
    the raw pydantic dump. Swapping it changes both behaviours without touching the
    published input schema, which was derived from the original model at registration.

    ``add_tool`` returns nothing, so the registered tool is read back through the SDK's
    private tool manager (:func:`_registered_tool`, the single accessor for that seam).
    The access is deliberate and pinned: the argument-validation tests fail if a future
    SDK stops exposing the model there.

    Returns:
        The registered tool, so the caller can apply the remaining description-level
        documentation without reading the seam twice.
    """
    tool = _registered_tool(server, name)
    if tool is None:  # pragma: no cover - add_tool registered it immediately above
        return None
    tool.fn_metadata.arg_model = _sanitized_argument_model(tool.fn_metadata.arg_model)
    # The published schema must say what the runtime now enforces.
    tool.parameters = {**tool.parameters, "additionalProperties": False}
    return tool


def _document_request_wrapper(tool: Tool | None) -> None:
    """Explain the ``request`` wrapper in the description of a tool that takes arguments.

    The sentence is added centrally, from the published input schema, so no domain
    description repeats it and it cannot drift from the schema: a tool whose schema
    declares a ``request`` property gets the note, and a no-argument tool (whose schema
    has no properties) is left alone. The wrapper itself is unchanged -- it is the SDK's
    single-argument convention, not something this project can flatten.
    """
    if tool is None:  # pragma: no cover - add_tool registered it immediately above
        return
    if "request" not in tool.parameters.get("properties", {}):
        return
    tool.description = f"{tool.description} {_REQUEST_WRAPPER_NOTE}"


def _sanitized_argument_model(model: type[ModelT]) -> type[ModelT]:
    """Return a subclass of the SDK's argument model with a closed, sanitized contract."""

    class Sanitized(model):  # type: ignore[misc, valid-type]
        model_config = ConfigDict(extra="forbid")

        @classmethod
        def model_validate(cls, obj: Any, **kwargs: Any) -> BaseModel:
            try:
                # ``super()`` keeps ``cls``, so the closed config above is the one applied.
                return cast(BaseModel, super().model_validate(obj, **kwargs))
            except ValidationError as exc:
                raise _sanitized_argument_error(exc, cls) from None

    return cast(type[ModelT], Sanitized)


def _sanitized_argument_error(exc: ValidationError, model: type[BaseModel]) -> ValidationError:
    """Build the sanitized ``ValidationError`` the SDK renders for the model."""
    # ``errors()`` carries the same entries ``from_exception_data`` accepts; the extra
    # ``msg``/``url`` keys are ignored by the constructor.
    sanitized = _SanitizedArgumentError.from_exception_data(
        "invalid arguments", cast(Any, exc.errors())
    )
    sanitized._sanitized_message = _argument_error_message(exc, model)
    return sanitized


def _argument_error_message(exc: ValidationError, model: type[BaseModel]) -> str:
    """Render an argument-validation failure as one actionable line.

    The raw pydantic dump names the internal argument model, echoes the rejected input and
    links to the pydantic documentation; none of that helps a model correct its call. Only
    the field path and the rule are kept, plus the accepted names when the caller used an
    unknown one.
    """
    details: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ())) or "arguments"
        rule = _argument_rule(error)
        detail = f"{location} {rule}"
        if error.get("type") == "extra_forbidden":
            accepted = _accepted_arguments(model, error.get("loc", ()))
            if accepted:
                detail = f"{detail}; {accepted}"
        details.append(detail)
    return _sanitize("invalid arguments: " + "; ".join(details))


def _argument_rule(error: Any) -> str:
    """Render one pydantic error as a rule, falling back to its (input-free) message."""
    rule = _ARGUMENT_RULES.get(error.get("type", ""))
    if rule is None:
        return str(error.get("msg", "is invalid"))
    try:
        return rule.format(**(error.get("ctx") or {}))
    except KeyError:
        return str(error.get("msg", "is invalid"))


def _accepted_arguments(model: type[BaseModel], location: tuple[Any, ...]) -> str:
    """Name the arguments the caller could have used at the rejected field's level."""
    parent: type[BaseModel] = model
    for part in location[:-1]:
        annotation = _field_annotation(parent, str(part))
        if not (isinstance(annotation, type) and issubclass(annotation, BaseModel)):
            return ""
        parent = annotation
    names = list(parent.model_fields)
    if not names:
        return "this tool accepts no arguments"
    return f"accepted arguments are {', '.join(names)}"


def _field_annotation(model: type[BaseModel], name: str) -> Any:
    """Return the annotation of the field called ``name`` (or aliased to it), if any."""
    for field_name, field in model.model_fields.items():
        if field_name == name or field.alias == name:
            return field.annotation
    return None


def _check_metadata(*, name: str, title: str, description: str) -> None:
    """Reject tool metadata that would publish a confusing or invalid contract."""
    if _TOOL_NAME_PATTERN.match(name) is None:
        raise ValueError(
            "tool name must be lower snake_case, start with a letter and be at most 64 "
            f"characters; got {name!r}"
        )
    if not title.strip():
        raise ValueError(f"tool {name!r} must have a non-empty title")
    if not description.strip():
        raise ValueError(f"tool {name!r} must have a non-empty description")


def _build_annotations(
    *, kind: ToolKind, annotations: ToolAnnotations | None, title: str
) -> ToolAnnotations:
    """Fill in the annotation policy for the tool kind and reject contradictions."""
    resolved = annotations if annotations is not None else ToolAnnotations()
    open_world = True if resolved.open_world_hint is None else resolved.open_world_hint

    if kind is ToolKind.READ:
        if resolved.read_only_hint is False:
            raise ValueError("a read-only tool cannot declare readOnlyHint=False")
        if resolved.destructive_hint is not None or resolved.idempotent_hint is not None:
            raise ValueError(
                "read-only tools must not declare destructiveHint or idempotentHint: "
                "those hints describe write operations"
            )
        return resolved.model_copy(
            update={"title": title, "read_only_hint": True, "open_world_hint": open_world}
        )

    if resolved.read_only_hint is True:
        raise ValueError("a mutation tool cannot declare readOnlyHint=True")
    if resolved.destructive_hint is None or resolved.idempotent_hint is None:
        raise ValueError(
            "mutation tools must declare destructiveHint and idempotentHint explicitly: "
            "create, update, delete, move and disconnect have different risk and "
            "idempotence"
        )
    return resolved.model_copy(
        update={"title": title, "read_only_hint": False, "open_world_hint": open_world}
    )


def _sanitize(text: str, *, limit: int = _MAX_ERROR_LENGTH) -> str:
    """Collapse whitespace, drop control and markup characters, and bound the length."""
    collapsed = " ".join(text.split())
    printable = "".join(
        character
        for character in collapsed
        if character.isprintable() and character not in _UNSAFE_CHARACTERS
    )
    if len(printable) > limit:
        printable = printable[: limit - 3].rstrip() + "..."
    return printable
