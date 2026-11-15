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
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Callable, Protocol, Self, TypeVar

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

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

ToolHandlerT = TypeVar("ToolHandlerT", bound=Callable[..., Any])
"""A registered tool function: a typed ``async def`` with an optional ``Context``."""


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
        return fn

    return decorator


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
        detail = (
            "the Sophos administrator associated with this API key is not allowed to "
            "perform this operation; check its profile permissions"
        )
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
