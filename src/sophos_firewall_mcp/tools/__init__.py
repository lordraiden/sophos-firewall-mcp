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

and registers each tool through :func:`register_tool`. The second parameter is illustrated
as a ``Callable[[], AppContext]``; this project uses the SDK's typed
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

Flat arguments
--------------
The SDK derives one argument field per handler parameter, so a handler that takes a single
``request`` model publishes a ``request`` wrapper. MCP's own examples are flat and a model's
prior is flat, so the wrapper is a per-call failure mode that has to be explained in prose.

:func:`register_tool` publishes the request model's own fields at the top level instead. The
argument model becomes the request model itself -- closed and sanitized as above -- and its
``model_dump_one_level`` hands the validated instance back under the ``request`` key, which
is the key the handler already declares. The handler, its signature and the wire body are
unchanged; only the published ``inputSchema`` and the accepted argument shape are flat. A
tool whose request is a discriminated union publishes a root ``oneOf`` of the closed
variants, because flattening a union into one object would lose the per-variant required
fields.

Destructive confirmation
------------------------
The four highest-blast-radius deletes -- ``firewall_rule_delete``, ``nat_rule_delete``,
``network_user_delete`` and ``network_interface_delete_vlan`` -- require an explicit
client confirmation before the appliance is touched. Each handler declares a
``Resolve``-injected confirmation parameter (:func:`destructive_confirmation`), so the SDK
asks the question *before* the handler body runs and the body only executes once the
client has accepted.

The question is delivered on both protocol eras without emulating a server-initiated
request the negotiated protocol no longer supports:

* on the modern ``2026-07-28`` protocol the SDK batches the question into an
  ``InputRequiredResult``; the client answers and retries the same call with
  ``inputResponses`` and ``requestState``, and the SDK resumes the handler exactly once;
* on the legacy handshake (``2024-11-05`` .. ``2025-11-25``) the SDK sends the same
  question as a standalone elicitation request.

The confirmation fails closed. A declined or cancelled answer, an ``accept`` that does not
set ``confirm``, a client that declared no form-mode ``elicitation`` capability, and a
transport that cannot carry the question all abort the call with a sanitized
:class:`~mcp.server.mcpserver.exceptions.ToolError` before any HTTP request is made. The
spec's backwards-compatible ``"elicitation": {}`` declaration counts as form-mode support.
The SDK seals the resume state and binds it to the tool name, the canonical arguments, the
authenticated principal and a TTL, so a resumed call can only execute the originally
confirmed target; a missing, malformed, expired or mismatched state is rejected before the
handler runs. The state is also single-use: :mod:`sophos_firewall_mcp.mrtr` refuses a
second use of the same sealed token, so a retry cannot execute the confirmed delete twice
(:data:`CONFIRMATION_NOTE` is the model-facing summary).

Mutation annotations
--------------------
Every mutation tool declares ``destructiveHint`` and ``idempotentHint`` explicitly;
:func:`_build_annotations` rejects a mutation that omits either, so a new tool cannot
silently inherit the spec default. The surface uses two shared pairs,
:data:`ADDITIVE_ANNOTATIONS` for an operation that only adds state (a create or a clone)
and :data:`DESTRUCTIVE_ANNOTATIONS` for one that replaces, removes or reorders existing
state (a JSON Merge Patch update, a delete, a move or an enable/disable flip). The two
hints are independent: ``live_user_disconnect`` is destructive but not idempotent, so it
declares its own pair. ``tests/test_tool_surface.py`` pins all 38 pairs tool by tool.

Open-world hint
---------------
``openWorldHint`` describes the tool's interaction domain, not how much its data can be
trusted. This server talks to exactly one configured appliance and no tool accepts a URL,
host or endpoint, so the domain of every tool that reads or writes that appliance's own
configuration is closed: :data:`OPEN_WORLD_TOOLS` is the small, explicit set of tools whose
result is produced by entities the appliance does not own and cannot enumerate -- DHCP
client leases, live authenticated sessions, live IPsec peers, the cellular carrier's
network registration and the vendor's DNS Protection verdict. Everything else publishes
``openWorldHint: false``. A tool that starts reaching beyond the appliance must be added to
that set; ``tests/test_tool_surface.py`` pins the mapping so the decision stays deliberate.
"""

from __future__ import annotations

import re
import types
from enum import Enum
from typing import (
    Annotated,
    Any,
    Awaitable,
    Callable,
    Protocol,
    Self,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
)

from mcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
    ElicitationResult,
)
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.resolve import Elicit
from mcp.server.mcpserver.tools import Tool, ToolManager
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from pydantic.fields import FieldInfo

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
    "CONFIRMATION_NOTE",
    "IP_FAMILY_DESCRIPTION",
    "OPEN_WORLD_TOOLS",
    "SUPPORTED_MCP_SDK_VERSION",
    "DestructiveConfirmation",
    "DomainAdapter",
    "DomainRegistrar",
    "ToolKind",
    "destructive_confirmation",
    "register_tool",
    "registered_read_only_tool_names",
    "registered_tool_count",
    "registered_tool_names",
    "require_confirmation",
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

#: The one description every required ``ip_family`` argument publishes.
#:
#: ``ip_family`` is the single new argument of 0.7.0 and the one a model must get right on
#: 32 tools, so it is documented once here instead of thirteen different ways across the
#: domain models (and not at all on the six firewall tools). The published ``inputSchema``
#: is the model's only description of a parameter, so the description is normalised there
#: by :func:`_describe_ip_family` rather than repeated in every model.
#:
#: The three audit composites keep their own description: their ``ip_family`` is optional
#: and means something different (both families when omitted, ``fqdn`` on
#: ``find_object_usage``).
IP_FAMILY_DESCRIPTION = (
    "IP family of the collection: 'ipv4' or 'ipv6'. Required: the two collections are "
    "separate, so the family is never inferred."
)

#: The confirmation sentence the four gated delete descriptions carry.
#:
#: The gate is a precondition, not an affordance: the call asks the client to confirm and
#: deletes nothing unless the client accepts. The question is delivered as an
#: ``InputRequiredResult`` round trip on the modern (``2026-07-28``) protocol and as a
#: standalone elicitation on the legacy handshake; a client that cannot answer fails
#: closed. The description must not promise a path where the question cannot happen.
CONFIRMATION_NOTE = (
    "The call asks the client to confirm first, naming the object, and deletes nothing "
    "unless the client accepts. On the 2026-07-28 protocol the question is delivered as a "
    "multi-round-trip input-required result; on the legacy handshake it is a standalone "
    "elicitation request. The confirmation is single-use: replaying the same resume is "
    "rejected. A declined or cancelled confirmation, or a client that cannot answer, "
    "aborts the call with a tool error and nothing is deleted."
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
    # A model-level validator raises ``ValueError``; pydantic prefixes its message with
    # "Value error, ". ``ctx["error"]`` is the exception itself, so formatting it drops the
    # prefix and keeps the validator's own wording.
    "value_error": "{error}",
}

#: The single parameter name the SDK's argument model gives a handler that takes one
#: pydantic model. The published schema is flattened away from it, but the handler keeps
#: the parameter, so the flat argument model still hands the validated instance back under
#: this key (see :func:`_flat_argument_model`).
_REQUEST_FIELD = "request"

#: The one MCP SDK release the private tool-registry seam below was verified against.
#:
#: ``pyproject.toml`` declares ``mcp==2.3.0`` for the same reason: the seam reads
#: ``MCPServer._tool_manager``, ``Tool.fn_metadata.arg_model`` and ``Tool.parameters``,
#: none of which is public API, so another release may move them and silently break
#: argument validation for every tool. ``tests/test_sdk_compat.py`` keeps this constant,
#: the declared dependency and the installed distribution in agreement; widen the pin only
#: after that test passes against the new release. See ``docs/SDK-COMPATIBILITY.md``.
SUPPORTED_MCP_SDK_VERSION = "2.3.0"

ToolHandlerT = TypeVar("ToolHandlerT", bound=Callable[..., Any])
"""A registered tool function: a typed ``async def`` with an optional ``Context``."""

ModelT = TypeVar("ModelT", bound=BaseModel)
"""A pydantic model class, used to keep the argument-model swap type-preserving."""

#: The tools whose interaction domain is open, i.e. whose result is produced by entities
#: the appliance does not own and cannot enumerate. Every other tool publishes
#: ``openWorldHint: false``: it reads or writes the configuration and the operational
#: state of the one configured appliance, which is a closed domain.
#:
#: The classification is by *what the result describes*, not by where the bytes come from
#: (every tool reaches the appliance over the same REST client):
#:
#: ``dhcp_lease_list``
#:     Live leases held by client devices on the network.
#: ``live_user_list`` / ``live_user_disconnect``
#:     Live sessions of authenticated users, and the act of terminating one.
#: ``ipsec_live_connection_list_ipv4``
#:     Established security associations with remote peers.
#: ``network_status_cellular_wan``
#:     The carrier's modem, SIM and network-registration state.
#: ``network_status_dns_protection``
#:     The vendor service's verdict on this firewall, not a value the appliance owns.
#:
#: The composites (``audit_firewall_rules``, ``find_object_usage``,
#: ``explain_connectivity``) stay closed: they read only the appliance's own configuration,
#: and ``explain_connectivity`` reports an FQDN as not verifiable instead of resolving it.
OPEN_WORLD_TOOLS: frozenset[str] = frozenset(
    {
        "dhcp_lease_list",
        "ipsec_live_connection_list_ipv4",
        "live_user_disconnect",
        "live_user_list",
        "network_status_cellular_wan",
        "network_status_dns_protection",
    }
)
"""The closed-by-default exception list for ``openWorldHint``; see the module docstring."""

#: The annotation pair for a mutation that only adds state: a create or a clone. The
#: operation is additive (``destructiveHint: false``) and not idempotent
#: (``idempotentHint: false``): repeating it either creates a second object or fails with a
#: duplicate-name conflict, so it never converges on the same state.
ADDITIVE_ANNOTATIONS = ToolAnnotations(destructive_hint=False, idempotent_hint=False)

#: The annotation pair for a mutation that replaces, removes or reorders existing state: a
#: JSON Merge Patch update, a delete, a move or an enable/disable flip. It is destructive
#: (``destructiveHint: true``) because it overwrites or removes stored configuration, and
#: idempotent (``idempotentHint: true``) because repeating the same call leaves the same
#: state. The two hints are independent: a tool whose idempotence differs declares its own
#: pair (``live_user_disconnect`` is destructive but not idempotent).
DESTRUCTIVE_ANNOTATIONS = ToolAnnotations(destructive_hint=True, idempotent_hint=True)


class DestructiveConfirmation(BaseModel):
    """Confirm the deletion.

    Set confirm to true to perform the deletion, or false to abort without changing the
    appliance.
    """

    # Elicitation schemas are restricted to primitive properties, so the answer is a single
    # boolean rather than a free-text acknowledgement. The docstring above is the schema
    # description the client renders in the confirmation dialog, so it is plain user-facing
    # prose; this implementation note stays out of it.
    confirm: bool = Field(
        description=(
            "Set true to perform the deletion; set false to abort without changing the "
            "appliance."
        )
    )


def _client_can_elicit(ctx: Context[AppContext]) -> bool:
    """Whether the connected client declared the form-mode elicitation capability.

    A client that declared nothing (``client_capabilities`` is ``None``) or declared no
    ``elicitation`` capability cannot be asked, and the destructive call must fail closed
    rather than proceed unconfirmed. The attribute is read defensively because a resolver
    is also called directly in tests with a stub context.

    The spec's backwards-compatible declaration ``"elicitation": {}`` is equivalent to
    form-mode support, so an ``ElicitationCapability`` with neither ``form`` nor ``url``
    set counts as able to answer. A ``url``-only client cannot answer a boolean question,
    so it is not asked.
    """
    capabilities = getattr(ctx, "client_capabilities", None)
    if capabilities is None:
        return False
    elicitation = getattr(capabilities, "elicitation", None)
    if elicitation is None:
        return False
    form = getattr(elicitation, "form", None)
    if form is not None:
        return True
    # ``"elicitation": {}``: the spec defines the empty object as form-mode support.
    return getattr(elicitation, "url", None) is None


def _confirmation_message(action: str, target: str) -> str:
    """The one question every gated delete asks."""
    return f"Confirm: {action} {target}. This is irreversible and cannot be undone."


def destructive_confirmation(
    action: str,
    target: Callable[[Any], str],
) -> Callable[[Any, Context[AppContext]], Awaitable[Elicit[DestructiveConfirmation]]]:
    """Build the resolver that asks the client to confirm one destructive call.

    Use the returned resolver as a tool parameter::

        async def firewall_rule_delete(
            request: DeleteFirewallRuleInput,
            confirmation: Annotated[
                ElicitationResult[DestructiveConfirmation], Resolve(_CONFIRM_DELETE)
            ],
            ctx: Context[AppContext],
        ) -> DeleteFirewallRuleOutput:
            require_confirmation(confirmation, action="delete the firewall rule")
            ...

    The SDK runs the resolver before the handler body. On the modern ``2026-07-28``
    protocol the returned :class:`~mcp.server.mcpserver.resolve.Elicit` marker becomes an
    ``InputRequiredResult`` round trip; on the legacy handshake it becomes a standalone
    elicitation request. The handler body therefore never runs until the client has
    answered, and a client that cannot answer fails closed with a ``ToolError``.

    Args:
        action: What is about to happen, phrased as a verb and object, e.g.
            ``"delete the firewall rule"``.
        target: Builds the object description from the validated request, e.g.
            ``"'allow-lan-to-wan' from the ipv4 rule base"``.

    Returns:
        An async resolver taking the tool's ``request`` argument and the SDK context.
    """

    async def resolve(request: Any, ctx: Context[AppContext]) -> Elicit[DestructiveConfirmation]:
        if not _client_can_elicit(ctx):
            raise ToolError(
                f"{action} requires confirmation, but the client did not declare form-mode "
                "elicitation support; nothing was changed"
            )
        return Elicit(
            message=_confirmation_message(action, target(request)),
            schema=DestructiveConfirmation,
        )

    return resolve


def require_confirmation(
    outcome: ElicitationResult[DestructiveConfirmation], *, action: str
) -> None:
    """Abort unless the client accepted and confirmed the destructive call.

    Call this first in a gated handler body. The body only runs after the resolver has an
    outcome, so a decline or cancel reaches this function instead of the adapter; raising
    here guarantees no HTTP request is made.

    Raises:
        ToolError: The user declined or cancelled, or accepted without setting ``confirm``.
    """
    if isinstance(outcome, DeclinedElicitation):
        raise ToolError(f"{action} was declined by the user; nothing was changed")
    if isinstance(outcome, CancelledElicitation):
        raise ToolError(f"{action} was cancelled by the user; nothing was changed")
    if not isinstance(outcome, AcceptedElicitation) or not outcome.data.confirm:
        raise ToolError(f"{action} was not confirmed; nothing was changed")


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
            rejected. ``read_only_hint`` is filled in by this helper, and
            ``open_world_hint`` defaults to the per-tool verdict in
            :data:`OPEN_WORLD_TOOLS` unless the caller sets it explicitly. ``title`` is
            deliberately not copied into the annotations: the tool-level ``title`` is the
            one the spec's display precedence reads first, so a second copy is redundant.

    Returns:
        A decorator that registers the function and returns it unchanged, so the handler
        stays directly callable in tests.

    The registered tool accepts exactly the arguments its signature declares: the SDK's
    argument model is closed (``extra="forbid"``) and its validation failures are
    sanitized, so a misspelled argument is reported instead of silently ignored and the
    model never sees the internal model name or a pydantic URL.

    A tool that takes arguments publishes them flat: the request model's own fields are the
    top-level arguments, not a nested ``request`` object (see :func:`_flatten_arguments`).
    The handler signature is unchanged, so the domain modules are unaffected.

    Raises:
        ValueError: The metadata is invalid or the annotations contradict the kind.
    """
    _check_metadata(name=name, title=title, description=description)
    resolved_annotations = _build_annotations(kind=kind, annotations=annotations, name=name)

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
        _flatten_arguments(server, name)
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
# Pinned SDK: mcp 2.3.0 (pyproject.toml declares mcp==2.3.0; uv.lock pins 2.3.0).
# The pin is exact on purpose: the attributes below are not public API, so a different
# release may move them. tests/test_sdk_compat.py is the executable compatibility
# contract and docs/SDK-COMPATIBILITY.md records the reason for the restriction.
#
# mcp 2.3.0 exposes no public way to close the argument model of a tool that is already
# registered:
#   * MCPServer.add_tool() returns None, so the Tool it built is not handed back;
#   * MCPServer.list_tools() returns the wire MCPTool, which carries the JSON schema but
#     not the pydantic argument model;
#   * MCPServer has no public get_tool();
#   * Tool.from_function()/func_metadata() accept no argument-model override.
#
# The server identity is the same kind of seam: MCPServer.description is read-only and the
# registered tool count is only known after registration, so server.py assigns
# MCPServer._lowlevel_server.description (private, pinned to mcp 2.3.0).
# The only route is the private attribute below, so it is confined to one accessor.
#
# Exact private surface this module depends on (mcp 2.3.0):
#   MCPServer._tool_manager       private attribute, set in MCPServer.__init__
#   ToolManager.get_tool(name)    public method on that private object
#   Tool.fn_metadata.arg_model    read by Tool.run -> FuncMetadata.validate_arguments
#   Tool.parameters               returned as input_schema by MCPServer.list_tools
# If any of these moves, _registered_tool raises and tests/test_sdk_compat.py fails with
# a diagnostic naming the attribute that moved.
def _tool_manager(server: MCPServer[AppContext]) -> ToolManager:
    """Return the SDK's private tool manager through the pinned seam.

    This is the only place in the package that touches ``MCPServer._tool_manager``; see
    the seam note above for the pinned version and the exact attributes it relies on.
    """
    manager = getattr(server, "_tool_manager", None)
    if manager is None:
        raise RuntimeError(
            "the pinned MCP SDK seam moved: MCPServer._tool_manager is missing (expected "
            f"mcp {SUPPORTED_MCP_SDK_VERSION}). Argument validation for every tool depends "
            "on it; see the seam note in sophos_firewall_mcp.tools and "
            "docs/SDK-COMPATIBILITY.md."
        )
    return cast(ToolManager, manager)


def _registered_tool(server: MCPServer[AppContext], name: str) -> Tool | None:
    """Return the SDK's internal ``Tool`` for ``name`` through the pinned private seam."""
    return cast(Tool | None, _tool_manager(server).get_tool(name))


def registered_tool_count(server: MCPServer[AppContext]) -> int:
    """The number of tools registered on ``server`` so far.

    The server factory uses it to publish a ``serverInfo.description`` whose tool count
    matches ``tools/list`` instead of the count an older installed summary carries. It
    reads the same pinned private seam as :func:`_registered_tool`.
    """
    return len(_tool_manager(server).list_tools())


def registered_tool_names(server: MCPServer[AppContext]) -> tuple[str, ...]:
    """The names of the tools registered on ``server`` so far, in registration order.

    The server factory uses it to describe the surface this process actually publishes: the
    resources, the prompts and the instructions are built from these names, so a filtered
    instance cannot claim a tool it did not register. It reads the same pinned private seam
    as :func:`registered_tool_count`, which keeps ``MCPServer._tool_manager`` confined to
    this module.
    """
    return tuple(tool.name for tool in _tool_manager(server).list_tools())


def registered_read_only_tool_names(server: MCPServer[AppContext]) -> tuple[str, ...]:
    """The names of the registered tools whose annotation is ``readOnlyHint=true``.

    Read-only mode removes the mutation tools before they reach the registry, so this is the
    read-only half of the surface this process publishes, not the catalog's. It reads the
    same pinned private seam as :func:`registered_tool_count`.
    """
    return tuple(
        tool.name
        for tool in _tool_manager(server).list_tools()
        if tool.annotations is not None and tool.annotations.read_only_hint
    )


def _flatten_arguments(server: MCPServer[AppContext], name: str) -> Tool | None:
    """Publish a registered tool's arguments flat instead of inside a ``request`` object.

    The SDK derives one argument field per handler parameter, so a handler that takes a
    single ``request`` model publishes a ``request`` wrapper. MCP's own examples are flat
    and a model's prior is flat, so the wrapper costs a round trip on the first call of
    every session. mcp 2.3.0 has no public way to register flat arguments for such a
    handler (see the seam note above :func:`_registered_tool`), but ``Tool.run`` only
    depends on two mutable attributes -- ``fn_metadata.arg_model`` and ``parameters`` -- so
    replacing both publishes flat arguments while keeping the closed model and the
    sanitized errors.

    The handler is not touched. ``FuncMetadata.validate_arguments`` returns
    ``arg_model.model_dump_one_level()`` and ``call_fn`` splats that into the handler, so a
    flat argument model only has to validate the flat arguments and hand the validated
    request instance back under the ``request`` key the handler already declares. That also
    keeps ``model_fields_set`` exact, which the partial-PATCH adapters depend on through
    ``exclude_unset``.

    A request that is a union cannot become one flat object without losing the per-variant
    required fields, so it publishes a root union of the closed variants instead
    (:func:`_union_argument_model`).

    ``add_tool`` returns nothing, so the registered tool is read back through the SDK's
    private tool manager (:func:`_registered_tool`, the single accessor for that seam).

    Returns:
        The registered tool, or ``None`` if the SDK did not keep it.
    """
    tool = _registered_tool(server, name)
    if tool is None:  # pragma: no cover - add_tool registered it immediately above
        return None

    arg_model = tool.fn_metadata.arg_model
    request_field = arg_model.model_fields.get(_REQUEST_FIELD)
    if request_field is None:
        # No-argument tool: only the closed, sanitized contract applies.
        tool.fn_metadata.arg_model = _sanitized_argument_model(arg_model)
        tool.parameters = {**tool.parameters, "additionalProperties": False}
        return tool

    annotation = request_field.annotation
    variants = _union_variants(annotation)
    if variants:
        discriminator = request_field.discriminator
        tool.fn_metadata.arg_model = cast(
            Any,
            _union_argument_model(
                annotation,
                variants,
                discriminator if isinstance(discriminator, str) else None,
            ),
        )
        schema = _union_schema(annotation, request_field.discriminator)
    elif isinstance(annotation, type) and issubclass(annotation, BaseModel):
        tool.fn_metadata.arg_model = cast(Any, _flat_argument_model(annotation))
        schema = _flat_schema(annotation)
    else:  # pragma: no cover - every request parameter is annotated with a model
        raise RuntimeError(
            f"tool {name!r} declares a request parameter that is not a pydantic model; "
            "flat arguments need a model or a union of models"
        )
    schema["title"] = f"{name}Arguments"
    _describe_ip_family(schema)
    tool.parameters = schema
    return tool


def _flat_argument_model(request_model: type[ModelT]) -> type[ModelT]:
    """Return the request model itself, closed and sanitized, as the argument model.

    Subclassing the request model (rather than copying its fields) keeps every constraint,
    alias and ``model_validator`` exactly as the domain declared them, and makes the
    validated instance a real request model for the handler. ``model_dump_one_level`` is
    the one behaviour that changes: the SDK splats its result into the handler, so it hands
    the instance back under the ``request`` key instead of dumping the fields.
    """

    class Flat(_sanitized_argument_model(request_model)):  # type: ignore[misc, valid-type]
        def model_dump_one_level(self) -> dict[str, Any]:
            return {_REQUEST_FIELD: self}

    # The request model's docstring is its published schema description; a subclass does
    # not inherit ``__doc__``, so carry it over explicitly.
    Flat.__doc__ = request_model.__doc__
    return cast(type[ModelT], Flat)


def _union_argument_model(
    annotation: Any,
    variants: tuple[type[BaseModel], ...],
    discriminator: str | None = None,
) -> type[BaseModel]:
    """Return an argument model for a tool whose request is a union of models.

    The union cannot be flattened into one object without losing the per-variant required
    fields, so the arguments stay a union: this class validates the flat arguments against
    the union and hands the chosen variant back under the ``request`` key.
    It is deliberately not a pydantic model -- a union has no single field set -- but it
    implements the three attributes ``FuncMetadata`` reads: ``model_validate``,
    ``model_fields`` (for JSON pre-parsing and the accepted-argument hint) and
    ``model_dump_one_level``.

    ``discriminator`` is the union's discriminator field name (``ip_family`` or ``type``),
    or ``None`` for an undiscriminated union. It lets a failed call be reported as one
    readable line instead of every variant's errors at once.
    """
    adapter = TypeAdapter(annotation)
    fields: dict[str, FieldInfo] = {}
    for variant in variants:
        for field_name, field_info in variant.model_fields.items():
            fields.setdefault(field_name, field_info)

    class UnionArguments:
        """Flat arguments validated against the request's union of models."""

        model_config = ConfigDict(extra="forbid")
        model_fields = fields

        def __init__(self, request: BaseModel) -> None:
            self._request = request

        def model_dump_one_level(self) -> dict[str, Any]:
            return {_REQUEST_FIELD: self._request}

        @classmethod
        def model_validate(cls, obj: Any, **kwargs: Any) -> "UnionArguments":
            try:
                return cls(adapter.validate_python(obj))
            except ValidationError as exc:
                raise _sanitized_argument_error(
                    exc,
                    cast(Any, cls),
                    message=_union_argument_message(obj, variants, discriminator),
                ) from None

    return cast(type[BaseModel], UnionArguments)


def _union_variants(annotation: Any) -> tuple[type[BaseModel], ...]:
    """Return the model variants of a (possibly ``Annotated``) union, or ``()``."""
    base = get_args(annotation)[0] if get_origin(annotation) is Annotated else annotation
    if get_origin(base) not in (Union, types.UnionType):
        return ()
    return tuple(
        variant
        for variant in get_args(base)
        if isinstance(variant, type) and issubclass(variant, BaseModel)
    )


def _flat_schema(request_model: type[BaseModel]) -> dict[str, Any]:
    """The published input schema for a flat request model."""
    return {**request_model.model_json_schema(by_alias=True), "additionalProperties": False}


def _union_schema(annotation: Any, discriminator: Any) -> dict[str, Any]:
    """The published input schema for a union request.

    The variants stay under a root union, which keeps each one's own ``required`` list and
    its own ``additionalProperties: false``; a root ``additionalProperties: false`` would
    reject every variant's fields, so it is deliberately absent. ``type: object`` is added
    because every variant is an object and some clients expect the root to say so.

    pydantic emits ``anyOf`` for a union. A discriminated union matches exactly one
    variant, so it is published as the stricter ``oneOf``; an undiscriminated union keeps
    ``anyOf``, where ``oneOf`` would be wrong.
    """
    schema = TypeAdapter(annotation).json_schema(by_alias=True)
    if discriminator is not None and "anyOf" in schema:
        schema["oneOf"] = schema.pop("anyOf")
    return {**schema, "type": "object"}


def _describe_ip_family(schema: dict[str, Any]) -> None:
    """Give every required ``ip_family`` property the one shared description.

    ``ip_family`` is the single new argument of 0.7.0 and the one a model must get right on
    32 tools, but the domain models declare it thirteen different ways -- and the six
    firewall tools not at all -- because each was written with its own domain in mind. The
    model reads the published ``inputSchema``, not the Python field, so the description is
    normalised here, once, for every tool: a required ``ip_family`` is the same argument
    everywhere.

    An optional ``ip_family`` (the three audit composites) keeps its own description,
    because there it means "both families when omitted" rather than "never inferred". The
    union variants are covered too: their ``ip_family`` is a ``const`` that selects the
    family, so it is the same argument one level down.
    """
    _describe_required_ip_family(schema)
    for definition in (schema.get("$defs") or {}).values():
        if isinstance(definition, dict):
            _describe_required_ip_family(definition)


def _describe_required_ip_family(node: dict[str, Any]) -> None:
    """Set :data:`IP_FAMILY_DESCRIPTION` on ``node``'s required ``ip_family``, if any."""
    properties = node.get("properties")
    if not isinstance(properties, dict):
        return
    ip_family = properties.get("ip_family")
    if not isinstance(ip_family, dict):
        return
    if "ip_family" in (node.get("required") or ()):
        ip_family["description"] = IP_FAMILY_DESCRIPTION


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


def _sanitized_argument_error(
    exc: ValidationError, model: type[BaseModel], *, message: str | None = None
) -> ValidationError:
    """Build the sanitized ``ValidationError`` the SDK renders for the model."""
    # ``errors()`` carries the same entries ``from_exception_data`` accepts; the extra
    # ``msg``/``url`` keys are ignored by the constructor.
    sanitized = _SanitizedArgumentError.from_exception_data(
        "invalid arguments", cast(Any, exc.errors())
    )
    sanitized._sanitized_message = (
        message if message is not None else _argument_error_message(exc, model)
    )
    return sanitized


def _argument_error_message(exc: ValidationError, model: type[BaseModel]) -> str:
    """Render an argument-validation failure as one actionable line.

    The raw pydantic dump names the internal argument model, echoes the rejected input and
    links to the pydantic documentation; none of that helps a model correct its call. Only
    the field path and the rule are kept, plus the accepted names when the caller used an
    unknown one.
    """
    return _sanitize("invalid arguments: " + "; ".join(_argument_error_details(exc, model)))


def _argument_error_details(exc: ValidationError, model: type[BaseModel]) -> list[str]:
    """Render each pydantic error as one ``<field> <rule>`` detail."""
    details: list[str] = []
    for error in exc.errors():
        location = _display_location(model, error.get("loc", ()))
        rule = _argument_rule(error)
        detail = f"{location} {rule}" if location else rule
        if error.get("type") == "extra_forbidden":
            accepted = _accepted_arguments(model, error.get("loc", ()))
            if accepted:
                detail = f"{detail}; {accepted}"
        details.append(detail)
    return details


def _union_argument_message(
    obj: Any, variants: tuple[type[BaseModel], ...], discriminator: str | None
) -> str:
    """Render a union-request failure as one readable line.

    A discriminated union is resolved by its discriminator first: a missing or unknown
    value is reported once, with the accepted values, instead of repeating every variant's
    required-field errors. Once the discriminator selects a variant, only that variant's
    errors are reported, so the message has the same shape a flat tool produces. An
    undiscriminated union has no selector, so the variant that got furthest is reported
    (and, on a tie, the alternatives are joined with "or").
    """
    if discriminator is not None:
        accepted = _discriminator_values(variants, discriminator)
        value = obj.get(discriminator) if isinstance(obj, dict) else None
        if value is None:
            # The caller may have sent the *other* selector with a value no variant
            # accepts: ``address_create`` is discriminated by ``type`` but every variant
            # also pins ``ip_family``, so ``{"ip_family": "ipv5"}`` is a bad ``ip_family``,
            # not a missing ``type``. Naming the field the caller actually sent is
            # actionable; "type is required" names a field it never sent.
            rejected = _rejected_selector(obj, variants, discriminator)
            if rejected is not None:
                return rejected
            return _sanitize(
                f"invalid arguments: {discriminator} is required; "
                f"accepted values are {_quoted_values(accepted)}"
            )
        if value not in accepted:
            return _sanitize(
                f"invalid arguments: {discriminator} must be one of {_quoted_values(accepted)}"
            )
        variant = _variant_for_discriminator(variants, discriminator, value)
        if variant is not None:
            try:
                variant.model_validate(obj)
            except ValidationError as exc:
                return _argument_error_message(exc, variant)
            # Unreachable: the adapter applies the same discriminator and the same variant
            # validators. Report a neutral line rather than another variant's errors if a
            # future model makes it reachable.
            return "invalid arguments: the arguments do not match an accepted shape"

    exclusive = _mutually_exclusive_message(obj, variants)
    if exclusive is not None:
        return exclusive

    failures: list[tuple[int, str]] = []
    for variant in variants:
        try:
            variant.model_validate(obj)
        except ValidationError as exc:
            details = _argument_error_details(exc, variant)
            failures.append((len(details), "; ".join(details)))
    if not failures:
        return "invalid arguments: the arguments do not match an accepted shape"
    fewest = min(count for count, _ in failures)
    best = [detail for count, detail in failures if count == fewest]
    return _sanitize("invalid arguments: " + " or ".join(best))


def _mutually_exclusive_message(obj: Any, variants: tuple[type[BaseModel], ...]) -> str | None:
    """Name the alternatives when a caller supplies fields from more than one variant.

    An undiscriminated union has no selector, so a caller that sends the identifying
    required field of two variants is rejected once per variant ("not an accepted
    argument" each time). The alternatives are mutually exclusive, and one sentence naming
    them is actionable; the per-variant rejections are not.

    A field identifies a variant when it is required by that variant and is not a field of
    any other variant. A field shared by every variant (``name``) identifies none, so it
    never triggers the message.
    """
    if not isinstance(obj, dict):
        return None
    supplied = set(obj)
    identifying: list[set[str]] = []
    for variant in variants:
        others: set[str] = set()
        for other in variants:
            if other is not variant:
                others.update(other.model_fields)
        required = {name for name, field in variant.model_fields.items() if field.is_required()}
        identifying.append(required - others)
    chosen = [group for group in identifying if group & supplied]
    if len(chosen) < 2:
        return None
    names = sorted(set().union(*chosen))
    return _sanitize(
        f"invalid arguments: {' and '.join(names)} are mutually exclusive; provide exactly one"
    )


def _discriminator_values(variants: tuple[type[BaseModel], ...], discriminator: str) -> list[str]:
    """The accepted values of a union's discriminator, in variant order."""
    values: list[str] = []
    for variant in variants:
        field = variant.model_fields.get(discriminator)
        if field is None:
            continue
        for value in get_args(field.annotation):
            if isinstance(value, str) and value not in values:
                values.append(value)
    return values


def _rejected_selector(
    obj: Any, variants: tuple[type[BaseModel], ...], discriminator: str
) -> str | None:
    """Name a selector field the caller sent with a value no variant accepts.

    A union can be selected by more than one field: the address create union is
    discriminated by ``type``, but every variant also pins ``ip_family`` to a literal, so
    ``{"ip_family": "ipv5"}`` is a bad ``ip_family`` rather than a missing ``type``. Only a
    field that is a literal on every variant is considered, so an ordinary argument with a
    bad value is left to the selected variant's own error.
    """
    if not isinstance(obj, dict):
        return None
    for field_name, value in obj.items():
        if field_name == discriminator:
            continue
        accepted = _discriminator_values(variants, field_name)
        if not accepted or value in accepted:
            continue
        return _sanitize(
            f"invalid arguments: {field_name} must be one of {_quoted_values(accepted)}"
        )
    return None


def _variant_for_discriminator(
    variants: tuple[type[BaseModel], ...], discriminator: str, value: str
) -> type[BaseModel] | None:
    """The variant whose discriminator field accepts ``value``."""
    for variant in variants:
        field = variant.model_fields.get(discriminator)
        if field is not None and value in get_args(field.annotation):
            return variant
    return None


def _quoted_values(values: list[str]) -> str:
    """Render accepted values the way the flat-tool rules do: ``'a', 'b'``."""
    return ", ".join(f"'{value}'" for value in values)


def _display_location(model: type[BaseModel], location: tuple[Any, ...]) -> str:
    """Render a pydantic error location without the tags a union adds to it.

    A discriminated union reports ``("ipv4", "bogus")``: the first part is the tag pydantic
    used to name the chosen variant, not an argument the caller sent. Dropping a leading
    part that is not a field of the model keeps the message about the caller's own input.
    A single-part location is never dropped -- there it is the caller's argument name.
    """
    parts = [str(part) for part in location]
    while len(parts) > 1 and _field_annotation(model, parts[0]) is None:
        parts.pop(0)
    return ".".join(parts)


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
        if annotation is None:
            # A discriminated-union tag, not a field: the level does not change.
            continue
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
    *, kind: ToolKind, annotations: ToolAnnotations | None, name: str
) -> ToolAnnotations:
    """Fill in the annotation policy for the tool kind and reject contradictions.

    ``openWorldHint`` is resolved per tool: an explicit value on ``annotations`` wins,
    otherwise :data:`OPEN_WORLD_TOOLS` decides, and a tool that is not listed is closed.

    ``title`` is deliberately not copied into the annotations: the spec's display
    precedence is ``title``, then ``annotations.title``, then ``name``, so the tool-level
    title already wins and a duplicate costs bytes on every tool without adding
    information.
    """
    resolved = annotations if annotations is not None else ToolAnnotations()
    open_world = (
        name in OPEN_WORLD_TOOLS if resolved.open_world_hint is None else resolved.open_world_hint
    )

    if kind is ToolKind.READ:
        if resolved.read_only_hint is False:
            raise ValueError("a read-only tool cannot declare readOnlyHint=False")
        if resolved.destructive_hint is not None or resolved.idempotent_hint is not None:
            raise ValueError(
                "read-only tools must not declare destructiveHint or idempotentHint: "
                "those hints describe write operations"
            )
        return resolved.model_copy(update={"read_only_hint": True, "open_world_hint": open_world})

    if resolved.read_only_hint is True:
        raise ValueError("a mutation tool cannot declare readOnlyHint=True")
    if resolved.destructive_hint is None or resolved.idempotent_hint is None:
        raise ValueError(
            "mutation tools must declare destructiveHint and idempotentHint explicitly: "
            "create, update, delete, move and disconnect have different risk and "
            "idempotence"
        )
    return resolved.model_copy(update={"read_only_hint": False, "open_world_hint": open_world})


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
