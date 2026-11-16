"""MCP server factory and entrypoint for Sophos Firewall MCP.

The server is a local STDIO MCP server that administers one Sophos Firewall appliance
through its Configuration REST API. This module owns application construction, the
lifespan and the STDIO entrypoint; domain tools live in :mod:`sophos_firewall_mcp.tools`
and register themselves through the contract documented there.

Surface
-------
The server publishes all three MCP primitives, because they do different jobs: tools are
model-controlled actions (:mod:`sophos_firewall_mcp.tools`), resources are
application-controlled passive context (:mod:`sophos_firewall_mcp.resources`) and prompts
are user-controlled templates (:mod:`sophos_firewall_mcp.prompts`). The resources carry the
REST API surface, the coverage matrix, the read-only policy and the calling conventions
once, instead of repeating them in 112 tool descriptions; the prompts carry the three
analysis workflows (audit the rule base, explain a flow, find unused objects). All three
catalogs are static for the process lifetime.

Domain selection
----------------
``SOPHOS_TOOL_DOMAINS`` narrows the tool surface to the domains a deployment needs, so a
client is not handed 112 tool definitions when it uses six. The setting is a comma-separated
allowlist of the stable identifiers in
:data:`~sophos_firewall_mcp.config.TOOL_DOMAINS`; each identifier maps to exactly one
``register_<domain>_tools`` function in :data:`DOMAIN_REGISTRARS`, so no handler is
duplicated or reimplemented. Unset means :data:`DEFAULT_DOMAINS`, the complete surface, in
the same order as before the setting existed.

The two filters compose and stay independent: the domain selection decides which
capabilities exist, and ``SOPHOS_READ_ONLY_MODE`` then removes the mutation tools *within*
the selected domains. A domain selection is validated by
:func:`~sophos_firewall_mcp.config.validate_tool_domains` before any tool registers, so an
unknown, repeated or empty entry fails startup instead of quietly publishing a different
surface. The audit composites are the only cross-domain tools and they carry no
registration-time dependency: they call the other domains' adapter classes directly, so
``audit`` works with any selection.

The surface is read back from the registry after registration (:func:`_registered_surface`)
and drives the resources, the prompts and the instructions, so a filtered instance
describes the tools it publishes and never claims an excluded one is registered.

Lifecycle
---------
``create_server(settings)`` validates nothing about the environment -- it receives
settings that :func:`create_server_from_env` already validated -- and builds the server:
the read-only mode and the domain selection are resolved from those settings *before* any
domain registers a tool, because the SDK does not re-read the tool registry and the tool
set must be fixed for the process lifetime. The lifespan then creates exactly one
:class:`~sophos_firewall_mcp.client.SophosRestClient`, yields the
:class:`~sophos_firewall_mcp.context.AppContext` every handler receives, and closes the
client in ``finally`` on both normal and exceptional shutdown.

Transport and diagnostics
-------------------------
STDIO only: stdout carries the MCP protocol and nothing else. Logging and diagnostics go
to stderr. ``MCPServer(..., subscriptions=False)`` is used because the tool, resource and
prompt catalogs are static for the process lifetime (the read-only mode is applied at
startup), so the SDK must not advertise ``subscriptions/listen`` or ``listChanged``. The
same static catalogs are why ``cache_hints`` gives ``tools/list``, ``server/discover``,
``resources/list``, ``resources/read`` and ``prompts/list`` a long TTL: the SDK default of
``0`` means "immediately stale" and makes a client re-fetch a ~623 KB payload on every
turn.

Identity
--------
``serverInfo`` is built from the installed distribution metadata (``version``,
``description``, ``website_url``) plus :data:`SERVER_TITLE`, so a client can report which
release produced a behaviour without the version being duplicated in code. The description
is published verbatim: it names the product and the API, never a tool count, so it stays
true for the complete surface, a read-only deployment and a domain-filtered one alike.
"""

from __future__ import annotations

import importlib.metadata
import logging
import sys
from collections.abc import AsyncIterator, Iterable, Mapping
from contextlib import asynccontextmanager
from typing import Any, NamedTuple

# Must precede the mcp import: it is the check that explains a shadowed or too-new `mcp`
# before the import below dies with a bare ModuleNotFoundError the MCP client cannot see
# (empty error). Kept from the pre-REST server; it is not XML-specific.
from sophos_firewall_mcp._env_guard import verify_local_mcp

verify_local_mcp()

from mcp.server import CacheHint  # noqa: E402
from mcp.server.caching import CacheableMethod  # noqa: E402
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402
from mcp.types import INVALID_PARAMS  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from sophos_firewall_mcp.client import SophosRestClient  # noqa: E402
from sophos_firewall_mcp.config import ConfigurationError, Settings, TOOL_DOMAINS  # noqa: E402
from sophos_firewall_mcp.context import AppContext  # noqa: E402
from sophos_firewall_mcp.models.common import trim_published_output_schema  # noqa: E402
from sophos_firewall_mcp.mrtr import mrtr_replay_guard  # noqa: E402
from sophos_firewall_mcp.prompts import (  # noqa: E402
    PromptArgumentError,
    available_prompts,
    register_prompts,
)
from sophos_firewall_mcp.resources import (  # noqa: E402
    SurfaceSummary,
    register_resources,
)
from sophos_firewall_mcp.tools import (  # noqa: E402
    DomainRegistrar,
    registered_read_only_tool_names,
    registered_tool_names,
    trim_registered_output_schemas,
)
from sophos_firewall_mcp.tools.audit import register_audit_tools  # noqa: E402
from sophos_firewall_mcp.tools.firewall_rules import register_firewall_tools  # noqa: E402
from sophos_firewall_mcp.tools.hosts_objects import register_objects_tools  # noqa: E402
from sophos_firewall_mcp.tools.nat_rules import register_nat_tools  # noqa: E402
from sophos_firewall_mcp.tools.network import register_network_tools  # noqa: E402
from sophos_firewall_mcp.tools.users_auth import register_users_tools  # noqa: E402

__all__ = [
    "DEFAULT_DOMAINS",
    "DOMAIN_REGISTRARS",
    "INSTRUCTIONS",
    "SERVER_NAME",
    "SERVER_TITLE",
    "create_server",
    "create_server_from_env",
    "instructions_for",
    "main",
    "selected_domains",
]

logger = logging.getLogger(__name__)

#: Name advertised to MCP clients.
SERVER_NAME = "Sophos Firewall MCP Server"

#: Human-readable display name (``serverInfo.title``). The distribution metadata carries
#: no title, so this is the one identity field that is not read from it.
SERVER_TITLE = "Sophos Firewall MCP"

#: Distribution name in ``pyproject.toml``: the single source of truth for the version,
#: the summary and the project URL, read back through :mod:`importlib.metadata`.
_PACKAGE_NAME = "sophos-firewall-mcp-server"

#: Reported when the distribution metadata is unavailable (a source checkout that was
#: never installed). An explicit unknown is better than an empty string, which is what
#: the SDK default publishes and what makes "which release produced this?" unanswerable.
_UNKNOWN_VERSION = "0.0.0+unknown"

#: Freshness hint for the static catalog, in milliseconds: one hour.
#:
#: The tool catalog cannot change while the process runs -- the read-only mode is applied
#: at startup and ``subscriptions=False`` is passed, so no ``listChanged`` notification is
#: ever sent. The SDK default is ``0``, which the MCP caching specification defines as
#: "immediately stale" and which makes a client re-fetch a ~623 KB ``tools/list`` payload
#: on every turn. One hour matches the ``server/discover`` example in the specification
#: and is short enough that a client notices a restarted server (a different read-only
#: mode) within a session.
_CATALOG_TTL_MS = 3_600_000

#: Cache hints for the static catalog methods this server serves. ``server/discover``
#: carries the same identity and capability set for the process lifetime, so it is as
#: cacheable as ``tools/list``. The resource and prompt catalogs are static for the same
#: reason -- the read-only mode is resolved before registration and every resource is a
#: constant -- so a client that re-reads them per turn pays for nothing.
_CATALOG_CACHE_HINTS: dict[CacheableMethod, CacheHint] = {
    "tools/list": CacheHint(ttl_ms=_CATALOG_TTL_MS),
    "server/discover": CacheHint(ttl_ms=_CATALOG_TTL_MS),
    "resources/list": CacheHint(ttl_ms=_CATALOG_TTL_MS),
    "resources/templates/list": CacheHint(ttl_ms=_CATALOG_TTL_MS),
    "resources/read": CacheHint(ttl_ms=_CATALOG_TTL_MS),
    "prompts/list": CacheHint(ttl_ms=_CATALOG_TTL_MS),
}

#: Server-level instructions shown to the model. Domain tools carry their own.
#:
#: One convention is stated here, once, instead of in 105 tool descriptions: a successful
#: result carries the same payload twice (``content`` text and ``structuredContent``), so a
#: client reads one of them. It is a property of this server's calling convention, not of
#: any one domain.
#:
#: The prompt sentence is appended by :func:`instructions_for` rather than baked in, because
#: a process that enables only some domains does not register every prompt and must not
#: name one it did not register.
_INSTRUCTIONS_BASE = (
    "Administers a Sophos Firewall (SFOS) through its Configuration REST API. Tools are "
    "narrow and typed: they list, read, create, update, move or delete firewall and NAT "
    "rules, address and service objects, users and live sessions. Read-only tools never "
    "modify the appliance. When the server runs in read-only mode, mutation tools are "
    "not registered at all. Every tool that takes arguments takes them flat: the fields "
    "its `inputSchema` lists are the fields the call sends, with no wrapper object. A tool "
    "whose request is a union of shapes publishes a root `oneOf` instead, and its "
    "discriminator (`ip_family` or `type`) selects the variant; `mac_address_create` "
    "publishes `anyOf` because the API declares no discriminator. Every "
    "successful result carries the same payload twice, as `content` text and as "
    "`structuredContent`; read one of them, not both. Read `sophos://conventions` before "
    "the first call"
)


def _prompt_sentence(prompt_names: tuple[str, ...]) -> str:
    """The instructions clause that names the registered prompts.

    The complete surface keeps the original wording verbatim, including the "and" before the
    last name and the word "three": the published instructions are a stable string, and a
    filtered instance only shortens the list.
    """
    if not prompt_names:
        return "."
    if len(prompt_names) == 1:
        listed = f"`{prompt_names[0]}`"
    else:
        listed = ", ".join(f"`{name}`" for name in prompt_names[:-1]) + f" and `{prompt_names[-1]}`"
    if len(prompt_names) == 3:
        return f"; the prompts {listed} carry the three analysis workflows."
    return f"; the prompts {listed} carry the analysis workflows."


#: The instructions of the complete default surface: every prompt is registered there.
INSTRUCTIONS = _INSTRUCTIONS_BASE + _prompt_sentence(
    ("audit_firewall", "explain_flow", "find_unused_objects")
)

#: Stable domain identifier -> the registration function that publishes it.
#:
#: The identifiers are the six domain families of the registration architecture, and each one
#: maps to exactly one ``register_<domain>_tools`` function: selecting a domain selects the
#: tools that function registers, with no handler duplicated or reimplemented here. ``network``
#: also registers the VPN and status tools and ``objects`` also registers the service tools,
#: because those are the entry points the domains already use.
DOMAIN_REGISTRARS: Mapping[str, DomainRegistrar] = {
    "firewall": register_firewall_tools,
    "nat": register_nat_tools,
    "objects": register_objects_tools,
    "users": register_users_tools,
    "network": register_network_tools,
    "audit": register_audit_tools,
}

#: Domain registration functions, in registration order (the complete default surface).
#:
#: Phase 2 (#27-#31, #35): the six domain families from ADR-001 §10. ``network`` also
#: registers the VPN and status tools, so it is a single entry point. ``audit`` is last
#: because it composes the other domains' adapters.
DEFAULT_DOMAINS: tuple[DomainRegistrar, ...] = tuple(
    DOMAIN_REGISTRARS[name] for name in TOOL_DOMAINS
)


def selected_domains(settings: Settings) -> tuple[str, ...]:
    """The domain identifiers this process registers, in canonical order.

    ``SOPHOS_TOOL_DOMAINS`` unset means the complete default surface, so an existing
    installation keeps publishing exactly the same tools in exactly the same order.
    """
    if settings.tool_domains is None:
        return TOOL_DOMAINS
    return settings.tool_domains


def _enabled_domains(registrars: Iterable[DomainRegistrar]) -> tuple[str, ...]:
    """The known domain identifiers among *registrars*, in canonical order.

    An explicit ``domains`` iterable is the seam the domain tests use to build a one-domain
    server, and it may carry a registrar that is not one of the six domains (a synthetic
    one). Such a registrar is not a domain, so it is not named here; the resources then
    describe the tools that were actually registered instead of claiming a domain that was
    not selected.
    """
    selected = tuple(registrars)
    return tuple(
        name
        for name in TOOL_DOMAINS
        if any(registrar is DOMAIN_REGISTRARS[name] for registrar in selected)
    )


def _registered_surface(server: MCPServer[AppContext], domains: tuple[str, ...]) -> SurfaceSummary:
    """The tool surface this process actually registered.

    The registry is the ground truth: the resources and the instructions describe what is in
    it, so a filtered instance cannot claim a tool it did not register. Both accessors come
    from :mod:`sophos_firewall_mcp.tools`, which owns the pinned private SDK seam, so this
    module never touches ``MCPServer._tool_manager`` itself.
    """
    return SurfaceSummary(
        domains=domains,
        tool_names=registered_tool_names(server),
        read_only_tool_names=registered_read_only_tool_names(server),
    )


def instructions_for(surface: SurfaceSummary, prompt_names: tuple[str, ...]) -> str:
    """The server instructions for the surface this process registered.

    The complete default surface keeps :data:`INSTRUCTIONS` verbatim. A filtered instance
    appends one sentence naming the domains it publishes and the tools it does not, so the
    model is told that the excluded tools are absent instead of discovering it from a failed
    call.
    """
    if surface.is_full and prompt_names == (
        "audit_firewall",
        "explain_flow",
        "find_unused_objects",
    ):
        return INSTRUCTIONS
    return _INSTRUCTIONS_BASE + _prompt_sentence(prompt_names) + " " + surface.enabled_summary()


class _PackageIdentity(NamedTuple):
    """The ``serverInfo`` fields that come from the installed distribution metadata."""

    version: str
    description: str | None
    website_url: str | None


def _package_identity() -> _PackageIdentity:
    """Read the server identity from the installed distribution metadata.

    ``pyproject.toml`` is the single source of truth: the build backend copies its
    ``version``, ``description`` and ``Homepage`` URL into the distribution metadata, and
    :mod:`importlib.metadata` reads them back at runtime. The version is not duplicated in
    code, but the *installed* metadata can lag behind ``pyproject.toml`` in a checkout that
    was never reinstalled, so ``serverInfo`` reports what is installed and the test suite
    compares it against ``pyproject.toml`` to catch that drift.

    A source checkout that was never installed has no metadata. That is not a reason to
    refuse to start: the version falls back to :data:`_UNKNOWN_VERSION` and the optional
    fields stay unset.
    """
    try:
        metadata = importlib.metadata.metadata(_PACKAGE_NAME)
    except importlib.metadata.PackageNotFoundError:
        return _PackageIdentity(version=_UNKNOWN_VERSION, description=None, website_url=None)

    version = (metadata.get("Version") or "").strip() or _UNKNOWN_VERSION
    description = (metadata.get("Summary") or "").strip() or None
    website_url: str | None = None
    for entry in metadata.get_all("Project-URL") or ():
        label, _, url = entry.partition(",")
        if label.strip().lower() == "homepage":
            website_url = url.strip() or None
            break
    return _PackageIdentity(version=version, description=description, website_url=website_url)


#: The prefixes of the ``ValueError`` messages the SDK raises for a ``prompts/get`` the
#: caller can fix. ``MCPServer.get_prompt`` wraps every failure in ``ValueError`` and the
#: runner maps that to ``-32603`` (internal error), but the spec puts an unknown prompt
#: name and missing arguments in the ``-32602`` (invalid params) class.
_PROMPT_ARGUMENT_ERRORS = (
    "Unknown prompt:",
    "Missing required arguments:",
)

#: The prefix the SDK wraps a prompt renderer failure in. The renderer's own exception is
#: the root ``__cause__`` of the chain, and only a caller-fixable root cause is ``-32602``.
_PROMPT_RENDER_ERROR = "Error rendering prompt"

#: The exact message the SDK's tool manager raises for a tool name it does not know. The
#: tool handler turns that into an ``isError`` result, so the middleware recognises the one
#: caller-fixable case by the message the SDK wrote, not by a broad "any tool error" rule.
_UNKNOWN_TOOL_PREFIX = "Unknown tool: "


def _root_cause(exc: BaseException) -> BaseException:
    """The innermost exception in the ``__cause__`` chain."""
    cause = exc
    while cause.__cause__ is not None:
        cause = cause.__cause__
    return cause


def _prompt_error_is_caller_fixable(exc: ValueError) -> bool:
    """Whether a ``prompts/get`` ``ValueError`` is the caller's mistake, not a crash.

    The SDK raises ``ValueError`` for every prompt failure: an unknown name and missing
    arguments directly, and a renderer failure wrapped twice (``Prompt.render`` wraps it,
    then ``MCPServer.get_prompt`` re-wraps that). Only the root cause decides: a pydantic
    ``ValidationError`` is an argument the prompt does not accept, and
    :class:`~sophos_firewall_mcp.prompts.PromptArgumentError` is an argument combination
    the renderer rejects. Any other root cause is a programming error and stays
    ``-32603``, which the SDK logs server-side.
    """
    message = str(exc)
    if message.startswith(_PROMPT_ARGUMENT_ERRORS):
        return True
    if not message.startswith(_PROMPT_RENDER_ERROR):
        return False
    return isinstance(_root_cause(exc), (PromptArgumentError, ValidationError))


def _prompt_error_message(exc: ValueError) -> str:
    """A sanitized, actionable message for a caller-fixable ``prompts/get`` failure.

    The SDK's own render-failure message is only ``Error rendering prompt <name>``, which
    names neither the rejected argument nor the reason. The root cause carries both, so the
    message is rebuilt from it: the prompt name plus the rejected field and, for a mistyped
    value, pydantic's field-level reason. The caller's input value, the traceback and any
    internal path are never included.
    """
    message = str(exc)
    if message.startswith(_PROMPT_ARGUMENT_ERRORS):
        return message
    prompt_name = message.removeprefix(_PROMPT_RENDER_ERROR).strip() or "prompt"
    cause = _root_cause(exc)
    if isinstance(cause, PromptArgumentError):
        return f"{prompt_name}: {cause}"
    if isinstance(cause, ValidationError):
        rejected: list[str] = []
        for error in cause.errors():
            field = ".".join(str(part) for part in error["loc"]) or "arguments"
            if error["type"] in ("extra_forbidden", "unexpected_keyword_argument"):
                rejected.append(f"{field!r} is not an accepted argument")
            else:
                rejected.append(f"{field!r}: {error['msg']}")
        if rejected:
            return f"{prompt_name}: " + "; ".join(rejected)
    return message


def _unknown_tool_name(ctx: ServerRequestContext[Any, Any], result: HandlerResult) -> str | None:
    """The requested tool name when the SDK reported it as unknown, else ``None``.

    ``MCPServer._handle_call_tool`` turns every tool failure into an ``isError`` result, so
    the middleware cannot see the ``ToolError``. The one caller-fixable case is an unknown
    tool name, which the SDK reports with the exact message ``Unknown tool: <name>`` for the
    name the caller sent. Every other ``isError`` result is a failure after a valid tool was
    invoked and stays a tool error.
    """
    if ctx.method != "tools/call" or not isinstance(result, dict):
        return None
    if result.get("isError") is not True:
        return None
    params = ctx.params or {}
    name = params.get("name")
    if not isinstance(name, str):
        return None
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return None
    first = content[0]
    if not isinstance(first, dict) or first.get("text") != f"{_UNKNOWN_TOOL_PREFIX}{name}":
        return None
    return name


async def _request_error_middleware(
    ctx: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    """Report a caller-fixable request failure as ``-32602``, not ``-32603``/``isError``.

    Two dispatch paths need this correction because the SDK owns their error mapping:

    * ``prompts/get``: the SDK maps every ``ValueError`` to ``-32603``, but an unknown
      prompt name, missing arguments and an argument the prompt rejects are the caller's
      mistake. A genuine renderer crash keeps the SDK's ``-32603`` and its server-side log.
    * ``tools/call``: the SDK turns an unknown tool name into an ``isError`` result, but the
      spec puts it in the invalid-params class. A failure after a valid tool was invoked
      stays an ``isError`` result.

    The ``-32603`` half of the prompt contract holds on the modern protocol this server
    advertises (2026-07-28). On a legacy ``initialize`` handshake the SDK's own dispatcher
    deliberately maps an unmapped exception to JSON-RPC code ``0`` (its ``TODO(L58)``
    compatibility pin), so a genuine renderer crash is ``code=0`` there. This middleware
    does not change that; the ``-32602`` mappings above apply on both paths.
    """
    try:
        result = await call_next(ctx)
    except ValueError as exc:
        if ctx.method == "prompts/get" and _prompt_error_is_caller_fixable(exc):
            raise MCPError(code=INVALID_PARAMS, message=_prompt_error_message(exc)) from exc
        raise
    unknown_tool = _unknown_tool_name(ctx, result)
    if unknown_tool is not None:
        raise MCPError(code=INVALID_PARAMS, message=f"{_UNKNOWN_TOOL_PREFIX}{unknown_tool}")
    return result


def create_server(
    settings: Settings,
    *,
    domains: Iterable[DomainRegistrar] | None = None,
) -> MCPServer[AppContext]:
    """Build the MCP server for already-validated settings.

    Configuration is validated once, before this function is called (see
    :func:`create_server_from_env`), because the read-only mode and the domain selection
    decide the tool set and the SDK does not re-read the registry after construction.

    Args:
        settings: Validated connection settings. The API key inside is a ``SecretStr``
            and is only ever placed in the ``Authorization`` header by the client.
        domains: Registration functions called once each, before the server starts. Each
            receives the server and the resolved ``read_only`` flag. ``None`` -- the normal
            path -- selects the domains named by ``settings.tool_domains``, which is the
            complete default surface when the setting is unset. An explicit iterable
            overrides the setting; it is the seam the domain tests use to build a
            one-domain server.

    Returns:
        A server whose lifespan creates one shared REST client and yields the
        :class:`~sophos_firewall_mcp.context.AppContext`.

    Raises:
        TypeError: ``settings`` is not a :class:`~sophos_firewall_mcp.config.Settings`.
    """
    if not isinstance(settings, Settings):
        raise TypeError("settings must be a Settings instance")
    read_only = settings.read_only_mode
    if domains is None:
        enabled = selected_domains(settings)
        registrars: tuple[DomainRegistrar, ...] = tuple(DOMAIN_REGISTRARS[name] for name in enabled)
    else:
        registrars = tuple(domains)
        enabled = _enabled_domains(registrars)

    @asynccontextmanager
    async def lifespan(_: MCPServer[AppContext]) -> AsyncIterator[AppContext]:
        """Create the one shared client, yield the context, close the client exactly once.

        The environment was already validated by :func:`create_server_from_env` before the
        tool set was fixed. Constructing the client here is the remaining startup
        validation: an unusable TLS/CA configuration fails the lifespan instead of the
        first tool call. The client is closed in ``finally`` on every shutdown path.
        """
        logger.info(
            "starting %s: appliance %s, read-only=%s, domains=%s",
            SERVER_NAME,
            settings.authority,
            read_only,
            ",".join(enabled) or "custom",
        )
        client = SophosRestClient(settings)
        try:
            yield AppContext(client=client, settings=settings, read_only=read_only)
        finally:
            # Runs on normal and exceptional shutdown. ``aclose`` is idempotent, but the
            # lifespan calls it once: the client is created here and nowhere else.
            await client.aclose()

    identity = _package_identity()
    server: MCPServer[AppContext] = MCPServer(
        SERVER_NAME,
        title=SERVER_TITLE,
        description=identity.description,
        instructions=INSTRUCTIONS,
        website_url=identity.website_url,
        version=identity.version,
        lifespan=lifespan,
        subscriptions=False,
        cache_hints=_CATALOG_CACHE_HINTS,
        middleware=[_request_error_middleware],
    )
    # The SDK appends its RequestStateBoundary before the user middleware, so a middleware
    # passed to the constructor runs *inside* the boundary and sees the unsealed state.
    # The replay guard must see the raw sealed token, so it is prepended: outermost-first,
    # it runs before the boundary unseals (and before any handler). See mrtr.py.
    server.middleware.insert(0, mrtr_replay_guard)
    for register in registrars:
        register(server, read_only=read_only)
    # The published output schemas are trimmed once, after every domain has registered:
    # the trim is per tool and the registry is fixed for the process lifetime. The tool
    # package owns the registry access, so this module never touches the private seam.
    trim_registered_output_schemas(server, trim_published_output_schema)
    # The surface is read back from the registry, not assumed from the selection: the
    # resources, the prompts and the instructions then describe the tools this process
    # actually publishes, so a filtered instance cannot claim one it did not register.
    surface = _registered_surface(server, enabled)
    prompt_names = available_prompts(surface.tool_names)
    # Resources and prompts are not domain tools: they publish the passive context and the
    # analysis templates, are static for the process lifetime, and are registered in both
    # modes (a read-only deployment is exactly where an audit prompt is useful). A prompt
    # whose workflow names a tool this surface does not have is not registered at all.
    register_resources(server, read_only=read_only, surface=surface)
    register_prompts(server, available_tools=surface.tool_names)
    # ``serverInfo.description`` is the installed package description, passed to the
    # constructor above and published verbatim: it carries no tool count, so it cannot
    # contradict ``tools/list`` for the full surface, a read-only deployment or a filtered
    # one. Only the instructions depend on what registration produced.
    server._lowlevel_server.instructions = instructions_for(surface, prompt_names)
    return server


def create_server_from_env(
    env: Mapping[str, str] | None = None,
    *,
    domains: Iterable[DomainRegistrar] | None = None,
) -> MCPServer[AppContext]:
    """Validate the environment and build the server.

    Args:
        env: Environment mapping to read. Defaults to :data:`os.environ`; passing an
            explicit mapping never touches the process environment.
        domains: Registration functions, as for :func:`create_server`. ``None`` selects the
            domains named by ``SOPHOS_TOOL_DOMAINS``.

    Raises:
        ConfigurationError: A required setting is missing or invalid, including an unknown,
            repeated or empty ``SOPHOS_TOOL_DOMAINS`` entry. The message names the setting
            and never contains the API key.
    """
    return create_server(Settings.from_env(env), domains=domains)


def main(env: Mapping[str, str] | None = None) -> None:
    """Entrypoint: validate configuration, then serve MCP over STDIO.

    Diagnostics go to stderr; stdout is reserved for the MCP protocol. A configuration
    failure exits with status 2 and one actionable line on stderr instead of a traceback
    the client cannot see.

    Args:
        env: Optional environment mapping for startup; defaults to :data:`os.environ`.
            Exposed so tests can exercise startup without mutating the process
            environment.
    """
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        server = create_server_from_env(env)
    except ConfigurationError as exc:
        sys.stderr.write(f"sophos-firewall-mcp: cannot start: {exc}\n")
        sys.stderr.flush()
        raise SystemExit(2) from None
    server.run("stdio")


if __name__ == "__main__":
    main()
