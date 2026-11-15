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
once, instead of repeating them in 152 tool descriptions; the prompts carry the three
analysis workflows (audit the rule base, explain a flow, find unused objects). All three
catalogs are static for the process lifetime.

Lifecycle
---------
``create_server(settings)`` validates nothing about the environment -- it receives
settings that :func:`create_server_from_env` already validated -- and builds the server:
the read-only mode is resolved from those settings *before* any domain registers a tool,
because the SDK does not re-read the tool registry and the tool set must be fixed for the
process lifetime. The lifespan then creates exactly one
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
``0`` means "immediately stale" and makes a client re-fetch a ~894 KB payload on every
turn.

Identity
--------
``serverInfo`` is built from the installed distribution metadata (``version``,
``description``, ``website_url``) plus :data:`SERVER_TITLE`, so a client can report which
release produced a behaviour without the version being duplicated in code.
"""

from __future__ import annotations

import importlib.metadata
import logging
import sys
from collections.abc import AsyncIterator, Iterable, Mapping
from contextlib import asynccontextmanager
from typing import NamedTuple

# Must precede the mcp import: it is the check that explains a shadowed or too-new `mcp`
# before the import below dies with a bare ModuleNotFoundError the MCP client cannot see
# (empty error). Kept from the pre-REST server; it is not XML-specific.
from sophos_firewall_mcp._env_guard import verify_local_mcp

verify_local_mcp()

from mcp.server import CacheHint  # noqa: E402
from mcp.server.caching import CacheableMethod  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402

from sophos_firewall_mcp.client import SophosRestClient  # noqa: E402
from sophos_firewall_mcp.config import ConfigurationError, Settings  # noqa: E402
from sophos_firewall_mcp.context import AppContext  # noqa: E402
from sophos_firewall_mcp.prompts import register_prompts  # noqa: E402
from sophos_firewall_mcp.resources import register_resources  # noqa: E402
from sophos_firewall_mcp.tools import DomainRegistrar  # noqa: E402
from sophos_firewall_mcp.tools.audit import register_audit_tools  # noqa: E402
from sophos_firewall_mcp.tools.firewall_rules import register_firewall_tools  # noqa: E402
from sophos_firewall_mcp.tools.hosts_objects import register_objects_tools  # noqa: E402
from sophos_firewall_mcp.tools.nat_rules import register_nat_tools  # noqa: E402
from sophos_firewall_mcp.tools.network import register_network_tools  # noqa: E402
from sophos_firewall_mcp.tools.users_auth import register_users_tools  # noqa: E402

__all__ = [
    "DEFAULT_DOMAINS",
    "INSTRUCTIONS",
    "SERVER_NAME",
    "SERVER_TITLE",
    "create_server",
    "create_server_from_env",
    "main",
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
#: "immediately stale" and which makes a client re-fetch a ~894 KB ``tools/list`` payload
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
#: Two conventions are stated here, once, instead of in 144 tool descriptions: the
#: ``request`` wrapper every tool with arguments uses, and the fact that a successful
#: result carries the same payload twice (``content`` text and ``structuredContent``).
#: Both are properties of this server's calling convention, not of any one domain.
INSTRUCTIONS = (
    "Administers a Sophos Firewall (SFOS) through its Configuration REST API. Tools are "
    "narrow and typed: they list, read, create, update, move or delete firewall and NAT "
    "rules, address and service objects, users and live sessions. Read-only tools never "
    "modify the appliance. When the server runs in read-only mode, mutation tools are "
    "not registered at all. Every tool that takes arguments takes them flat: the fields "
    "its `inputSchema` lists are the fields the call sends, with no wrapper object. A tool "
    "whose request is a union of shapes publishes a root `oneOf` instead, and its "
    "discriminator (`ip_family` or `type`) selects the variant. Every "
    "successful result carries the same payload twice, as `content` text and as "
    "`structuredContent`; read one of them, not both."
)

#: Domain registration functions, in registration order.
#:
#: Phase 2 (#27-#31, #35): the six domain families from ADR-001 §10. ``network`` also
#: registers the VPN and status tools, so it is a single entry point. ``audit`` is last
#: because it composes the other domains' adapters.
DEFAULT_DOMAINS: tuple[DomainRegistrar, ...] = (
    register_firewall_tools,
    register_nat_tools,
    register_objects_tools,
    register_users_tools,
    register_network_tools,
    register_audit_tools,
)


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


def create_server(
    settings: Settings,
    *,
    domains: Iterable[DomainRegistrar] = DEFAULT_DOMAINS,
) -> MCPServer[AppContext]:
    """Build the MCP server for already-validated settings.

    Configuration is validated once, before this function is called (see
    :func:`create_server_from_env`), because the read-only mode decides the tool set and
    the SDK does not re-read the registry after construction.

    Args:
        settings: Validated connection settings. The API key inside is a ``SecretStr``
            and is only ever placed in the ``Authorization`` header by the client.
        domains: Registration functions called once each, before the server starts. Each
            receives the server and the resolved ``read_only`` flag.

    Returns:
        A server whose lifespan creates one shared REST client and yields the
        :class:`~sophos_firewall_mcp.context.AppContext`.

    Raises:
        TypeError: ``settings`` is not a :class:`~sophos_firewall_mcp.config.Settings`.
    """
    if not isinstance(settings, Settings):
        raise TypeError("settings must be a Settings instance")
    read_only = settings.read_only_mode

    @asynccontextmanager
    async def lifespan(_: MCPServer[AppContext]) -> AsyncIterator[AppContext]:
        """Create the one shared client, yield the context, close the client exactly once.

        The environment was already validated by :func:`create_server_from_env` before the
        tool set was fixed. Constructing the client here is the remaining startup
        validation: an unusable TLS/CA configuration fails the lifespan instead of the
        first tool call. The client is closed in ``finally`` on every shutdown path.
        """
        logger.info(
            "starting %s: appliance %s, read-only=%s",
            SERVER_NAME,
            settings.authority,
            read_only,
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
    )
    for register in domains:
        register(server, read_only=read_only)
    # Resources and prompts are not domain tools: they publish the passive context and the
    # analysis templates, are static for the process lifetime, and are registered in both
    # modes (a read-only deployment is exactly where an audit prompt is useful).
    register_resources(server, read_only=read_only)
    register_prompts(server)
    return server


def create_server_from_env(
    env: Mapping[str, str] | None = None,
    *,
    domains: Iterable[DomainRegistrar] = DEFAULT_DOMAINS,
) -> MCPServer[AppContext]:
    """Validate the environment and build the server.

    Args:
        env: Environment mapping to read. Defaults to :data:`os.environ`; passing an
            explicit mapping never touches the process environment.
        domains: Registration functions, as for :func:`create_server`.

    Raises:
        ConfigurationError: A required setting is missing or invalid. The message names
            the setting and never contains the API key.
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
