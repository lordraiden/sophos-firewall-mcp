"""MCP server factory and entrypoint for Sophos Firewall MCP.

The server is a local STDIO MCP server that administers one Sophos Firewall appliance
through its Configuration REST API. This module owns application construction, the
lifespan and the STDIO entrypoint; domain tools live in :mod:`sophos_firewall_mcp.tools`
and register themselves through the contract documented there.

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
to stderr. ``MCPServer(..., subscriptions=False)`` is used because the tool catalog is
static for the process lifetime (the read-only mode is applied at startup), so the SDK
must not advertise ``subscriptions/listen`` or ``listChanged``.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator, Iterable, Mapping
from contextlib import asynccontextmanager

# Must precede the mcp import: it is the check that explains a shadowed or too-new `mcp`
# before the import below dies with a bare ModuleNotFoundError the MCP client cannot see
# (empty error). Kept from the pre-REST server; it is not XML-specific.
from sophos_firewall_mcp._env_guard import verify_local_mcp

verify_local_mcp()

from mcp.server.mcpserver import MCPServer  # noqa: E402

from sophos_firewall_mcp.client import SophosRestClient  # noqa: E402
from sophos_firewall_mcp.config import ConfigurationError, Settings  # noqa: E402
from sophos_firewall_mcp.context import AppContext  # noqa: E402
from sophos_firewall_mcp.tools import DomainRegistrar  # noqa: E402
from sophos_firewall_mcp.tools.firewall_rules import register_firewall_tools  # noqa: E402
from sophos_firewall_mcp.tools.hosts_objects import register_objects_tools  # noqa: E402
from sophos_firewall_mcp.tools.nat_rules import register_nat_tools  # noqa: E402
from sophos_firewall_mcp.tools.network import register_network_tools  # noqa: E402
from sophos_firewall_mcp.tools.users_auth import register_users_tools  # noqa: E402

__all__ = [
    "DEFAULT_DOMAINS",
    "INSTRUCTIONS",
    "SERVER_NAME",
    "create_server",
    "create_server_from_env",
    "main",
]

logger = logging.getLogger(__name__)

#: Name advertised to MCP clients.
SERVER_NAME = "Sophos Firewall MCP Server"

#: Server-level instructions shown to the model. Domain tools carry their own.
INSTRUCTIONS = (
    "Administers a Sophos Firewall (SFOS) through its Configuration REST API. Tools are "
    "narrow and typed: they list, read, create, update, move or delete firewall and NAT "
    "rules, address and service objects, users and live sessions. Read-only tools never "
    "modify the appliance. When the server runs in read-only mode, mutation tools are "
    "not registered at all."
)

#: Domain registration functions, in registration order.
#:
#: Phase 2 (#27-#31, #35): the six domain families from ADR-001 §10. ``network`` also
#: registers the VPN and status tools, so it is a single entry point. ``audit`` is added
#: last because it composes the other domains' adapters.
DEFAULT_DOMAINS: tuple[DomainRegistrar, ...] = (
    register_firewall_tools,
    register_nat_tools,
    register_objects_tools,
    register_users_tools,
    register_network_tools,
)


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

    server: MCPServer[AppContext] = MCPServer(
        SERVER_NAME,
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
        subscriptions=False,
    )
    for register in domains:
        register(server, read_only=read_only)
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
