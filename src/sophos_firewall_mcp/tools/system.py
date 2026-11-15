"""Read-only network status tools.

The API exposes exactly two status operations, and this module registers exactly those
two -- no more:

* ``getDnsProtectionStatus`` (``GET /network/dns/protection/status``) -- the DNS Protection
  state of the appliance;
* ``getCellularWanStatus`` (``GET /network/cellular-wan/modem-status``) -- the live cellular
  WAN modem state.

There is deliberately **no** generic "firewall health" tool. The Web Admin Console's
Firewall Health Check is a policy-compliance view, not a REST resource, and the API has
no endpoint that returns appliance model, serial number, firmware version, uptime or system
service state. Those are accepted regressions: no placeholder tool is advertised for them.

Both tools are reads and are registered in read-only mode as well.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import SophosAPIError
from sophos_firewall_mcp.models import network as models
from sophos_firewall_mcp.tools import DomainAdapter, ToolKind, register_tool, tool_error

__all__ = ["register_status_tools"]

# -- API paths (module constants: no tool argument ever reaches a path) -----------------

_DNS_PROTECTION_STATUS = "/network/dns/protection/status"
_CELLULAR_WAN_STATUS = "/network/cellular-wan/modem-status"


def _require_object(payload: Any, path: str) -> dict[str, Any]:
    """Reject a non-object body from an operation that documents an object response."""
    if not isinstance(payload, dict):
        raise ToolError(f"the appliance returned a non-object body for GET {path}")
    return payload


class StatusAdapter(DomainAdapter):
    """Domain adapter for the two read-only status operations."""

    async def single(self, path: str) -> dict[str, Any]:
        """Read one status object."""
        try:
            payload = await self.client.get(path)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, path)


def register_status_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the two read-only status tools.

    Called by :func:`sophos_firewall_mcp.tools.network.register_network_tools`; it can also be
    called directly in a test. Both tools are reads, so ``read_only`` has no effect on the
    registered set.

    Args:
        server: The server built by :func:`sophos_firewall_mcp.server.create_server`.
        read_only: The resolved read-only mode; the status tools are reads either way.
    """

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="network_status_dns_protection",
        title="Get DNS Protection status",
        description=(
            "Read the appliance's DNS Protection status (active, notConfigured, notSubscribed, "
            "requiresSophosCentralRegistration or firewallNotRecognized) and when it was last "
            "updated. This is one specific status endpoint, not a general firewall health "
            "check. Read-only."
        ),
    )
    async def network_status_dns_protection(ctx: Context[AppContext]) -> models.DnsProtectionStatus:
        payload = await StatusAdapter.from_context(ctx).single(_DNS_PROTECTION_STATUS)
        return models.DnsProtectionStatus.model_validate(payload)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="network_status_cellular_wan",
        title="Get cellular WAN modem status",
        description=(
            "Read the number of cellular WAN modems detected and the live state of the modem: "
            "model, connection and SIM status, signal indicators, airplane mode, network "
            "registration, bandwidth and connection duration. This is one specific status "
            "endpoint, not a general firewall health check. Read-only."
        ),
    )
    async def network_status_cellular_wan(ctx: Context[AppContext]) -> models.CellularWanStatus:
        payload = await StatusAdapter.from_context(ctx).single(_CELLULAR_WAN_STATUS)
        return models.CellularWanStatus.model_validate(payload)
