"""Network-architecture tools for the Sophos Firewall Configuration REST API.

This module owns the network domain's 28 tools:

* **25 read-only tools** that project the firewall's network architecture: interfaces,
  zones, IPv4/IPv6 routing gateways (WAN and custom), static unicast routes, SD-WAN routes,
  DHCP servers, DHCP leases, DHCP relays, DNS settings, DNS host entries, DNS request
  routes and static neighbors. The IPv4/IPv6 pairs are one tool each, selected by the
  required ``ip_family``. They are configuration and live-state views; the API exposes no
  live routing table, so none is promised.
* **3 VLAN-only interface mutations** -- ``network_interface_create_vlan``,
  ``network_interface_update_vlan`` and ``network_interface_delete_vlan``. They are the
  only writes in this domain and the only interface writes this server exposes. Physical,
  bridge, LAG and XFRM interfaces stay read-only because a wrong mutation can cut off
  management access.

VLAN-only enforcement
---------------------
``updateNetworkInterface`` and ``deleteNetworkInterface`` address an existing interface, so
each tool first reads it with ``getNetworkInterface`` and refuses anything whose ``type`` is
not ``vlan`` **before** the write; for delete that pre-read is the only enforcement, because
the operation has no request body. ``createNetworkInterface`` has no existing interface to
read, so the create tool pre-reads the **parent** interface named in the request: it must
exist and must be a physical, VLAN, bridge or LAG interface (a cellular WAN or XFRM
interface cannot carry a VLAN), and the body it sends always declares ``type: "vlan"``.

Registration
------------
``register_network_tools`` is this domain's single entry point: it registers the 28 network
tools and then delegates to :func:`sophos_firewall_mcp.tools.vpn.register_vpn_tools` (20
read-only VPN tools) and :func:`sophos_firewall_mcp.tools.system.register_status_tools` (2
read-only status tools), which are the other two surfaces of the network domain. Wire only
``register_network_tools`` into ``DEFAULT_DOMAINS``.

Every handler is a thin typed layer over :class:`NetworkAdapter`: it validates the closed
input model, resolves the shared application context, delegates to the adapter and projects
the response into a bounded model. No handler builds a URL, a header or an HTTP client, and
no tool argument ever reaches the request path unvalidated.
"""

from __future__ import annotations

import re
from typing import Any, TypeVar
from urllib.parse import quote

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ValidationError

from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import SophosAPIError
from sophos_firewall_mcp.models import network as models
from sophos_firewall_mcp.models.common import ListPage
from sophos_firewall_mcp.tools import DomainAdapter, ToolKind, register_tool, tool_error
from sophos_firewall_mcp.tools.system import register_status_tools
from sophos_firewall_mcp.tools.vpn import register_vpn_tools

__all__ = ["register_network_tools"]

ModelT = TypeVar("ModelT", bound=BaseModel)

# -- API paths (module constants: no tool argument ever reaches a path) -----------------

INTERFACES_PATH = "/network/interfaces/network-interfaces"
ZONES_PATH = "/network/zones"
GATEWAYS_IPV4_PATH = "/routing/gateways/ipv4"
GATEWAYS_IPV6_PATH = "/routing/gateways/ipv6"
_WAN_GATEWAYS_IPV4 = "/routing/gateways/wan/ipv4"
_WAN_GATEWAYS_IPV6 = "/routing/gateways/wan/ipv6"
_CUSTOM_GATEWAYS_IPV4 = "/routing/gateways/custom/ipv4"
_CUSTOM_GATEWAYS_IPV6 = "/routing/gateways/custom/ipv6"
UNICAST_ROUTES_IPV4_PATH = "/routing/static-unicast-routes/ipv4"
UNICAST_ROUTES_IPV6_PATH = "/routing/static-unicast-routes/ipv6"
_SDWAN_ROUTES_IPV4 = "/sd-wan/routes/ipv4"
_SDWAN_ROUTES_IPV6 = "/sd-wan/routes/ipv6"
_DHCP_SERVERS_IPV4 = "/network/dhcp/server/servers/ipv4"
_DHCP_SERVERS_IPV6 = "/network/dhcp/server/servers/ipv6"
_DHCP_LEASES_IPV4 = "/network/dhcp/server/leases/ipv4"
_DHCP_LEASES_IPV6 = "/network/dhcp/server/leases/ipv6"
_DHCP_RELAYS_IPV4 = "/network/dhcp/relays/ipv4"
_DHCP_RELAYS_IPV6 = "/network/dhcp/relays/ipv6"
_DNS_SETTINGS = "/network/dns/settings"
_DNS_HOST_ENTRIES = "/network/dns/host-entries"
_DNS_REQUEST_ROUTES = "/network/dns/request-routes"
_STATIC_NEIGHBORS_IPV4 = "/network/neighbors/static/ipv4"
_STATIC_NEIGHBORS_IPV6 = "/network/neighbors/static/ipv6"

#: Interface types a VLAN can be created on. A cellular WAN or XFRM interface cannot carry
#: a VLAN, and the create tool refuses those before it sends anything.
_VLAN_PARENT_TYPES = frozenset({"physical", "vlan", "bridge", "lag"})

#: The only interface type any interface write in this server may touch.
_VLAN_TYPE = "vlan"

#: Characters kept when an appliance-supplied value is echoed in an error message.
_SAFE_TEXT = re.compile(r"[^A-Za-z0-9_.:#\- ]")


def _segment(value: str) -> str:
    """Percent-encode one path segment (names may contain spaces, dots and slashes)."""
    return quote(value, safe="")


def _safe(value: Any) -> str:
    """Render an appliance-supplied value as inert, bounded text for an error message."""
    text = _SAFE_TEXT.sub("", str(value))[:64].strip()
    return text or "unknown"


def _require_object(payload: Any, path: str) -> dict[str, Any]:
    """Reject a non-object body from an operation that documents an object response."""
    if not isinstance(payload, dict):
        raise ToolError(f"the appliance returned a non-object body for GET {path}")
    return payload


def _schema_error(exc: ValidationError, path: str) -> ToolError:
    """Build the sanitized error for a response that does not match its output model.

    Only the field location is echoed: the rejected input may contain appliance data, and
    the raw payload must never reach the model.
    """
    first = exc.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "body"
    return ToolError(
        f"the appliance returned a response for {path} that does not match the documented "
        f"schema ({location})"
    )


def _project(payload: Any, model: type[ModelT], path: str) -> ModelT:
    """Validate one appliance payload into its bounded model, with a sanitized error."""
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise _schema_error(exc, path) from exc


def _refuse_non_vlan(payload: dict[str, Any], id_or_name: str) -> None:
    """Refuse a write on any interface whose type is not ``vlan``.

    Called only after the interface has been read, so a refusal happens before any write
    request is sent.
    """
    interface_type = payload.get("type")
    if interface_type != _VLAN_TYPE:
        raise ToolError(
            f"interface {_safe(id_or_name)!r} has type {_safe(interface_type)!r}; this server "
            "only writes interfaces of type 'vlan'. Physical, bridge, LAG and XFRM "
            "interfaces are read-only."
        )


def _refuse_unsuitable_parent(payload: dict[str, Any], parent: str) -> None:
    """Refuse a VLAN parent that does not exist as a VLAN-capable interface."""
    parent_type = payload.get("type")
    if parent_type not in _VLAN_PARENT_TYPES:
        raise ToolError(
            f"parent interface {_safe(parent)!r} has type {_safe(parent_type)!r}; a VLAN can "
            "only be created on a physical, vlan, bridge or lag interface."
        )


class NetworkAdapter(DomainAdapter):
    """Domain adapter for the network-architecture operations.

    It owns the path constants, calls the shared REST client and maps transport failures to
    sanitized ``ToolError`` messages. It never creates an HTTP client, never accepts a path
    from a tool argument, and never returns a raw Sophos payload to a handler: the handler
    validates the returned payload into a bounded model.
    """

    async def page(
        self, path: str, request: models.PageInput | models.FilteredPageInput
    ) -> dict[str, Any]:
        """Read one page of a paginated collection, with the declared name filters."""
        filters = request.name_filters() if isinstance(request, models.FilteredPageInput) else {}
        try:
            return await self.client.get_page(
                path,
                page=request.page,
                page_size=request.page_size,
                page_total=request.page_total,
                params=filters,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def collection(self, path: str, request: models.FilterInput) -> dict[str, Any]:
        """Read an unpaginated collection with the declared name filters."""
        try:
            payload = await self.client.get(path, params=request.name_filters())
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, path)

    async def keyset(self, path: str) -> dict[str, Any]:
        """Read a keyset-paginated collection (the DHCP leases declare no page parameters)."""
        try:
            payload = await self.client.get(path)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, path)

    async def object(self, path: str, id_or_name: str) -> dict[str, Any]:
        """Read one object by name or UUID."""
        full_path = f"{path}/{_segment(id_or_name)}"
        try:
            payload = await self.client.get(full_path)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, full_path)

    async def single(self, path: str) -> dict[str, Any]:
        """Read a singleton settings object."""
        try:
            payload = await self.client.get(path)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, path)

    # -- VLAN-only interface writes ----------------------------------------------------

    async def create_vlan(self, request: models.NetworkInterfaceCreateVlanInput) -> dict[str, Any]:
        """Create one VLAN interface after validating its parent interface."""
        parent = await self.object(INTERFACES_PATH, request.parent_interface)
        _refuse_unsuitable_parent(parent, request.parent_interface)

        body: dict[str, Any] = {
            "name": request.name,
            "type": _VLAN_TYPE,
            "vlanDetails": {
                "vlanId": request.vlan_id,
                "parentInterface": {"name": request.parent_interface},
            },
        }
        if request.zone is not None:
            body["zone"] = {"name": request.zone}
        if request.ipv4 is not None:
            body["ipv4"] = request.ipv4.model_dump(mode="json", by_alias=True, exclude_none=True)
        if request.ipv6 is not None:
            body["ipv6"] = request.ipv6.model_dump(mode="json", by_alias=True, exclude_none=True)

        try:
            payload = await self.client.post(INTERFACES_PATH, json=body)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, INTERFACES_PATH)

    async def update_vlan(self, request: models.NetworkInterfaceUpdateVlanInput) -> dict[str, Any]:
        """Patch one VLAN interface after confirming the target really is a VLAN."""
        id_or_name = request.id_or_name
        current = await self.object(INTERFACES_PATH, id_or_name)
        _refuse_non_vlan(current, id_or_name)

        body: dict[str, Any] = {}
        if request.name is not None:
            body["name"] = request.name
        if request.zone is not None:
            body["zone"] = {"name": request.zone}
        if request.ipv4 is not None:
            body["ipv4"] = request.ipv4.model_dump(mode="json", by_alias=True, exclude_none=True)
        if request.ipv6 is not None:
            body["ipv6"] = request.ipv6.model_dump(mode="json", by_alias=True, exclude_none=True)
        if request.mtu is not None:
            body["mtu"] = request.mtu
        if request.mss is not None:
            body["mss"] = request.mss

        try:
            payload = await self.client.patch(
                f"{INTERFACES_PATH}/{_segment(id_or_name)}", json=body
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, INTERFACES_PATH)

    async def delete_vlan(self, id_or_name: str) -> models.InterfaceDeleteOutput:
        """Delete one VLAN interface after confirming the target really is a VLAN."""
        current = await self.object(INTERFACES_PATH, id_or_name)
        _refuse_non_vlan(current, id_or_name)
        try:
            await self.client.delete(f"{INTERFACES_PATH}/{_segment(id_or_name)}")
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        # The client discards the ``{"deleted": ...}`` body; a 2xx is the appliance's
        # confirmation that the interface was deleted.
        return models.InterfaceDeleteOutput(deleted=True)


def register_network_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the network domain: 28 network tools plus the VPN and status surfaces.

    This is the only registration function the network domain needs in ``DEFAULT_DOMAINS``: it
    registers the network tools itself and delegates to
    :func:`~sophos_firewall_mcp.tools.vpn.register_vpn_tools` and
    :func:`~sophos_firewall_mcp.tools.system.register_status_tools` for the other two
    read-only surfaces of the issue.

    Args:
        server: The server built by :func:`sophos_firewall_mcp.server.create_server`.
        read_only: When true, the three VLAN mutation tools are not registered at all.
    """

    # -- Interfaces --------------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="network_interface_list",
        title="List network interfaces",
        description=(
            "List the firewall's network interfaces one page at a time, with optional name "
            "filters. Each item carries its type (physical, vlan, bridge, lag, xfrm or "
            "cellularWan), zone, IPv4/IPv6 configuration and VLAN/bridge/LAG details. "
            "Pagination: `page` is 1-based and `page_size` is 1-100 (default 10). "
            "Read-only: no interface is changed by this tool. Use network_interface_get for "
            "one interface, and the network_interface_*_vlan tools for the only interface "
            "writes this server exposes."
        ),
    )
    async def network_interface_list(
        request: models.FilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.NetworkInterface]:
        payload = await NetworkAdapter.from_context(ctx).page(INTERFACES_PATH, request)
        return _project(payload, ListPage[models.NetworkInterface], INTERFACES_PATH)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="network_interface_get",
        title="Get a network interface",
        description=(
            "Read one network interface by name or UUID. The response carries the interface "
            "type, which is what the VLAN-only write tools check before they touch anything. "
            "Read-only."
        ),
    )
    async def network_interface_get(
        request: models.InterfaceRefInput, ctx: Context[AppContext]
    ) -> models.NetworkInterface:
        payload = await NetworkAdapter.from_context(ctx).object(INTERFACES_PATH, request.id_or_name)
        return _project(payload, models.NetworkInterface, INTERFACES_PATH)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="network_interface_create_vlan",
        title="Create a VLAN interface",
        description=(
            "Create one VLAN interface. The parent interface is read first: it must exist and "
            "must be a physical, vlan, bridge or lag interface, and the request always creates "
            "type 'vlan'. Physical, bridge, LAG and XFRM interfaces cannot be created or "
            "changed by this server. A created interface is not enabled by this tool; the API "
            "exposes no enable/disable operation for interfaces."
        ),
        annotations=ToolAnnotations(destructive_hint=False, idempotent_hint=False),
    )
    async def network_interface_create_vlan(
        request: models.NetworkInterfaceCreateVlanInput, ctx: Context[AppContext]
    ) -> models.NetworkInterface:
        payload = await NetworkAdapter.from_context(ctx).create_vlan(request)
        return _project(payload, models.NetworkInterface, INTERFACES_PATH)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="network_interface_update_vlan",
        title="Update a VLAN interface",
        description=(
            "Partially update one VLAN interface with a JSON Merge Patch body: only the fields "
            "you set are sent. The interface is read first and the write is refused unless its "
            "type is 'vlan'. The VLAN ID and parent interface cannot be changed (the API's "
            "PATCH body has no vlanDetails member), and description is bridge-only, so neither "
            "is exposed."
        ),
        annotations=ToolAnnotations(destructive_hint=False, idempotent_hint=True),
    )
    async def network_interface_update_vlan(
        request: models.NetworkInterfaceUpdateVlanInput, ctx: Context[AppContext]
    ) -> models.NetworkInterface:
        payload = await NetworkAdapter.from_context(ctx).update_vlan(request)
        return _project(payload, models.NetworkInterface, INTERFACES_PATH)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="network_interface_delete_vlan",
        title="Delete a VLAN interface",
        description=(
            "Delete one VLAN interface. The interface is read first and the delete is refused "
            "unless its type is 'vlan'; because deleteNetworkInterface has no request body, "
            "that pre-read is the only enforcement of the VLAN-only rule. Destructive: the "
            "interface and its configuration are removed, and a non-2xx response is reported "
            "as an error rather than retried. Idempotent: repeating the delete has no further "
            "effect, and an already-absent interface reports not found."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def network_interface_delete_vlan(
        request: models.NetworkInterfaceDeleteVlanInput, ctx: Context[AppContext]
    ) -> models.InterfaceDeleteOutput:
        return await NetworkAdapter.from_context(ctx).delete_vlan(request.id_or_name)

    # -- Zones -------------------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="zone_list",
        title="List zones",
        description=(
            "List the firewall's network zones one page at a time, with optional name filters. "
            "Each zone carries its type (lan, wan, dmz, local, vpn or discover) and the firewall "
            "services allowed for it. Pagination: `page` is 1-based and `page_size` is 1-100 "
            "(default 10). Read-only: zone mutations are excluded from this server."
        ),
    )
    async def zone_list(
        request: models.FilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.Zone]:
        payload = await NetworkAdapter.from_context(ctx).page(ZONES_PATH, request)
        return _project(payload, ListPage[models.Zone], ZONES_PATH)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="zone_get",
        title="Get a zone",
        description="Read one network zone by name or UUID. Read-only.",
    )
    async def zone_get(request: models.ZoneRefInput, ctx: Context[AppContext]) -> models.Zone:
        payload = await NetworkAdapter.from_context(ctx).object(ZONES_PATH, request.id_or_name)
        return _project(payload, models.Zone, ZONES_PATH)

    # -- Gateways (IPv4 and IPv6; ``ip_family`` selects the collection) ----------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="gateway_list",
        title="List gateways",
        description=(
            "List the configured IPv4 or IPv6 routing gateways (both WAN and custom), "
            "selected by the required `ip_family`, one page at a time, with optional name "
            "filters. This is configuration, not live gateway state. Read-only: gateway "
            "mutations are excluded from this server."
        ),
    )
    async def gateway_list(
        request: models.IpFamilyFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.GatewayOutput]:
        path = GATEWAYS_IPV6_PATH if request.ip_family == "ipv6" else GATEWAYS_IPV4_PATH
        payload = await NetworkAdapter.from_context(ctx).page(path, request)
        return _project(payload, ListPage[models.GatewayOutput], path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="wan_gateway_list",
        title="List WAN gateways",
        description=(
            "List the IPv4 or IPv6 WAN gateways, selected by the required `ip_family`, one "
            "page at a time, with optional name filters. Each gateway carries its "
            "active/backup role, weight, interface, address, backup activation settings and "
            "health-check rules. Read-only."
        ),
    )
    async def wan_gateway_list(
        request: models.IpFamilyFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.WanGatewayOutput]:
        path = _WAN_GATEWAYS_IPV6 if request.ip_family == "ipv6" else _WAN_GATEWAYS_IPV4
        payload = await NetworkAdapter.from_context(ctx).page(path, request)
        return _project(payload, ListPage[models.WanGatewayOutput], path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="wan_gateway_get",
        title="Get a WAN gateway",
        description=(
            "Read one IPv4 or IPv6 WAN gateway by name or UUID, selected by the required "
            "`ip_family`. Read-only."
        ),
    )
    async def wan_gateway_get(
        request: models.IpFamilyGatewayRefInput, ctx: Context[AppContext]
    ) -> models.WanGatewayOutput:
        path = _WAN_GATEWAYS_IPV6 if request.ip_family == "ipv6" else _WAN_GATEWAYS_IPV4
        payload = await NetworkAdapter.from_context(ctx).object(path, request.id_or_name)
        return _project(payload, models.WanGatewayOutput, path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="custom_gateway_list",
        title="List custom gateways",
        description=(
            "List the custom IPv4 or IPv6 gateways, selected by the required `ip_family`, "
            "one page at a time, with optional name filters. Each gateway carries its "
            "interface, zone, address and health-check settings. Read-only."
        ),
    )
    async def custom_gateway_list(
        request: models.IpFamilyFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.CustomGatewayOutput]:
        path = _CUSTOM_GATEWAYS_IPV6 if request.ip_family == "ipv6" else _CUSTOM_GATEWAYS_IPV4
        payload = await NetworkAdapter.from_context(ctx).page(path, request)
        return _project(payload, ListPage[models.CustomGatewayOutput], path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="custom_gateway_get",
        title="Get a custom gateway",
        description=(
            "Read one custom IPv4 or IPv6 gateway by name or UUID, selected by the required "
            "`ip_family`. Read-only."
        ),
    )
    async def custom_gateway_get(
        request: models.IpFamilyGatewayRefInput, ctx: Context[AppContext]
    ) -> models.CustomGatewayOutput:
        path = _CUSTOM_GATEWAYS_IPV6 if request.ip_family == "ipv6" else _CUSTOM_GATEWAYS_IPV4
        payload = await NetworkAdapter.from_context(ctx).object(path, request.id_or_name)
        return _project(payload, models.CustomGatewayOutput, path)

    # -- Static unicast routes ---------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="unicast_route_list",
        title="List static unicast routes",
        description=(
            "List the configured IPv4 or IPv6 static unicast routes, selected by the "
            "required `ip_family`, one page at a time. This operation declares no name "
            "filters. It is configuration, not the live routing table, which the API does "
            "not expose. Read-only: route mutations are excluded."
        ),
    )
    async def unicast_route_list(
        request: models.IpFamilyPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.UnicastRouteOutput]:
        path = UNICAST_ROUTES_IPV6_PATH if request.ip_family == "ipv6" else UNICAST_ROUTES_IPV4_PATH
        payload = await NetworkAdapter.from_context(ctx).page(path, request)
        return _project(payload, ListPage[models.UnicastRouteOutput], path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="unicast_route_get",
        title="Get a static unicast route",
        description=(
            "Read one IPv4 or IPv6 static unicast route by name or UUID, selected by the "
            "required `ip_family`. Read-only."
        ),
    )
    async def unicast_route_get(
        request: models.IpFamilyWideRefInput, ctx: Context[AppContext]
    ) -> models.UnicastRouteOutput:
        path = UNICAST_ROUTES_IPV6_PATH if request.ip_family == "ipv6" else UNICAST_ROUTES_IPV4_PATH
        payload = await NetworkAdapter.from_context(ctx).object(path, request.id_or_name)
        return _project(payload, models.UnicastRouteOutput, path)

    # -- SD-WAN routes -----------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sdwan_route_list",
        title="List SD-WAN routes",
        description=(
            "List the configured IPv4 or IPv6 SD-WAN routes, selected by the required "
            "`ip_family`, one page at a time, with optional name filters. Each route carries "
            "its interface/service/application/user selectors, link selection and "
            "source/destination networks. Read-only: SD-WAN mutations and moves are "
            "excluded."
        ),
    )
    async def sdwan_route_list(
        request: models.IpFamilyFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.SdwanRoute]:
        path = _SDWAN_ROUTES_IPV6 if request.ip_family == "ipv6" else _SDWAN_ROUTES_IPV4
        payload = await NetworkAdapter.from_context(ctx).page(path, request)
        return _project(payload, ListPage[models.SdwanRoute], path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sdwan_route_get",
        title="Get an SD-WAN route",
        description=(
            "Read one IPv4 or IPv6 SD-WAN route by name or UUID, selected by the required "
            "`ip_family`. Read-only."
        ),
    )
    async def sdwan_route_get(
        request: models.IpFamilySdwanRefInput, ctx: Context[AppContext]
    ) -> models.SdwanRoute:
        path = _SDWAN_ROUTES_IPV6 if request.ip_family == "ipv6" else _SDWAN_ROUTES_IPV4
        payload = await NetworkAdapter.from_context(ctx).object(path, request.id_or_name)
        return _project(payload, models.SdwanRoute, path)

    # -- DHCP servers ------------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dhcp_server_list",
        title="List DHCP servers",
        description=(
            "List the IPv4 or IPv6 DHCP servers, selected by the required `ip_family`, with "
            "optional name filters. The operation declares no pagination, so the whole "
            "collection is returned in one call and pages is null. Configuration only: use "
            "dhcp_lease_list for live leases. Read-only: DHCP mutations are excluded."
        ),
    )
    async def dhcp_server_list(
        request: models.IpFamilyFilterInput, ctx: Context[AppContext]
    ) -> models.UnpaginatedList[models.DhcpServerOutput]:
        path = _DHCP_SERVERS_IPV6 if request.ip_family == "ipv6" else _DHCP_SERVERS_IPV4
        payload = await NetworkAdapter.from_context(ctx).collection(path, request)
        return _project(payload, models.UnpaginatedList[models.DhcpServerOutput], path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dhcp_server_get",
        title="Get a DHCP server",
        description=(
            "Read one IPv4 or IPv6 DHCP server by name or UUID, selected by the required "
            "`ip_family`. Read-only."
        ),
    )
    async def dhcp_server_get(
        request: models.IpFamilyWideRefInput, ctx: Context[AppContext]
    ) -> models.DhcpServerOutput:
        path = _DHCP_SERVERS_IPV6 if request.ip_family == "ipv6" else _DHCP_SERVERS_IPV4
        payload = await NetworkAdapter.from_context(ctx).object(path, request.id_or_name)
        return _project(payload, models.DhcpServerOutput, path)

    # -- DHCP leases -------------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dhcp_lease_list",
        title="List DHCP leases",
        description=(
            "List the active IPv4 or IPv6 DHCP leases, selected by the required `ip_family`. "
            "This is live state, not configuration. The API declares no page/pageSize "
            "parameters for this operation (it returns keyset metadata), so the call takes "
            "no pagination input and returns one page with its pages metadata preserved. "
            "Only the first page is reachable: a non-null pages.nextKey means the list is "
            "incomplete and the remaining leases cannot be fetched through this server. "
            "pages.maxSize is not a page-size bound here -- the appliance reports the item "
            "count of the returned page in it (21 items and maxSize 21 on the tested "
            "appliance) -- and the value is preserved as returned. Read-only."
        ),
    )
    async def dhcp_lease_list(
        request: models.DhcpLeaseListInput, ctx: Context[AppContext]
    ) -> models.KeysetPage[models.DhcpLeaseOutput]:
        path = _DHCP_LEASES_IPV6 if request.ip_family == "ipv6" else _DHCP_LEASES_IPV4
        payload = await NetworkAdapter.from_context(ctx).keyset(path)
        return _project(payload, models.KeysetPage[models.DhcpLeaseOutput], path)

    # -- DHCP relays -------------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dhcp_relay_list",
        title="List DHCP relays",
        description=(
            "List the IPv4 or IPv6 DHCP relays, selected by the required `ip_family`, with "
            "optional name filters. The operation declares no pagination, so the whole "
            "collection is returned in one call and pages is null. The interface reference "
            "on a relay is the logical interface name (for example 'DMZ - Services'), not "
            "the hardware name ('Port3'): the appliance rejects the hardware name with 500 "
            "interfaceDoesNotExist. Read-only: DHCP mutations are excluded."
        ),
    )
    async def dhcp_relay_list(
        request: models.IpFamilyFilterInput, ctx: Context[AppContext]
    ) -> models.UnpaginatedList[models.DhcpRelayOutput]:
        path = _DHCP_RELAYS_IPV6 if request.ip_family == "ipv6" else _DHCP_RELAYS_IPV4
        payload = await NetworkAdapter.from_context(ctx).collection(path, request)
        return _project(payload, models.UnpaginatedList[models.DhcpRelayOutput], path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dhcp_relay_get",
        title="Get a DHCP relay",
        description=(
            "Read one IPv4 or IPv6 DHCP relay by UUID, selected by the required `ip_family`. "
            "The API declares format uuid for this path parameter, so a relay name is "
            "rejected before any request is sent, even though the operation's path is "
            "{idOrName} and its description says 'ID or name'. The appliance may answer 401 "
            "for this sub-resource even for a real, listed relay: on SFOS 23.0.0 "
            "GA-Build371 the collection returns 200 and the create 201 with the same token, "
            "while GET and DELETE on the relay itself return 401 for both a name and a UUID, "
            "and an unknown path returns 404. A 401 from this tool therefore does not by "
            "itself mean the API key is invalid: confirm the relay with dhcp_relay_list "
            "first, and treat the endpoint as possibly unusable on this firmware. Read-only."
        ),
    )
    async def dhcp_relay_get(
        request: models.IpFamilyDhcpRelayRefInput, ctx: Context[AppContext]
    ) -> models.DhcpRelayOutput:
        path = _DHCP_RELAYS_IPV6 if request.ip_family == "ipv6" else _DHCP_RELAYS_IPV4
        payload = await NetworkAdapter.from_context(ctx).object(path, request.id)
        return _project(payload, models.DhcpRelayOutput, path)

    # -- DNS ---------------------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dns_settings_get",
        title="Get DNS settings",
        description=(
            "Read the firewall's DNS settings: DNS Protection state, DNSSEC, the DNS protocol, "
            "the unencrypted upstream servers and the DNS-over-HTTPS servers. Configuration, "
            "not live resolver state. Read-only: DNS mutations are excluded."
        ),
    )
    async def dns_settings_get(ctx: Context[AppContext]) -> models.DnsSettings:
        payload = await NetworkAdapter.from_context(ctx).single(_DNS_SETTINGS)
        return _project(payload, models.DnsSettings, _DNS_SETTINGS)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dns_host_entry_list",
        title="List DNS host entries",
        description=(
            "List the DNS host entries one page at a time, with optional name filters. Each "
            "entry carries its domain, reverse-resolution flag and up to eight records with "
            "TTL, weight and publish-on-WAN settings. Pagination: `page` is 1-based and "
            "`page_size` is 1-100 (default 10). Read-only."
        ),
    )
    async def dns_host_entry_list(
        request: models.FilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.DnsHostEntry]:
        payload = await NetworkAdapter.from_context(ctx).page(_DNS_HOST_ENTRIES, request)
        return _project(payload, ListPage[models.DnsHostEntry], _DNS_HOST_ENTRIES)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dns_host_entry_get",
        title="Get a DNS host entry",
        description="Read one DNS host entry by name or UUID. Read-only.",
    )
    async def dns_host_entry_get(
        request: models.WideRefInput, ctx: Context[AppContext]
    ) -> models.DnsHostEntry:
        payload = await NetworkAdapter.from_context(ctx).object(
            _DNS_HOST_ENTRIES, request.id_or_name
        )
        return _project(payload, models.DnsHostEntry, _DNS_HOST_ENTRIES)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dns_request_route_list",
        title="List DNS request routes",
        description=(
            "List the DNS request routes one page at a time, with optional name filters. Each "
            "route maps a domain to a set of DNS servers. Pagination: `page` is 1-based and "
            "`page_size` is 1-100 (default 10). Read-only."
        ),
    )
    async def dns_request_route_list(
        request: models.FilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.DnsRequestRoute]:
        payload = await NetworkAdapter.from_context(ctx).page(_DNS_REQUEST_ROUTES, request)
        return _project(payload, ListPage[models.DnsRequestRoute], _DNS_REQUEST_ROUTES)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="dns_request_route_get",
        title="Get a DNS request route",
        description="Read one DNS request route by name or UUID. Read-only.",
    )
    async def dns_request_route_get(
        request: models.WideRefInput, ctx: Context[AppContext]
    ) -> models.DnsRequestRoute:
        payload = await NetworkAdapter.from_context(ctx).object(
            _DNS_REQUEST_ROUTES, request.id_or_name
        )
        return _project(payload, models.DnsRequestRoute, _DNS_REQUEST_ROUTES)

    # -- Static neighbors --------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="static_neighbor_list",
        title="List static neighbors",
        description=(
            "List the static IPv4 or IPv6 neighbor (ARP) entries, selected by the required "
            "`ip_family`, one page at a time, with optional name filters. The interface "
            "reference on an entry is the logical interface name (for example 'DMZ - "
            "Services'), not the hardware name ('Port3'): the appliance rejects the hardware "
            "name with 400 'Invalid interface.'. Read-only: neighbor mutations are excluded, "
            "and the global neighbor settings are not exposed."
        ),
    )
    async def static_neighbor_list(
        request: models.IpFamilyFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.StaticNeighborOutput]:
        path = _STATIC_NEIGHBORS_IPV6 if request.ip_family == "ipv6" else _STATIC_NEIGHBORS_IPV4
        payload = await NetworkAdapter.from_context(ctx).page(path, request)
        return _project(payload, ListPage[models.StaticNeighborOutput], path)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="static_neighbor_get",
        title="Get a static neighbor",
        description=(
            "Read one static IPv4 or IPv6 neighbor entry by name or UUID, selected by the "
            "required `ip_family`. Read-only."
        ),
    )
    async def static_neighbor_get(
        request: models.IpFamilyWideRefInput, ctx: Context[AppContext]
    ) -> models.StaticNeighborOutput:
        path = _STATIC_NEIGHBORS_IPV6 if request.ip_family == "ipv6" else _STATIC_NEIGHBORS_IPV4
        payload = await NetworkAdapter.from_context(ctx).object(path, request.id_or_name)
        return _project(payload, models.StaticNeighborOutput, path)

    # -- The other two read-only surfaces of the network domain ------------------------

    register_vpn_tools(server, read_only=read_only)
    register_status_tools(server, read_only=read_only)
