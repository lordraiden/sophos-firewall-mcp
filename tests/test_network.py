"""Contract tests for the network-architecture domain (issue #31, ``tools/network.py``).

Every test runs against RESPX: no firewall, no network, no real credentials. The tests prove
the exact request each tool builds (method, path, query, headers, body, content type), the
bounded projections, the VLAN-only pre-read rule (a non-VLAN interface is refused before any
write request is sent), pagination bounds, sanitized error mapping, the published tool
surface and its annotations, and the read-only filter.

The handlers are exercised through the official SDK client, so the whole chain runs: MCP
argument validation, the typed handler, the domain adapter, the shared REST client and the
lifespan-created ``AppContext``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from mcp import Client, types

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.models.network import (
    DhcpRelayRefInput,
    DhcpServerIpv4,
    DnsSettings,
    FilterInput,
    FilteredPageInput,
    KeysetPage,
    KeysetPages,
    NetworkInterface,
    NetworkInterfaceCreateVlanInput,
    NetworkInterfaceUpdateVlanInput,
    PageInput,
    SdwanRoute,
    UnicastRouteIpv4,
    UnicastRouteIpv6,
    VlanIpv4Create,
    ZoneRefInput,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.network import register_network_tools

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
API_PREFIX = "/api/firewall-config/v1"

INTERFACES = "/network/interfaces/network-interfaces"
SPEC_PATH = Path(__file__).resolve().parents[1] / "firewall_config_openapi.yaml"

RELAY_UUID = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"

PAGE = {"current": 1, "size": 50, "maxSize": 100}
DEFAULT_PAGE_QUERY = {"page": "1", "pageSize": "10", "pageTotal": "false"}


# -- Helpers ---------------------------------------------------------------------------


def make_settings(**overrides: Any) -> Settings:
    """Build valid settings without touching the process environment."""
    values: dict[str, Any] = {
        "host": HOST,
        "port": 4444,
        "api_key": KEY,
        "verify_ssl": False,
        "timeout": 5.0,
        "read_only_mode": False,
    }
    values.update(overrides)
    return Settings(**values)


def make_server(**overrides: Any) -> Any:
    """A server with only the network domain registered."""
    return create_server(make_settings(**overrides), domains=[register_network_tools])


async def _accept_confirmation(
    context: Any, params: types.ElicitRequestParams
) -> types.ElicitResult:
    """Answer the destructive-confirmation question with an explicit accept."""
    return types.ElicitResult(action="accept", content={"confirm": True})


async def call_tool(name: str, arguments: dict[str, Any], *, read_only: bool = False) -> Any:
    """Call one tool through the official SDK client (full lifespan included)."""
    server = make_server(read_only_mode=read_only)
    async with Client(server, elicitation_callback=_accept_confirmation) as client:
        return await client.call_tool(name, arguments)


async def tool_map(*, read_only: bool = False) -> dict[str, Any]:
    """The published tools of the network domain, keyed by name."""
    server = make_server(read_only_mode=read_only)
    return {tool.name: tool for tool in await server.list_tools()}


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


def request_body(route: Any) -> Any:
    """The decoded JSON body of the last request the route saw."""
    return json.loads(route.calls.last.request.content)


# -- Read operations: one contract test per operation ----------------------------------

#: ``(tool, path, arguments, expected query, response body)`` for every network read tool.
#: The tools that take the required ``ip_family`` argument.
MERGED_TOOLS = {
    "gateway_list",
    "wan_gateway_list",
    "wan_gateway_get",
    "custom_gateway_list",
    "custom_gateway_get",
    "unicast_route_list",
    "unicast_route_get",
    "sdwan_route_list",
    "sdwan_route_get",
    "dhcp_server_list",
    "dhcp_server_get",
    "dhcp_lease_list",
    "dhcp_relay_list",
    "dhcp_relay_get",
    "static_neighbor_list",
    "static_neighbor_get",
}

READ_CASES: list[tuple[str, str, dict[str, Any] | None, dict[str, str], dict[str, Any]]] = [
    # Interfaces
    (
        "network_interface_list",
        INTERFACES,
        {"page": 2, "pageSize": 10, "pageTotal": True, "nameContains": "Port"},
        {"page": "2", "pageSize": "10", "pageTotal": "true", "nameContains": "Port"},
        {"items": [], "pages": PAGE},
    ),
    (
        "network_interface_get",
        f"{INTERFACES}/Port 1",
        {"idOrName": "Port 1"},
        {},
        {"id": "u-1", "name": "Port 1", "type": "physical"},
    ),
    # Zones
    (
        "zone_list",
        "/network/zones",
        {"nameNotEquals": "DMZ"},
        {**DEFAULT_PAGE_QUERY, "nameNotEquals": "DMZ"},
        {"items": [], "pages": PAGE},
    ),
    (
        "zone_get",
        "/network/zones/LAN",
        {"idOrName": "LAN"},
        {},
        {"id": "u-2", "name": "LAN", "type": "lan"},
    ),
    # IPv4 gateways
    (
        "gateway_list",
        "/routing/gateways/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "wan_gateway_list",
        "/routing/gateways/wan/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "wan_gateway_get",
        "/routing/gateways/wan/ipv4/gw-wan1",
        {"idOrName": "gw-wan1"},
        {},
        {"id": "u-3", "name": "gw-wan1"},
    ),
    (
        "custom_gateway_list",
        "/routing/gateways/custom/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "custom_gateway_get",
        "/routing/gateways/custom/ipv4/gw-branch",
        {"idOrName": "gw-branch"},
        {},
        {"id": "u-4", "name": "gw-branch"},
    ),
    # IPv6 gateways
    (
        "gateway_list",
        "/routing/gateways/ipv6",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "wan_gateway_list",
        "/routing/gateways/wan/ipv6",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "wan_gateway_get",
        "/routing/gateways/wan/ipv6/gw-wan2",
        {"idOrName": "gw-wan2"},
        {},
        {"id": "u-5", "name": "gw-wan2"},
    ),
    (
        "custom_gateway_list",
        "/routing/gateways/custom/ipv6",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "custom_gateway_get",
        "/routing/gateways/custom/ipv6/gw-branch6",
        {"idOrName": "gw-branch6"},
        {},
        {"id": "u-6", "name": "gw-branch6"},
    ),
    # Static unicast routes
    (
        "unicast_route_list",
        "/routing/static-unicast-routes/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "unicast_route_get",
        "/routing/static-unicast-routes/ipv4/route1",
        {"idOrName": "route1"},
        {},
        {"name": "route1", "id": "u-7"},
    ),
    (
        "unicast_route_list",
        "/routing/static-unicast-routes/ipv6",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "unicast_route_get",
        "/routing/static-unicast-routes/ipv6/route1v6",
        {"idOrName": "route1v6"},
        {},
        {"name": "route1v6", "id": "u-8"},
    ),
    # SD-WAN routes
    (
        "sdwan_route_list",
        "/sd-wan/routes/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "sdwan_route_get",
        "/sd-wan/routes/ipv4/sdwan1",
        {"idOrName": "sdwan1"},
        {},
        {"id": "u-9", "name": "sdwan1"},
    ),
    (
        "sdwan_route_list",
        "/sd-wan/routes/ipv6",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "sdwan_route_get",
        "/sd-wan/routes/ipv6/sdwan1v6",
        {"idOrName": "sdwan1v6"},
        {},
        {"id": "u-10", "name": "sdwan1v6"},
    ),
    # DHCP servers
    (
        "dhcp_server_list",
        "/network/dhcp/server/servers/ipv4",
        {"nameContains": "lan"},
        {"nameContains": "lan"},
        {"items": []},
    ),
    (
        "dhcp_server_get",
        "/network/dhcp/server/servers/ipv4/dhcp-lan",
        {"idOrName": "dhcp-lan"},
        {},
        {"id": "u-11", "name": "dhcp-lan"},
    ),
    (
        "dhcp_server_list",
        "/network/dhcp/server/servers/ipv6",
        {},
        {},
        {"items": []},
    ),
    (
        "dhcp_server_get",
        "/network/dhcp/server/servers/ipv6/dhcp-lan6",
        {"idOrName": "dhcp-lan6"},
        {},
        {"id": "u-12", "name": "dhcp-lan6"},
    ),
    # DHCP leases (no pagination parameters in the contract)
    (
        "dhcp_lease_list",
        "/network/dhcp/server/leases/ipv4",
        None,
        {},
        {"items": [], "pages": {"size": 50, "maxSize": 100}},
    ),
    (
        "dhcp_lease_list",
        "/network/dhcp/server/leases/ipv6",
        None,
        {},
        {"items": [], "pages": {"size": 50, "maxSize": 100}},
    ),
    # DHCP relays
    (
        "dhcp_relay_list",
        "/network/dhcp/relays/ipv4",
        {},
        {},
        {"items": []},
    ),
    (
        "dhcp_relay_get",
        f"/network/dhcp/relays/ipv4/{RELAY_UUID}",
        {"id": RELAY_UUID},
        {},
        {"id": RELAY_UUID, "name": "relay1"},
    ),
    (
        "dhcp_relay_list",
        "/network/dhcp/relays/ipv6",
        {},
        {},
        {"items": []},
    ),
    (
        "dhcp_relay_get",
        f"/network/dhcp/relays/ipv6/{RELAY_UUID}",
        {"id": RELAY_UUID},
        {},
        {"id": RELAY_UUID, "name": "relay1v6"},
    ),
    # DNS
    ("dns_settings_get", "/network/dns/settings", None, {}, {}),
    (
        "dns_host_entry_list",
        "/network/dns/host-entries",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "dns_host_entry_get",
        "/network/dns/host-entries/host1",
        {"idOrName": "host1"},
        {},
        {"name": "host1", "domain": "example.com", "hostEntries": []},
    ),
    (
        "dns_request_route_list",
        "/network/dns/request-routes",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "dns_request_route_get",
        "/network/dns/request-routes/route1",
        {"idOrName": "route1"},
        {},
        {"name": "route1", "domain": "corp.example", "dnsServers": []},
    ),
    # Static neighbors
    (
        "static_neighbor_list",
        "/network/neighbors/static/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "static_neighbor_get",
        "/network/neighbors/static/ipv4/neighbor1",
        {"idOrName": "neighbor1"},
        {},
        {"id": "u-13", "name": "neighbor1"},
    ),
    (
        "static_neighbor_list",
        "/network/neighbors/static/ipv6",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "static_neighbor_get",
        "/network/neighbors/static/ipv6/neighbor1v6",
        {"idOrName": "neighbor1v6"},
        {},
        {"id": "u-14", "name": "neighbor1v6"},
    ),
]


@pytest.mark.parametrize(
    ("tool", "path", "arguments", "query", "body"),
    READ_CASES,
    ids=[case[0] for case in READ_CASES],
)
async def test_read_operation_contract(
    router: Any,
    tool: str,
    path: str,
    arguments: dict[str, Any] | None,
    query: dict[str, str],
    body: dict[str, Any],
) -> None:
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=body))

    if arguments is None and tool not in MERGED_TOOLS:
        result = await call_tool(tool, {})
    else:
        request_payload = {} if arguments is None else dict(arguments)
        if tool in MERGED_TOOLS:
            request_payload = {
                "ip_family": "ipv6" if "/ipv6" in path else "ipv4",
                **request_payload,
            }
        result = await call_tool(tool, request_payload)

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.path == f"{API_PREFIX}{path}"
    assert dict(request.url.params) == query
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["accept"] == "application/json"
    assert "content-type" not in request.headers
    assert request.content == b""


async def test_a_name_with_a_space_is_percent_encoded_in_the_path(router: Any) -> None:
    route = router.get(f"{BASE}{INTERFACES}/Port 1").mock(
        return_value=httpx.Response(200, json={"name": "Port 1", "type": "physical"})
    )

    result = await call_tool("network_interface_get", {"idOrName": "Port 1"})

    assert result.is_error is False
    assert route.calls.last.request.url.raw_path == (
        b"/api/firewall-config/v1/network/interfaces/network-interfaces/Port%201"
    )


# -- VLAN-only writes: pre-read enforcement --------------------------------------------


def _physical_interface() -> dict[str, Any]:
    return {"id": "u-port1", "name": "Port 1", "type": "physical"}


def _vlan_interface() -> dict[str, Any]:
    return {
        "id": "u-vlan10",
        "name": "vlan10",
        "type": "vlan",
        "vlanDetails": {"vlanId": 10, "parentInterface": {"name": "Port 1"}},
    }


async def test_update_vlan_refuses_a_physical_interface_before_writing(router: Any) -> None:
    get = router.get(f"{BASE}{INTERFACES}/Port 1").mock(
        return_value=httpx.Response(200, json=_physical_interface())
    )
    patch = router.patch(f"{BASE}{INTERFACES}/Port 1").mock(
        return_value=httpx.Response(200, json=_physical_interface())
    )

    result = await call_tool("network_interface_update_vlan", {"idOrName": "Port 1", "mtu": 1500})

    assert result.is_error is True
    assert "only writes interfaces of type 'vlan'" in result.content[0].text
    assert get.call_count == 1
    assert patch.call_count == 0


async def test_update_vlan_proceeds_for_a_vlan_interface(router: Any) -> None:
    router.get(f"{BASE}{INTERFACES}/vlan10").mock(
        return_value=httpx.Response(200, json=_vlan_interface())
    )
    patch = router.patch(f"{BASE}{INTERFACES}/vlan10").mock(
        return_value=httpx.Response(
            200,
            json={
                **_vlan_interface(),
                "mtu": 1500,
                "ipv4": {"assignmentType": "static", "ipv4Address": "10.0.10.1", "cidr": 24},
            },
        )
    )

    result = await call_tool(
        "network_interface_update_vlan",
        {
            "idOrName": "vlan10",
            "mtu": 1500,
            "ipv4": {"assignmentType": "static", "ipv4Address": "10.0.10.1", "cidr": 24},
        },
    )

    assert result.is_error is False
    request = patch.calls.last.request
    assert request.method == "PATCH"
    assert request.headers["content-type"] == "application/json"
    assert request_body(patch) == {
        "mtu": 1500,
        "ipv4": {"assignmentType": "static", "ipv4Address": "10.0.10.1", "cidr": 24},
    }
    assert result.structured_content["type"] == "vlan"


async def test_delete_vlan_refuses_a_bridge_interface_before_deleting(router: Any) -> None:
    router.get(f"{BASE}{INTERFACES}/br0").mock(
        return_value=httpx.Response(200, json={"name": "br0", "type": "bridge"})
    )
    delete = router.delete(f"{BASE}{INTERFACES}/br0").mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )

    result = await call_tool("network_interface_delete_vlan", {"idOrName": "br0"})

    assert result.is_error is True
    assert "bridge" in result.content[0].text
    assert delete.call_count == 0


async def test_delete_vlan_pre_reads_and_then_deletes(router: Any) -> None:
    get = router.get(f"{BASE}{INTERFACES}/vlan10").mock(
        return_value=httpx.Response(200, json=_vlan_interface())
    )
    delete = router.delete(f"{BASE}{INTERFACES}/vlan10").mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )

    result = await call_tool("network_interface_delete_vlan", {"idOrName": "vlan10"})

    assert result.is_error is False
    assert get.call_count == 1
    assert delete.call_count == 1
    assert delete.calls.last.request.method == "DELETE"
    assert result.structured_content == {"deleted": True}


async def test_create_vlan_pre_reads_the_parent_and_sends_the_vlan_body(router: Any) -> None:
    router.get(f"{BASE}{INTERFACES}/Port 1").mock(
        return_value=httpx.Response(200, json=_physical_interface())
    )
    post = router.post(f"{BASE}{INTERFACES}").mock(
        return_value=httpx.Response(201, json=_vlan_interface())
    )

    result = await call_tool(
        "network_interface_create_vlan",
        {
            "name": "vlan10",
            "vlanId": 10,
            "parentInterface": "Port 1",
            "zone": "LAN",
            "ipv4": {"assignmentType": "static", "ipv4Address": "10.0.10.1", "cidr": 24},
        },
    )

    assert result.is_error is False
    request = post.calls.last.request
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert request_body(post) == {
        "name": "vlan10",
        "type": "vlan",
        "vlanDetails": {"vlanId": 10, "parentInterface": {"name": "Port 1"}},
        "zone": {"name": "LAN"},
        "ipv4": {"assignmentType": "static", "ipv4Address": "10.0.10.1", "cidr": 24},
    }
    assert result.structured_content["type"] == "vlan"


async def test_create_vlan_refuses_a_cellular_parent_before_writing(router: Any) -> None:
    router.get(f"{BASE}{INTERFACES}/wwan0").mock(
        return_value=httpx.Response(200, json={"name": "wwan0", "type": "cellularWan"})
    )
    post = router.post(f"{BASE}{INTERFACES}").mock(
        return_value=httpx.Response(201, json=_vlan_interface())
    )

    result = await call_tool(
        "network_interface_create_vlan",
        {"name": "vlan10", "vlanId": 10, "parentInterface": "wwan0"},
    )

    assert result.is_error is True
    assert "cellularWan" in result.content[0].text
    assert post.call_count == 0


async def test_create_vlan_refuses_a_missing_parent_before_writing(router: Any) -> None:
    router.get(f"{BASE}{INTERFACES}/missing").mock(
        return_value=httpx.Response(404, json={"error": "objectNotFound"})
    )
    post = router.post(f"{BASE}{INTERFACES}").mock(
        return_value=httpx.Response(201, json=_vlan_interface())
    )

    result = await call_tool(
        "network_interface_create_vlan",
        {"name": "vlan10", "vlanId": 10, "parentInterface": "missing"},
    )

    assert result.is_error is True
    assert "does not exist" in result.content[0].text
    assert post.call_count == 0


# -- Pagination, validation and errors -------------------------------------------------


async def test_page_size_above_100_is_rejected_without_a_request(router: Any) -> None:
    route = router.get(f"{BASE}/network/zones").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGE})
    )

    result = await call_tool("zone_list", {"pageSize": 101})

    assert result.is_error is True
    assert route.call_count == 0


async def test_page_zero_is_rejected_without_a_request(router: Any) -> None:
    route = router.get(f"{BASE}/network/zones").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGE})
    )

    result = await call_tool("zone_list", {"page": 0})

    assert result.is_error is True
    assert route.call_count == 0


async def test_not_found_is_a_sanitized_tool_error(router: Any) -> None:
    router.get(f"{BASE}/network/zones/Missing").mock(
        return_value=httpx.Response(
            404, json={"error": "objectNotFound", "message": "internal detail that must not leak"}
        )
    )

    result = await call_tool("zone_get", {"idOrName": "Missing"})

    assert result.is_error is True
    text = result.content[0].text
    assert "does not exist" in text
    assert "internal detail that must not leak" not in text
    assert KEY not in text


async def test_a_non_object_response_is_reported_as_a_tool_error(router: Any) -> None:
    router.get(f"{BASE}/network/zones/LAN").mock(
        return_value=httpx.Response(200, json=["not", "an", "object"])
    )

    result = await call_tool("zone_get", {"idOrName": "LAN"})

    assert result.is_error is True
    assert "non-object body" in result.content[0].text


async def test_a_malformed_interface_payload_is_a_sanitized_tool_error(router: Any) -> None:
    """A 200 body that does not match the output model becomes a sanitized ToolError."""
    router.get(f"{BASE}{INTERFACES}/Port 1").mock(
        return_value=httpx.Response(200, json={"id": "u-1", "name": "Port 1", "type": 123})
    )

    result = await call_tool("network_interface_get", {"idOrName": "Port 1"})

    assert result.is_error is True
    text = result.content[0].text
    assert "does not match the documented schema" in text
    assert "123" not in text
    assert KEY not in text


async def test_a_dhcp_relay_name_is_rejected_before_any_request(router: Any) -> None:
    route = router.get(f"{BASE}/network/dhcp/relays/ipv4/relay1").mock(
        return_value=httpx.Response(200, json={})
    )

    result = await call_tool("dhcp_relay_get", {"id": "relay1"})

    assert result.is_error is True
    assert route.call_count == 0


# -- Discovery and annotations ---------------------------------------------------------


EXPECTED_NETWORK_TOOLS = {case[0] for case in READ_CASES} | {
    "network_interface_create_vlan",
    "network_interface_update_vlan",
    "network_interface_delete_vlan",
}

VLAN_WRITE_TOOLS = {
    "network_interface_create_vlan",
    "network_interface_update_vlan",
    "network_interface_delete_vlan",
}


async def test_the_network_domain_publishes_its_28_tools() -> None:
    tools = await tool_map()

    assert len(EXPECTED_NETWORK_TOOLS) == 28
    assert EXPECTED_NETWORK_TOOLS <= set(tools)
    # The three surfaces of issue #31 are registered by the one domain entry point.
    assert len(tools) == 50


async def test_read_tools_carry_no_write_hints() -> None:
    tools = await tool_map()

    for name in EXPECTED_NETWORK_TOOLS - VLAN_WRITE_TOOLS:
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.read_only_hint is True
        assert annotations.destructive_hint is None
        assert annotations.idempotent_hint is None


async def test_vlan_writes_declare_their_risk_and_idempotence() -> None:
    tools = await tool_map()

    create = tools["network_interface_create_vlan"].annotations
    update = tools["network_interface_update_vlan"].annotations
    delete = tools["network_interface_delete_vlan"].annotations

    assert create is not None and update is not None and delete is not None
    assert create.read_only_hint is False
    assert create.destructive_hint is False
    assert create.idempotent_hint is False
    assert update.read_only_hint is False
    # A JSON Merge Patch overwrites stored values, so the update is destructive.
    assert update.destructive_hint is True
    assert update.idempotent_hint is True
    assert delete.read_only_hint is False
    assert delete.destructive_hint is True
    assert delete.idempotent_hint is True


async def test_every_tool_has_an_actionable_description() -> None:
    tools = await tool_map()

    for name, tool in tools.items():
        assert tool.description, name
        assert len(tool.description) > 45, name
        assert tool.title, name


async def test_read_only_mode_does_not_register_the_vlan_writes() -> None:
    tools = await tool_map(read_only=True)

    assert VLAN_WRITE_TOOLS.isdisjoint(tools)
    assert len(tools) == 47
    assert "network_interface_list" in tools


# -- Model tests -----------------------------------------------------------------------


def test_interface_projection_ignores_unknown_server_fields() -> None:
    from sophos_firewall_mcp.models.network import NetworkInterface

    interface = NetworkInterface.model_validate(
        {
            "id": "u-1",
            "name": "vlan10",
            "type": "vlan",
            "enabled": True,
            "vlanDetails": {"vlanId": 10, "parentInterface": {"name": "Port 1"}},
            "zone": {"name": "LAN"},
            "ipv4": {
                "assignmentType": "static",
                "ipv4Address": "10.0.10.1",
                "cidr": 24,
                "secondaryAddresses": [{"ipv4Address": "10.0.10.2", "cidr": 24}],
            },
            "createdAt": "2026-02-26T07:46:33.000Z",
            "futureField": "ignored",
        }
    )

    assert interface.type == "vlan"
    assert interface.vlanDetails is not None
    assert interface.vlanDetails.vlanId == 10
    assert interface.zone is not None and interface.zone.name == "LAN"
    assert (
        interface.ipv4 is not None
        and interface.ipv4.secondaryAddresses[0].ipv4Address == "10.0.10.2"
    )
    assert interface.createdAt is not None
    assert "futureField" not in interface.model_dump()


def test_sdwan_route_projections_flatten_the_selectors() -> None:
    route = SdwanRoute.model_validate(
        {
            "id": "u-9",
            "name": "sdwan1",
            "linkSelection": {"sdwanProfile": {"name": "profile1"}},
            "inboundInterface": {"any": True},
            "sourceNetworks": {"any": True},
            "destinationNetworks": {"ipv4Addresses": [{"name": "LAN"}]},
            "dscpMarking": "46-Expedited Forwarding(EF)",
        }
    )

    assert route.linkSelection is not None
    assert route.linkSelection.sdwanProfile is not None
    assert route.linkSelection.sdwanProfile.name == "profile1"
    assert route.inboundInterface is not None and route.inboundInterface.any is True
    assert route.destinationNetworks is not None
    assert route.destinationNetworks.ipv4Addresses[0].name == "LAN"
    assert route.dscpMarking == "46-Expedited Forwarding(EF)"


def test_dns_settings_projection_keeps_both_upstream_families() -> None:
    settings = DnsSettings.model_validate(
        {
            "dnsProtection": {"enabled": True, "fallback": False},
            "dnsProtocol": "dnsOverHttps",
            "unencryptedDns": {
                "ipv4": {"upstreamResolutionMethod": "static", "dnsServer1": "9.9.9.9"},
                "ipv6": {"upstreamResolutionMethod": "dhcp"},
            },
            "dnsOverHttps": {
                "dnsServer1": {"url": "https://dns.example/dns-query", "ipv4Address": "9.9.9.9"},
                "fallbackToUnencryptedDns": True,
            },
        }
    )

    assert settings.dnsProtection is not None and settings.dnsProtection.enabled is True
    assert settings.unencryptedDns is not None
    assert settings.unencryptedDns.ipv4 is not None
    assert settings.unencryptedDns.ipv4.dnsServer1 == "9.9.9.9"
    assert settings.dnsOverHttps is not None
    assert settings.dnsOverHttps.dnsServer1 is not None
    assert settings.dnsOverHttps.dnsServer1.url == "https://dns.example/dns-query"


def test_dhcp_lease_keyset_metadata_is_preserved() -> None:
    from sophos_firewall_mcp.models.network import DhcpLeaseIpv4

    page = KeysetPage[DhcpLeaseIpv4].model_validate(
        {
            "items": [
                {
                    "leasedStart": "2026-02-26T07:46:33.000Z",
                    "leasedIp": "10.0.10.50",
                    "macAddress": "aa:bb:cc:dd:ee:ff",
                    "leaseType": "dynamic",
                }
            ],
            "pages": {"fromKey": "k1", "nextKey": "k2", "size": 50, "maxSize": 100},
        }
    )

    assert page.items[0].leasedIp == "10.0.10.50"
    assert page.pages is not None
    assert page.pages.fromKey == "k1"
    assert page.pages.nextKey == "k2"


def test_vlan_ipv4_requires_address_and_cidr_for_a_static_assignment() -> None:
    with pytest.raises(ValueError):
        VlanIpv4Create(assignmentType="static", ipv4Address="10.0.10.1")
    with pytest.raises(ValueError):
        VlanIpv4Create(assignmentType="dhcp", ipv4Address="10.0.10.1", cidr=24)
    assert VlanIpv4Create(assignmentType="dhcp").assignment_type == "dhcp"


def test_vlan_create_input_rejects_an_unknown_field() -> None:
    with pytest.raises(ValueError):
        NetworkInterfaceCreateVlanInput(
            name="vlan10", vlanId=10, parentInterface="Port 1", type="bridge"
        )


def test_vlan_update_input_requires_at_least_one_change() -> None:
    with pytest.raises(ValueError):
        NetworkInterfaceUpdateVlanInput(idOrName="vlan10")


def test_name_or_id_accepts_a_uuid_and_rejects_a_comma() -> None:
    assert ZoneRefInput(idOrName=RELAY_UUID).id_or_name == RELAY_UUID
    with pytest.raises(ValueError):
        ZoneRefInput(idOrName="LAN,DMZ")


def test_dhcp_relay_input_requires_a_uuid() -> None:
    assert DhcpRelayRefInput(id=RELAY_UUID).id == RELAY_UUID
    with pytest.raises(ValueError):
        DhcpRelayRefInput(id="relay1")


def test_network_name_filters_are_mutually_exclusive() -> None:
    """The contract declares ``nameContains`` and ``nameNotEquals`` mutually exclusive."""
    for model in (FilteredPageInput, FilterInput):
        with pytest.raises(ValueError, match="mutually exclusive"):
            model(nameContains="lan", nameNotEquals="wan")
        assert model(nameContains="lan").name_filters() == {"nameContains": "lan"}
        assert model(nameNotEquals="wan").name_filters() == {"nameNotEquals": "wan"}


def test_dhcp_server_projection_keeps_boot_next_server() -> None:
    """``bootNextServer`` is declared by the contract and must not be dropped."""
    server = DhcpServerIpv4.model_validate(
        {
            "id": "u-1",
            "name": "dhcp-lan",
            "enabled": True,
            "bootFile": "pxelinux.0",
            "bootNextServer": {"ipv4Address": "10.0.10.5"},
        }
    )

    assert server.bootFile == "pxelinux.0"
    assert server.bootNextServer is not None
    assert server.bootNextServer.ipv4Address == "10.0.10.5"
    assert server.bootNextServer.fqdn is None

    fqdn = DhcpServerIpv4.model_validate({"bootNextServer": {"fqdn": "boot.example.com"}})
    assert fqdn.bootNextServer is not None
    assert fqdn.bootNextServer.fqdn == "boot.example.com"


def _response_properties(operation_id: str) -> set[str]:
    """The merged 200-response property names of one operation, parsed from the contract."""
    document = yaml.safe_load(SPEC_PATH.read_text())
    for path_item in document["paths"].values():
        for operation in path_item.values():
            if not isinstance(operation, dict) or operation.get("operationId") != operation_id:
                continue
            schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
            properties = dict(schema.get("properties") or {})
            for member in schema.get("allOf") or []:
                properties.update(member.get("properties") or {})
            return set(properties)
    raise AssertionError(f"{operation_id} not found in the contract")


def test_unicast_route_models_match_the_parsed_contract() -> None:
    """``name``/``interface`` are declared by the contract, so the models keep exactly it."""
    assert set(UnicastRouteIpv4.model_fields) == _response_properties("getUnicastRouteIPv4")
    assert set(UnicastRouteIpv6.model_fields) == _response_properties("getUnicastRouteIPv6")


async def test_unpaginated_lists_render_pages_null(router: Any) -> None:
    """M16: the four list operations declare no ``pages``, so the envelope renders null.

    A uniform envelope lets an agent tell "no pagination metadata" from "truncated" and
    keeps a generic pagination loop working across every list tool.
    """
    router.get(f"{BASE}/network/dhcp/relays/ipv4").mock(
        return_value=httpx.Response(200, json={"items": [{"id": RELAY_UUID, "name": "relay1"}]})
    )

    result = await call_tool("dhcp_relay_list", {"ip_family": "ipv4"})

    assert result.is_error is False
    assert set(result.structured_content) == {"items", "pages"}
    assert result.structured_content["pages"] is None
    assert result.structured_content["items"][0]["id"] == RELAY_UUID
    assert result.structured_content["items"][0]["name"] == "relay1"

    tools = await tool_map()
    for name in ("dhcp_relay_list", "dhcp_server_list"):
        schema = tools[name].output_schema
        assert schema is not None
        assert "pages" in schema["properties"], name
        assert schema["properties"]["pages"]["type"] == "null", name
        assert "pages: null" in tools[name].description or "pages is null" in (
            tools[name].description
        ), name


async def test_dhcp_lease_list_documents_the_keyset_ceiling(router: Any) -> None:
    """M15: only the first page is reachable, and the description must say so.

    The contract declares no ``fromKey``/``nextKey`` request parameters, so the tool must
    not invent them; it must instead warn that a non-null ``nextKey`` means the list is
    incomplete.
    """
    router.get(f"{BASE}/network/dhcp/server/leases/ipv4").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [{"leasedIp": "10.0.10.50"}],
                "pages": {
                    "fromKey": "10.0.10.50",
                    "nextKey": "10.0.10.51",
                    "size": 1,
                    "maxSize": 1,
                },
            },
        )
    )

    result = await call_tool("dhcp_lease_list", {"ip_family": "ipv4"})

    assert result.is_error is False
    # The appliance value is preserved, including the non-null nextKey.
    assert result.structured_content["pages"]["nextKey"] == "10.0.10.51"

    tools = await tool_map()
    description = tools["dhcp_lease_list"].description
    assert "Only the first page is reachable" in description
    assert "pages.nextKey" in description
    assert "incomplete" in description
    # No undeclared pagination input is exposed; only the family selector is.
    schema = tools["dhcp_lease_list"].input_schema
    assert set(schema["properties"]) == {"ip_family"}


def test_dhcp_lease_pages_max_size_is_documented_as_the_item_count() -> None:
    """L8: ``maxSize`` is the item count here, not a page-size bound; the value is kept."""
    pages = KeysetPages.model_validate(
        {"fromKey": "10.10.10.3", "nextKey": None, "size": 21, "maxSize": 21}
    )

    assert pages.maxSize == 21
    assert pages.size == 21
    description = KeysetPages.model_json_schema()["properties"]["maxSize"]["description"]
    assert "Not a page-size bound" in description
    assert "item count" in description
    # The keyset semantics of the other members are published too.
    schema = KeysetPages.model_json_schema()["properties"]
    assert "incomplete" in schema["nextKey"]["description"]
    assert "Always null here" in schema["total"]["description"]
    assert "Always null here" in schema["items"]["description"]


# -- Phase-5 polish: default page size, epoch sentinel, DNS host entry, DHCP relay notes --


def test_page_input_defaults_to_ten() -> None:
    """M11: a default list call must stay small enough for a model context."""
    parsed = PageInput()

    assert (parsed.page, parsed.page_size, parsed.page_total) == (1, 10, False)
    description = PageInput.model_json_schema()["properties"]["page_size"]["description"]
    assert "Defaults to 10" in description
    # The bounds are unchanged: this is a default, not a schema break.
    assert PageInput(page_size=100).page_size == 100


def test_every_paginated_list_input_defaults_to_ten() -> None:
    """M11: the default is uniform across every paginated list tool, VPN included."""
    from sophos_firewall_mcp.models.firewall import ListFirewallRulesInput
    from sophos_firewall_mcp.models.nat import NatRuleListInput
    from sophos_firewall_mcp.models.objects import ListQuery
    from sophos_firewall_mcp.models.users import NetworkUserListInput, UserListInput
    from sophos_firewall_mcp.models.vpn import VpnFilteredPageInput, VpnPageInput

    models = (
        PageInput(),
        FilteredPageInput(),
        ListQuery(),
        ListFirewallRulesInput(ip_family="ipv4"),
        NatRuleListInput(ip_family="ipv4"),
        UserListInput(),
        NetworkUserListInput(),
        VpnPageInput(),
        VpnFilteredPageInput(),
    )
    for model in models:
        assert model.page_size == 10, type(model).__name__


def test_epoch_sentinel_is_published_as_null() -> None:
    """L6: the appliance's epoch "never" sentinel is published as null, and only it."""
    interface = NetworkInterface.model_validate(
        {
            "name": "WAN - Port 1",
            "createdAt": "1970-01-01T00:00:00Z",
            "updatedAt": "2026-11-15T10:00:00Z",
        }
    )

    # The parsed value stays available to server-side logic: audit_firewall_rules detects
    # built-in objects from the epoch stamp, so hiding it from the model would disable it.
    assert interface.createdAt == datetime(1970, 1, 1, tzinfo=UTC)
    published = interface.model_dump(mode="json", by_alias=True)
    assert published["createdAt"] is None
    assert published["updatedAt"] == "2026-11-15T10:00:00Z"

    # Only the exact sentinel is mapped: one second later is a real timestamp.
    near = NetworkInterface.model_validate({"name": "x", "createdAt": "1970-01-01T00:00:01Z"})
    assert near.model_dump(mode="json")["createdAt"] == "1970-01-01T00:00:01Z"


async def test_dns_host_entry_projects_the_nested_address(router: Any) -> None:
    """P5-D1: the appliance nests the address under ``hostEntries[].ipv4``/``ipv6``."""
    payload = {
        "id": "c83ed35b-0000-4000-8000-000000000000",
        "name": "mcp-test-dns",
        "domain": "p5d904810.invalid",
        "enableReverseResolution": False,
        "hostEntries": [
            {
                "ipv4": {"ipv4Address": "192.0.2.11"},
                "ttl": 60,
                "weight": 1,
                "publishOnWan": False,
            },
            {
                "ipv6": {"ipv6Interface": {"name": "Port2"}},
                "ttl": 120,
                "weight": 2,
                "publishOnWan": True,
            },
        ],
    }
    router.get(f"{BASE}/network/dns/host-entries/mcp-test-dns").mock(
        return_value=httpx.Response(200, json=payload)
    )

    result = await call_tool("dns_host_entry_get", {"idOrName": "mcp-test-dns"})

    assert result.is_error is False
    entries = result.structured_content["hostEntries"]
    assert entries[0]["ipv4"] == {"ipv4Address": "192.0.2.11", "ipv4Interface": None}
    assert entries[0]["ttl"] == 60
    assert entries[1]["ipv6"] == {"ipv6Address": None, "ipv6Interface": {"name": "Port2"}}
    assert entries[1]["publishOnWan"] is True


async def test_dhcp_relay_get_documents_the_401_and_the_uuid_only_input() -> None:
    """M9/P5-O1/P5-O3: a 401 here does not prove the key is broken; only a UUID is accepted."""
    tools = await tool_map()

    for name in ("dhcp_relay_get", "dhcp_relay_get"):
        description = tools[name].description
        assert "401" in description, name
        assert "real, listed relay" in description, name
        assert "does not by itself mean the API key is invalid" in description, name
        assert "404" in description, name

    ipv4 = tools["dhcp_relay_get"].description
    assert "format uuid" in ipv4
    assert "{idOrName}" in ipv4
    assert "dhcp_relay_list" in ipv4


async def test_dhcp_relay_and_static_neighbor_document_the_logical_interface() -> None:
    """P5-O2: the interface reference is the logical name, not the hardware name."""
    tools = await tool_map()

    relay = tools["dhcp_relay_list"].description
    assert "logical interface name" in relay
    assert "DMZ - Services" in relay
    assert "Port3" in relay
    assert "interfaceDoesNotExist" in relay

    neighbor = tools["static_neighbor_list"].description
    assert "logical interface name" in neighbor
    assert "DMZ - Services" in neighbor
    assert "Port3" in neighbor
    assert "Invalid interface." in neighbor
