"""Live read-only verification of every read-only tool (issue #32, T34).

One parametrized test per read-only tool: 98 tools across the six domain families. Each
test calls the real tool through the real MCP server against the lab appliance and asserts
the documented envelope (no error, object-rooted structured content). The result of the run
is recorded in ``docs/live-evidence/phase-3-live-matrix.md``.

Safety: the server is built with ``read_only_mode=True`` (see ``conftest.py``), so the 54
mutation tools are not registered at all. No ``POST``, ``PATCH`` or ``DELETE`` can be sent
by this module.

Tools that need an identifier derive it from their list operation: the first object's
``name`` when it is usable as a single URL path segment, otherwise its ``id`` (a UUID).
A tool whose list is empty on this appliance is skipped with an explicit reason, which the
evidence file records as ``SKIP`` rather than as a pass.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from mcp import Client

from .conftest import assert_read_only_surface, live, open_live_client

#: A name is usable as a path segment when it has no separator, fragment or comma.
_PATH_SAFE = re.compile(r"^[^/#,]+$")

#: Every read-only tool the server publishes (98). Kept explicit so a surface change is a
#: deliberate edit here, not a silently skipped test.
LIVE_READ_TOOLS: tuple[str, ...] = (
    # Firewall rules
    "firewall_rule_list_ipv4",
    "firewall_rule_get_ipv4",
    "firewall_rule_list_ipv6",
    "firewall_rule_get_ipv6",
    # NAT rules
    "nat_rule_list_ipv4",
    "nat_rule_get_ipv4",
    "nat_rule_list_ipv6",
    "nat_rule_get_ipv6",
    # Addresses, groups, MAC and country
    "address_list_ipv4",
    "address_get_ipv4",
    "address_list_ipv6",
    "address_get_ipv6",
    "address_list_fqdn",
    "address_get_fqdn",
    "address_group_list_ipv4",
    "address_group_get_ipv4",
    "address_group_list_ipv6",
    "address_group_get_ipv6",
    "address_group_list_fqdn",
    "address_group_get_fqdn",
    "mac_address_list",
    "mac_address_get",
    "country_group_list",
    "country_group_get",
    # Services
    "service_list",
    "service_get",
    "service_group_list",
    "service_group_get",
    # Users and live sessions
    "user_list",
    "network_user_list",
    "network_user_get",
    "live_user_list",
    # Network architecture
    "network_interface_list",
    "network_interface_get",
    "zone_list",
    "zone_get",
    "gateway_list_ipv4",
    "wan_gateway_list_ipv4",
    "wan_gateway_get_ipv4",
    "custom_gateway_list_ipv4",
    "custom_gateway_get_ipv4",
    "gateway_list_ipv6",
    "wan_gateway_list_ipv6",
    "wan_gateway_get_ipv6",
    "custom_gateway_list_ipv6",
    "custom_gateway_get_ipv6",
    "unicast_route_list_ipv4",
    "unicast_route_get_ipv4",
    "unicast_route_list_ipv6",
    "unicast_route_get_ipv6",
    "sdwan_route_list_ipv4",
    "sdwan_route_get_ipv4",
    "sdwan_route_list_ipv6",
    "sdwan_route_get_ipv6",
    "dhcp_server_list_ipv4",
    "dhcp_server_get_ipv4",
    "dhcp_server_list_ipv6",
    "dhcp_server_get_ipv6",
    "dhcp_lease_list_ipv4",
    "dhcp_lease_list_ipv6",
    "dhcp_relay_list_ipv4",
    "dhcp_relay_get_ipv4",
    "dhcp_relay_list_ipv6",
    "dhcp_relay_get_ipv6",
    "dns_settings_get",
    "dns_host_entry_list",
    "dns_host_entry_get",
    "dns_request_route_list",
    "dns_request_route_get",
    "static_neighbor_list_ipv4",
    "static_neighbor_get_ipv4",
    "static_neighbor_list_ipv6",
    "static_neighbor_get_ipv6",
    # IPsec VPN
    "ipsec_profile_list",
    "ipsec_profile_get",
    "ipsec_failover_group_list",
    "ipsec_failover_group_get",
    "ipsec_connection_list_ipv4",
    "ipsec_policy_based_connection_list_ipv4",
    "ipsec_policy_based_connection_get_ipv4",
    "ipsec_route_based_connection_list_ipv4",
    "ipsec_route_based_connection_get_ipv4",
    "ipsec_live_connection_list_ipv4",
    "ipsec_remote_access_settings_get",
    # SSL VPN
    "sslvpn_remote_access_policy_list",
    "sslvpn_remote_access_policy_get",
    "sslvpn_bookmark_group_list",
    "sslvpn_bookmark_group_get",
    "sslvpn_bookmark_list",
    "sslvpn_bookmark_get",
    "sslvpn_clientless_policy_list",
    "sslvpn_clientless_policy_get",
    "sslvpn_global_settings_get",
    # Status
    "network_status_dns_protection",
    "network_status_cellular_wan",
    # Audit composites
    "audit_firewall_rules",
    "explain_connectivity",
    "find_object_usage",
)

#: Get-by-id tool -> (list tool, argument name).
FIRST_OF: dict[str, tuple[str, str]] = {
    "firewall_rule_get_ipv4": ("firewall_rule_list_ipv4", "idOrName"),
    "firewall_rule_get_ipv6": ("firewall_rule_list_ipv6", "idOrName"),
    "nat_rule_get_ipv4": ("nat_rule_list_ipv4", "id_or_name"),
    "nat_rule_get_ipv6": ("nat_rule_list_ipv6", "id_or_name"),
    "address_get_ipv4": ("address_list_ipv4", "id_or_name"),
    "address_get_ipv6": ("address_list_ipv6", "id_or_name"),
    "address_get_fqdn": ("address_list_fqdn", "id_or_name"),
    "address_group_get_ipv4": ("address_group_list_ipv4", "id_or_name"),
    "address_group_get_ipv6": ("address_group_list_ipv6", "id_or_name"),
    "address_group_get_fqdn": ("address_group_list_fqdn", "id_or_name"),
    "mac_address_get": ("mac_address_list", "id_or_name"),
    "country_group_get": ("country_group_list", "id_or_name"),
    "service_get": ("service_list", "id_or_name"),
    "service_group_get": ("service_group_list", "id_or_name"),
    "network_user_get": ("network_user_list", "id_or_name"),
    "network_interface_get": ("network_interface_list", "idOrName"),
    "zone_get": ("zone_list", "idOrName"),
    "wan_gateway_get_ipv4": ("wan_gateway_list_ipv4", "idOrName"),
    "custom_gateway_get_ipv4": ("custom_gateway_list_ipv4", "idOrName"),
    "wan_gateway_get_ipv6": ("wan_gateway_list_ipv6", "idOrName"),
    "custom_gateway_get_ipv6": ("custom_gateway_list_ipv6", "idOrName"),
    "unicast_route_get_ipv4": ("unicast_route_list_ipv4", "idOrName"),
    "unicast_route_get_ipv6": ("unicast_route_list_ipv6", "idOrName"),
    "sdwan_route_get_ipv4": ("sdwan_route_list_ipv4", "idOrName"),
    "sdwan_route_get_ipv6": ("sdwan_route_list_ipv6", "idOrName"),
    "dhcp_server_get_ipv4": ("dhcp_server_list_ipv4", "idOrName"),
    "dhcp_server_get_ipv6": ("dhcp_server_list_ipv6", "idOrName"),
    "dhcp_relay_get_ipv4": ("dhcp_relay_list_ipv4", "id"),
    "dhcp_relay_get_ipv6": ("dhcp_relay_list_ipv6", "id"),
    "dns_host_entry_get": ("dns_host_entry_list", "idOrName"),
    "dns_request_route_get": ("dns_request_route_list", "idOrName"),
    "static_neighbor_get_ipv4": ("static_neighbor_list_ipv4", "idOrName"),
    "static_neighbor_get_ipv6": ("static_neighbor_list_ipv6", "idOrName"),
    "ipsec_profile_get": ("ipsec_profile_list", "idOrName"),
    "ipsec_failover_group_get": ("ipsec_failover_group_list", "idOrName"),
    "ipsec_policy_based_connection_get_ipv4": (
        "ipsec_policy_based_connection_list_ipv4",
        "idOrName",
    ),
    "ipsec_route_based_connection_get_ipv4": (
        "ipsec_route_based_connection_list_ipv4",
        "idOrName",
    ),
    "sslvpn_remote_access_policy_get": ("sslvpn_remote_access_policy_list", "idOrName"),
    "sslvpn_bookmark_group_get": ("sslvpn_bookmark_group_list", "idOrName"),
    "sslvpn_bookmark_get": ("sslvpn_bookmark_list", "idOrName"),
    "sslvpn_clientless_policy_get": ("sslvpn_clientless_policy_list", "idOrName"),
}


def _identifier(item: dict[str, Any]) -> str | None:
    """The first usable identifier of a listed object: its name, else its UUID."""
    name = item.get("name")
    if isinstance(name, str) and _PATH_SAFE.match(name):
        return name
    identifier = item.get("id")
    return identifier if isinstance(identifier, str) else None


async def _first_item(client: Client, list_tool: str) -> dict[str, Any] | None:
    result = await client.call_tool(list_tool, {"request": {}})
    if result.is_error:
        return None
    items = (result.structured_content or {}).get("items") or []
    return items[0] if items else None


async def _build_args(client: Client, tool_name: str) -> dict[str, Any] | None:
    """The arguments for one live call, or ``None`` when the appliance has no target."""
    if tool_name in FIRST_OF:
        list_tool, argument = FIRST_OF[tool_name]
        item = await _first_item(client, list_tool)
        if item is None:
            return None
        identifier = _identifier(item)
        return None if identifier is None else {argument: identifier}

    if tool_name == "audit_firewall_rules":
        return {"max_findings": 5}

    if tool_name == "find_object_usage":
        item = await _first_item(client, "service_list")
        if item is None or not isinstance(item.get("name"), str):
            return None
        return {"object_type": "service", "identifier": item["name"]}

    if tool_name == "explain_connectivity":
        zones = await client.call_tool("zone_list", {"request": {}})
        names = [
            zone["name"]
            for zone in (zones.structured_content or {}).get("items") or []
            if isinstance(zone.get("name"), str)
        ]
        if len(names) < 2:
            return None
        return {
            "source": {"zone": names[0]},
            "destination": {"zone": names[1]},
            "service": {"protocol": "tcp", "port": 443},
        }

    return {}


@pytest.mark.live
@live
async def test_the_live_surface_is_exactly_the_read_only_surface() -> None:
    """The hardcoded list above must match what the read-only server publishes."""
    async with open_live_client() as client:
        await assert_read_only_surface(client)
        published = {tool.name for tool in (await client.list_tools()).tools}

    assert published == set(LIVE_READ_TOOLS)
    assert len(LIVE_READ_TOOLS) == len(set(LIVE_READ_TOOLS)) == 98


@pytest.mark.live
@live
@pytest.mark.parametrize("tool_name", LIVE_READ_TOOLS)
async def test_live_read_tool(tool_name: str) -> None:
    """Call one read-only tool against the appliance and assert the documented envelope."""
    async with open_live_client() as client:
        await assert_read_only_surface(client)
        args = await _build_args(client, tool_name)
        if args is None:
            pytest.skip(f"{tool_name}: the appliance holds no object this tool can read")

        result = await client.call_tool(tool_name, {"request": args})

    assert result.is_error is False, result.content[0].text
    assert isinstance(result.structured_content, dict), tool_name
    # Every output is object-rooted: never a bare array, scalar or null.
    assert result.structured_content, tool_name


@pytest.mark.live
@live
async def test_live_pagination_metadata_is_preserved() -> None:
    """``pageTotal=true`` adds ``pages.total``/``pages.items`` (phase-1 observation)."""
    async with open_live_client() as client:
        await assert_read_only_surface(client)
        result = await client.call_tool(
            "firewall_rule_list_ipv4",
            {"request": {"page": 1, "pageSize": 10, "pageTotal": True}},
        )

    assert result.is_error is False
    pages = result.structured_content["pages"]
    assert pages["current"] == 1
    assert pages["size"] == 10
    assert pages["maxSize"] == 100
    assert pages["total"] is not None
    assert pages["items"] is not None
