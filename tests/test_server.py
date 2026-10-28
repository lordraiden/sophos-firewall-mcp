"""Unit tests for MCP server initialization, tool count and registration.

Reads the tool list through the public ``list_tools()`` coroutine instead of FastMCP 1.x internals
(``mcp._tool_manager._tools``), so an SDK bump cannot break the test instead of the server.
"""

import pytest
from sophos_firewall_mcp.server import call_routed_tool, mcp, route_tools


@pytest.mark.asyncio
async def test_server_tool_registration():
    registered = await mcp.list_tools()
    tools = [tool.name for tool in registered]

    # Assert key tools are registered
    assert "sophos_raw_api_request" in tools
    assert "sophos_get_system_info" in tools
    assert "sophos_get_interface_list" in tools
    assert "sophos_list_firewall_rules" in tools
    assert "sophos_create_firewall_rule" in tools
    assert "sophos_update_firewall_rule" in tools
    assert "sophos_list_ip_hosts" in tools
    assert "sophos_create_ip_host" in tools
    assert "sophos_delete_ip_host_group" in tools
    assert "sophos_delete_fqdn_host" in tools
    assert "sophos_list_services" in tools
    assert "sophos_delete_service" in tools
    assert "sophos_create_service_group" in tools
    assert "sophos_delete_service_group" in tools
    assert "sophos_list_nat_rules" in tools
    assert "sophos_create_nat_rule" in tools
    assert "sophos_update_nat_rule" in tools
    assert "sophos_delete_nat_rule" in tools
    assert "sophos_list_users" in tools
    assert "sophos_delete_user" in tools
    assert "sophos_list_ipsec_vpns" in tools

    raw_tool = next(tool for tool in registered if tool.name == "sophos_raw_api_request")
    # Assert on the wire format, not on the Python attribute: mcp 2.x renamed the attribute to
    # ``destructive_hint`` but still serialises as ``destructiveHint``, which is what an MCP client
    # actually receives. Checking the attribute would pin an implementation detail and break on the
    # next SDK bump while the behaviour stayed correct.
    assert raw_tool.annotations is not None
    wire = raw_tool.annotations.model_dump(by_alias=True, exclude_none=True)
    assert wire["destructiveHint"] is True


@pytest.mark.asyncio
async def test_route_tools_disabled():
    res = await route_tools("show system status")
    assert "Tool routing is not enabled" in res


@pytest.mark.asyncio
async def test_call_routed_tool_disabled():
    res = await call_routed_tool("sophos_get_system_info")
    assert "Tool routing is not enabled" in res
