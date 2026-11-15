"""Contract tests for the two read-only network status tools (issue #31, ``tools/system.py``).

The contract exposes exactly two status operations. These tests prove that only those two are
registered -- in particular that no generic "firewall health" tool exists -- and that the
projections claim only the fields the API actually returns.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from mcp import Client

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.models.network import CellularWanStatus, DnsProtectionStatus
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.system import register_status_tools

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
API_PREFIX = "/api/firewall-config/v1"

DNS_STATUS = "/network/dns/protection/status"
CELLULAR_STATUS = "/network/cellular-wan/modem-status"

EXPECTED_TOOLS = {"network_status_dns_protection", "network_status_cellular_wan"}


def make_settings(**overrides: Any) -> Settings:
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
    return create_server(make_settings(**overrides), domains=[register_status_tools])


async def call_tool(name: str, arguments: dict[str, Any], *, read_only: bool = False) -> Any:
    server = make_server(read_only_mode=read_only)
    async with Client(server) as client:
        return await client.call_tool(name, arguments)


async def tool_map(*, read_only: bool = False) -> dict[str, Any]:
    server = make_server(read_only_mode=read_only)
    return {tool.name: tool for tool in await server.list_tools()}


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


# -- Contract tests --------------------------------------------------------------------

READ_CASES: list[tuple[str, str, dict[str, Any]]] = [
    (
        "network_status_dns_protection",
        DNS_STATUS,
        {"status": "active", "updatedAt": "2026-02-26T07:46:33.000Z"},
    ),
    (
        "network_status_cellular_wan",
        CELLULAR_STATUS,
        {
            "noOfModemsDetected": 1,
            "modem": {
                "model": "MC7455",
                "status": {"connection": "connected", "sim": "ready"},
                "signal": {"rssi": "-65", "rsrp": "-95"},
                "airplaneMode": "disabled",
                "cellularNetwork": {
                    "mode": "automatic",
                    "dataRoaming": "disabled",
                    "registered": True,
                    "type": "4G(LTE)",
                    "operator": "Example Mobile",
                },
                "uploadKbps": 50000,
                "downloadKbps": 150000,
                "connectionDuration": "01:20:00",
            },
        },
    ),
]


@pytest.mark.parametrize(("tool", "path", "body"), READ_CASES, ids=[case[0] for case in READ_CASES])
async def test_status_operation_contract(
    router: Any, tool: str, path: str, body: dict[str, Any]
) -> None:
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=body))

    result = await call_tool(tool, {})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.path == f"{API_PREFIX}{path}"
    assert dict(request.url.params) == {}
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["accept"] == "application/json"
    assert "content-type" not in request.headers
    assert request.content == b""


async def test_dns_protection_status_projects_the_state(router: Any) -> None:
    router.get(f"{BASE}{DNS_STATUS}").mock(
        return_value=httpx.Response(
            200, json={"status": "notSubscribed", "updatedAt": "2026-02-26T07:46:33.000Z"}
        )
    )

    result = await call_tool("network_status_dns_protection", {})

    assert result.is_error is False
    assert result.structured_content["status"] == "notSubscribed"
    assert result.structured_content["updatedAt"].startswith("2026-02-26")


async def test_cellular_status_projects_modem_details(router: Any) -> None:
    body = READ_CASES[1][2]
    router.get(f"{BASE}{CELLULAR_STATUS}").mock(return_value=httpx.Response(200, json=body))

    result = await call_tool("network_status_cellular_wan", {})

    assert result.is_error is False
    status = CellularWanStatus.model_validate(result.structured_content)
    assert status.noOfModemsDetected == 1
    assert status.modem is not None
    assert status.modem.status is not None
    assert status.modem.status.connection == "connected"
    assert status.modem.cellularNetwork is not None
    assert status.modem.cellularNetwork.type == "4G(LTE)"
    assert status.modem.downloadKbps == 150000


async def test_a_failure_is_a_sanitized_tool_error(router: Any) -> None:
    router.get(f"{BASE}{DNS_STATUS}").mock(
        return_value=httpx.Response(500, json={"error": "internal", "message": "raw detail"})
    )

    result = await call_tool("network_status_dns_protection", {})

    assert result.is_error is True
    text = result.content[0].text
    assert "unexpected error" in text
    assert "raw detail" not in text
    assert KEY not in text


# -- Discovery and annotations ---------------------------------------------------------


async def test_only_the_two_status_endpoints_are_registered() -> None:
    tools = await tool_map()

    assert set(tools) == EXPECTED_TOOLS


async def test_no_generic_firewall_health_tool_exists() -> None:
    tools = await tool_map()

    for name in tools:
        assert "health" not in name
        assert "system" not in name
    # Accepted regression: the contract has no endpoint for model, serial, firmware or uptime.
    for forbidden in ("firmware", "serial", "uptime", "model", "service"):
        assert not any(forbidden in name for name in tools), forbidden


async def test_status_tools_are_reads_with_no_write_hints() -> None:
    tools = await tool_map()

    for name, tool in tools.items():
        assert tool.annotations is not None, name
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.destructive_hint is None, name
        assert tool.annotations.idempotent_hint is None, name


async def test_read_only_mode_registers_both_status_tools() -> None:
    assert set(await tool_map(read_only=True)) == EXPECTED_TOOLS


# -- Model tests -----------------------------------------------------------------------


def test_dns_protection_status_requires_a_status() -> None:
    with pytest.raises(ValueError):
        DnsProtectionStatus.model_validate({"updatedAt": "2026-02-26T07:46:33.000Z"})
    with pytest.raises(ValueError):
        DnsProtectionStatus.model_validate({"status": "unknown-state"})


def test_cellular_status_requires_the_modem_count_and_ignores_unknown_fields() -> None:
    with pytest.raises(ValueError):
        CellularWanStatus.model_validate({"modem": {"model": "MC7455"}})

    status = CellularWanStatus.model_validate({"noOfModemsDetected": 0, "futureField": "ignored"})
    assert status.noOfModemsDetected == 0
    assert status.modem is None
    assert "futureField" not in status.model_dump()
