"""Regression tests for the two live contract deviations found on the lab appliance.

The checked-in OpenAPI document is the implementation contract, but the lab appliance
(15 November 2026, read-only GETs) returns two payloads the contract does not describe:

1. ``GET /network/addresses/ipv4`` and ``GET /network/addresses/ipv6`` return the built-in
   internal objects ``##ALL_RW``, ``##ALL_IPSEC_RW``, ``##ALL_SSLVPN_RW`` (and their IPv6
   equivalents) with ``"ipv4Addresses": []`` / ``"ipv6Addresses": []``, while the contract
   declares those arrays with ``minItems: 1``.
2. ``GET /network/dns/settings`` returns ``"updatedAt": ""`` (an empty string) where the
   contract declares ``format: date-time``.

Both deviations are recorded in ``docs/live-evidence/phase-3-live-matrix.md``. The fix is
deliberately narrow (Lead-approved, 15 Nov 2026):

* the *output* list models accept an empty array, so one built-in object cannot make the
  whole page unreadable;
* the *input* create/update models keep ``min_length=1``: creating an empty list is still
  invalid;
* ``DnsSettings.updatedAt`` maps only the empty string to ``None``; any other non-date-time
  value still fails, so a genuine schema mismatch is never turned into a silent result.

The tool-level tests prove the relaxation reaches the model through the real MCP surface
and that a genuinely malformed payload still produces the sanitized ``ToolError``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx
import pytest
import respx
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.models.network import DnsSettings
from sophos_firewall_mcp.models.objects import (
    Ipv4AddressCreateIpList,
    Ipv4AddressIpList,
    Ipv6AddressCreateIpList,
    Ipv6AddressIpList,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.hosts_objects import register_objects_tools
from sophos_firewall_mcp.tools.network import register_network_tools

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
IPV4_PATH = "/network/addresses/ipv4"
IPV6_PATH = "/network/addresses/ipv6"
DNS_SETTINGS_PATH = "/network/dns/settings"

#: The exact shape the appliance returns for a built-in internal object.
EMPTY_IPV4_LIST = {
    "id": "c68a5d1c-35e3-4eed-b898-3845cc2c1a33",
    "name": "##ALL_RW",
    "description": "",
    "type": "ipv4List",
    "ipv4Addresses": [],
    "createdAt": "1970-01-01T00:00:00.000Z",
    "updatedAt": "1970-01-01T00:00:00.000Z",
}
EMPTY_IPV6_LIST = {
    "id": "9294b4f7-d820-4b96-ba4a-f0b495a0bbd9",
    "name": "##ALL_RW6",
    "description": "",
    "type": "ipv6List",
    "ipv6Addresses": [],
    "createdAt": "1970-01-01T00:00:00.000Z",
    "updatedAt": "1970-01-01T00:00:00.000Z",
}
#: The exact shape the appliance returns for ``GET /network/dns/settings``.
DNS_SETTINGS_EMPTY_TIMESTAMP = {
    "dnsProtection": {"enabled": False, "fallback": False},
    "dnsSecProtection": False,
    "dnsProtocol": "unencryptedDns",
    "unencryptedDns": {
        "ipv4": {
            "upstreamResolutionMethod": "static",
            "dnsServer1": "10.10.30.2",
            "dnsServer2": "10.10.20.2",
            "dnsServer3": "",
        },
        "ipv6": {
            "upstreamResolutionMethod": "static",
            "dnsServer1": "",
            "dnsServer2": "",
            "dnsServer3": "",
        },
    },
    "updatedAt": "",
}


def make_settings(read_only: bool = False) -> Settings:
    return Settings(
        host=HOST,
        port=4444,
        api_key=KEY,
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=read_only,
    )


def make_server(read_only: bool = False) -> MCPServer[AppContext]:
    return create_server(
        make_settings(read_only),
        domains=[register_objects_tools, register_network_tools],
    )


@asynccontextmanager
async def open_client(read_only: bool = False) -> AsyncIterator[Client]:
    async with Client(make_server(read_only)) as client:
        yield client


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


# -- Deviation 1: empty address lists on the built-in internal objects ----------------


def test_ipv4_address_list_output_accepts_the_appliance_empty_list():
    """The output model must accept ``ipv4Addresses: []`` (contract says ``minItems: 1``)."""
    address = Ipv4AddressIpList.model_validate(EMPTY_IPV4_LIST)

    assert address.type == "ipv4List"
    assert address.name == "##ALL_RW"
    assert address.ipv4_addresses == []


def test_ipv4_address_create_input_still_rejects_an_empty_list():
    """Creating an empty list stays invalid: only the output model was relaxed."""
    with pytest.raises(ValidationError):
        Ipv4AddressCreateIpList.model_validate(
            {"name": "empty", "type": "ipv4List", "ipv4Addresses": []}
        )


def test_ipv6_address_list_output_accepts_the_appliance_empty_list():
    """The IPv6 output model must accept ``ipv6Addresses: []`` for the same reason."""
    address = Ipv6AddressIpList.model_validate(EMPTY_IPV6_LIST)

    assert address.type == "ipv6List"
    assert address.name == "##ALL_RW6"
    assert address.ipv6_addresses == []


def test_ipv6_address_create_input_still_rejects_an_empty_list():
    with pytest.raises(ValidationError):
        Ipv6AddressCreateIpList.model_validate(
            {"name": "empty", "type": "ipv6List", "ipv6Addresses": []}
        )


async def test_address_list_ipv4_projects_a_page_with_an_empty_builtin_list(router: Any):
    """The real tool must return the page instead of failing on the built-in object."""
    router.get(f"{BASE}{IPV4_PATH}").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    EMPTY_IPV4_LIST,
                    {
                        "id": "80e459a9-3d2e-492a-8b13-3778e4d2d1a8",
                        "name": "DNS - Google DNS",
                        "description": "",
                        "type": "ipv4List",
                        "ipv4Addresses": ["8.8.8.8", "8.8.4.4"],
                    },
                ],
                "pages": {"current": 1, "size": 50, "maxSize": 100, "total": 2, "items": 2},
            },
        )
    )

    async with open_client() as client:
        result = await client.call_tool("address_list_ipv4", {"request": {}})

    assert result.is_error is False
    items = result.structured_content["items"]
    assert [item["name"] for item in items] == ["##ALL_RW", "DNS - Google DNS"]
    assert items[0]["ipv4Addresses"] == []
    assert items[1]["ipv4Addresses"] == ["8.8.8.8", "8.8.4.4"]


async def test_address_list_ipv4_still_rejects_a_genuinely_malformed_payload(router: Any):
    """The relaxation must not turn a real schema mismatch into a silent empty result."""
    router.get(f"{BASE}{IPV4_PATH}").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": "80e459a9-3d2e-492a-8b13-3778e4d2d1a8",
                        "name": "broken",
                        "type": "ipv4List",
                        "ipv4Addresses": "not-a-list",
                    }
                ],
                "pages": {"current": 1, "size": 50, "maxSize": 100},
            },
        )
    )

    async with open_client() as client:
        result = await client.call_tool("address_list_ipv4", {"request": {}})

    assert result.is_error is True
    message = result.content[0].text
    assert "does not match the documented schema" in message
    assert "not-a-list" not in message


# -- Deviation 2: empty-string timestamp on the DNS settings --------------------------


def test_dns_settings_maps_the_appliance_empty_timestamp_to_none():
    """``updatedAt: ""`` is the appliance's way of saying "no timestamp"."""
    settings = DnsSettings.model_validate(DNS_SETTINGS_EMPTY_TIMESTAMP)

    assert settings.updatedAt is None
    assert settings.dnsProtocol == "unencryptedDns"
    assert settings.unencryptedDns is not None
    assert settings.unencryptedDns.ipv4 is not None
    assert settings.unencryptedDns.ipv4.dnsServer1 == "10.10.30.2"


def test_dns_settings_still_rejects_a_malformed_timestamp():
    """Only the empty string is tolerated; a real malformed value still fails."""
    with pytest.raises(ValidationError):
        DnsSettings.model_validate({"updatedAt": "not-a-date-time"})


async def test_dns_settings_get_projects_the_appliance_empty_timestamp(router: Any):
    router.get(f"{BASE}{DNS_SETTINGS_PATH}").mock(
        return_value=httpx.Response(200, json=DNS_SETTINGS_EMPTY_TIMESTAMP)
    )

    async with open_client() as client:
        result = await client.call_tool("dns_settings_get", {"request": {}})

    assert result.is_error is False
    assert result.structured_content["updatedAt"] is None
    assert result.structured_content["dnsProtocol"] == "unencryptedDns"


async def test_dns_settings_get_still_rejects_a_genuinely_malformed_payload(router: Any):
    router.get(f"{BASE}{DNS_SETTINGS_PATH}").mock(
        return_value=httpx.Response(200, json={"updatedAt": "not-a-date-time"})
    )

    async with open_client() as client:
        result = await client.call_tool("dns_settings_get", {"request": {}})

    assert result.is_error is True
    assert "does not match the documented schema" in result.content[0].text
