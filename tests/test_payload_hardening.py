"""Tests for response hardening: nested API errors and credential scrubbing."""

import pytest
import respx
from httpx import Response

from sophos_firewall_mcp.client import SophosFirewallClient, SophosResponseError

API_URL = "https://192.168.1.1:4444/webconsole/APIController"

# SFOS echoes the rejected tag and nests the error inside it, so a top-level
# <Status> check alone never sees it.
NESTED_529_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <SystemInformation>
        <Status code="529">Input request module is Invalid</Status>
    </SystemInformation>
</Response>
"""

# Per-record Status fields are plain strings, not error payloads.
RECORDS_WITH_STRING_STATUS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <FirewallRule>
        <Name>Allow_LAN_to_WAN</Name>
        <Status>Enable</Status>
    </FirewallRule>
    <FirewallRule>
        <Name>Block_All</Name>
        <Status>Disable</Status>
    </FirewallRule>
</Response>
"""

INTERFACE_WITH_CREDENTIALS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <Interface>
        <Name>WAN</Name>
        <IPAddress>203.0.113.5</IPAddress>
        <Username>ppp@isp.example</Username>
        <Password passwordform="encrypt">85E26018A7AE</Password>
    </Interface>
</Response>
"""

USER_WITH_USERNAME_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <User>
        <Username>jdoe</Username>
        <Name>John Doe</Name>
    </User>
</Response>
"""


def _client() -> SophosFirewallClient:
    return SophosFirewallClient(host="192.168.1.1", port=4444)


@pytest.mark.asyncio
@respx.mock
async def test_nested_status_error_raises():
    client = _client()
    respx.post(API_URL).mock(return_value=Response(200, text=NESTED_529_XML))

    with pytest.raises(SophosResponseError) as excinfo:
        await client.get_tag("SystemInformation")

    assert excinfo.value.code == "529"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_record_status_strings_are_not_errors():
    client = _client()
    respx.post(API_URL).mock(return_value=Response(200, text=RECORDS_WITH_STRING_STATUS_XML))

    res = await client.get_tag("FirewallRule")

    assert [rule["Status"] for rule in res] == ["Enable", "Disable"]
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_interface_credentials_are_scrubbed():
    client = _client()
    respx.post(API_URL).mock(return_value=Response(200, text=INTERFACE_WITH_CREDENTIALS_XML))

    res = await client.get_tag("Interface")

    assert res["Name"] == "WAN"
    assert res["IPAddress"] == "203.0.113.5"
    assert "Username" not in res
    assert "Password" not in res
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_user_username_is_preserved():
    client = _client()
    respx.post(API_URL).mock(return_value=Response(200, text=USER_WITH_USERNAME_XML))

    res = await client.get_tag("User")

    assert res["Username"] == "jdoe"
    await client.close()
