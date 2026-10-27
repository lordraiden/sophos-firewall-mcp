"""Tests for empty and non-XML response diagnostics (issue #6).

Both failures used to surface as `ExpatError: no element found: line 1, column 0` -- a parser bug to the
reader, when the actual causes are ordinary appliance configuration (API access disabled, IP not
whitelisted, wrong port, a proxy eating the body). The tests assert the two things that make the error
useful: it names those causes, and it still quotes enough of the body to diagnose without leaking the
account password.
"""

import pytest
import respx
from httpx import Response

from sophos_firewall_mcp.client import SophosFirewallClient, SophosResponseError

API_URL = "https://192.168.1.1:4444/webconsole/APIController"
PASSWORD = "s3cret-Pa55"
VALID_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Response APIVersion="2200.1">'
    "<Login><status>Authentication Successful</status></Login>"
    "<FirewallRule><Name>Allow_LAN_to_WAN</Name></FirewallRule>"
    "</Response>"
)


def _client() -> SophosFirewallClient:
    return SophosFirewallClient(host="192.168.1.1", port=4444, password=PASSWORD)


@pytest.mark.asyncio
@respx.mock
async def test_empty_body_names_the_configuration_causes():
    client = _client()
    respx.post(API_URL).mock(return_value=Response(200, text=""))

    with pytest.raises(SophosResponseError) as excinfo:
        await client.get_tag("FirewallRule")

    assert excinfo.value.code == "EMPTY"
    message = str(excinfo.value)
    # The four things a human has to check, in the order they are usually wrong.
    assert "API access" in message
    assert "Allowed IP Addresses" in message
    assert "reqxml" in message
    assert "4444" in message  # the port actually in use, not the default
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_whitespace_only_body_is_treated_as_empty():
    client = _client()
    respx.post(API_URL).mock(return_value=Response(200, text="   \n\t  "))

    with pytest.raises(SophosResponseError) as excinfo:
        await client.get_tag("FirewallRule")

    assert excinfo.value.code == "EMPTY"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_non_xml_body_is_quoted_but_redacted():
    client = _client()
    respx.post(API_URL).mock(
        return_value=Response(200, text=f"<html>Blocked by proxy for user {PASSWORD}</html")
    )

    with pytest.raises(SophosResponseError) as excinfo:
        await client.get_tag("FirewallRule")

    assert excinfo.value.code == "NOT-XML"
    message = str(excinfo.value)
    assert "Blocked by proxy" in message  # still diagnosable
    assert PASSWORD not in message  # but never a new leak path
    assert "[REDACTED]" in message
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_valid_payload_still_parses():
    """Guard against the diagnostics swallowing the happy path."""
    client = _client()
    respx.post(API_URL).mock(return_value=Response(200, text=VALID_XML))

    result = await client.get_tag("FirewallRule")

    assert result["Name"] == "Allow_LAN_to_WAN"
    await client.close()
