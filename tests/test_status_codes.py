"""Tests for SFOS status-code classification (issue #7).

The previous logic read the message text and exempted 500, so:
  * a 500 ("Operation could not be performed on Entity") was reported as SUCCESS,
  * a 203 ("successful but few configurations could not be applied") was indistinguishable from a clean 200,
  * a 526 ("Record does not exist") was an error even for a Get, where absence is a normal answer.

These tests pin the documented table instead of the prose.
"""

import pytest
import respx
from httpx import Response

from sophos_firewall_mcp.client import (
    SophosFirewallClient,
    SophosPartialResultError,
    SophosResponseError,
    _classify_status,
)

API_URL = "https://192.168.1.1:4444/webconsole/APIController"


def _client() -> SophosFirewallClient:
    return SophosFirewallClient(host="192.168.1.1", port=4444)


def _xml_with_status(code: str, text: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Response APIVersion="2200.1">'
        "<Login><status>Authentication Successful</status></Login>"
        f'<Status code="{code}">{text}</Status>'
        "</Response>"
    )


@pytest.mark.parametrize(
    "code,expected",
    [
        ("200", "ok"),
        ("216", "ok"),
        ("201", "warning"),
        ("203", "warning"),
        ("211", "warning"),
        ("215", "warning"),
        ("204", "error"),
        ("500", "error"),
        ("501", "error"),
        ("526", "error"),
        ("529", "error"),
        ("599", "error"),
        ("590", "error"),
        ("999", "error"),
    ],
)
def test_documented_codes_are_classified(code, expected):
    assert _classify_status(code) == expected


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("code", ["500", "501", "502", "599"])
async def test_failure_codes_raise(code):
    client = _client()
    respx.post(API_URL).mock(return_value=Response(200, text=_xml_with_status(code, "failure")))

    with pytest.raises(SophosResponseError) as excinfo:
        await client.send_request(operation="Set", tag="FirewallRule")
    assert excinfo.value.code == code
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_500_is_not_success_any_more():
    """The exact regression: 500 used to be exempt, so a failed operation looked applied."""
    client = _client()
    respx.post(API_URL).mock(
        return_value=Response(200, text=_xml_with_status("500", "Operation could not be performed"))
    )

    with pytest.raises(SophosResponseError) as excinfo:
        await client.send_request(operation="Set", tag="FirewallRule")
    assert excinfo.value.code == "500"
    assert "could not be performed" in str(excinfo.value)
    await client.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("code", ["201", "203", "211"])
async def test_partial_results_raise_their_own_error(code):
    client = _client()
    respx.post(API_URL).mock(
        return_value=Response(200, text=_xml_with_status(code, "Operation partially applied"))
    )

    with pytest.raises(SophosPartialResultError) as excinfo:
        await client.send_request(operation="Set", tag="FirewallRule")
    # Must still be catchable as a generic response error.
    assert isinstance(excinfo.value, SophosResponseError)
    assert excinfo.value.code == code
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_partial_message_carries_the_official_description():
    client = _client()
    respx.post(API_URL).mock(
        return_value=Response(200, text=_xml_with_status("203", "few configurations could not be applied"))
    )

    with pytest.raises(SophosPartialResultError) as excinfo:
        await client.send_request(operation="Set", tag="FirewallRule")
    message = str(excinfo.value).lower()
    assert "partially" in message or "could not be applied" in message
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_missing_record_on_get_returns_no_rows():
    """526 on a Get is an answer, not a failure."""
    client = _client()
    respx.post(API_URL).mock(
        return_value=Response(200, text=_xml_with_status("526", "Record does not exist"))
    )

    result = await client.send_request(operation="Get", tag="FirewallRule")

    assert result == {}
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_missing_record_on_set_is_still_an_error():
    """Updating something that does not exist is a failure, not an empty answer."""
    client = _client()
    respx.post(API_URL).mock(
        return_value=Response(200, text=_xml_with_status("526", "Record does not exist"))
    )

    with pytest.raises(SophosResponseError) as excinfo:
        await client.send_request(operation="Set", tag="FirewallRule")
    assert excinfo.value.code == "526"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_clean_200_still_passes():
    client = _client()
    respx.post(API_URL).mock(
        return_value=Response(
            200,
            text=(
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<Response APIVersion="2200.1">'
                "<Login><status>Authentication Successful</status></Login>"
                '<Status code="200">Configuration applied successfully.</Status>'
                "</Response>"
            ),
        )
    )

    result = await client.send_request(operation="Set", tag="FirewallRule")

    assert isinstance(result, dict)
    await client.close()
