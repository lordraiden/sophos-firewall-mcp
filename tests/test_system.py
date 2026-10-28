"""Unit tests for system tools."""

import pytest
from sophos_firewall_mcp.client import SophosResponseError
from sophos_firewall_mcp.tools.system import (
    sophos_get_interface_list,
    sophos_get_service_status,
    sophos_get_system_info,
)


@pytest.mark.asyncio
async def test_sophos_get_system_info(mock_client):
    mock_client.send_request.return_value = {
        "SystemInformation": {
            "Model": "XGS2100",
            "Version": "19.5.3",
        }
    }
    res = await sophos_get_system_info(client=mock_client)
    assert res["Model"] == "XGS2100"
    mock_client.send_request.assert_called_once_with("Get", "SystemInformation", None)


@pytest.mark.asyncio
async def test_sophos_get_system_info_unsupported_module(mock_client):
    mock_client.send_request.side_effect = SophosResponseError(code="529", message="Input request module is Invalid")
    res = await sophos_get_system_info(client=mock_client)
    assert res["Status"] == "Unsupported XML Module"
    assert "SystemInformation" in res["Message"]


@pytest.mark.asyncio
async def test_sophos_get_service_status(mock_client):
    mock_client.send_request.return_value = {
        "SystemServices": {"IPS": {"Action": "Start", "Status": "RUNNING"}}
    }
    res = await sophos_get_service_status(client=mock_client)
    assert res["IPS"]["Status"] == "RUNNING"
    mock_client.send_request.assert_called_once_with("Get", "SystemServices", None)


@pytest.mark.asyncio
async def test_sophos_get_interface_list(mock_client):
    mock_client.send_request.return_value = {
        "Interface": {"Name": "Port1", "Zone": "LAN"}
    }
    res = await sophos_get_interface_list(client=mock_client)
    assert res["Name"] == "Port1"
    mock_client.send_request.assert_called_once_with("Get", "Interface", None)


def test_system_info_description_does_not_promise_what_sfos_cannot_give():
    """The docstring is the tool description an agent reads before calling (issue #2).

    It used to promise "appliance model, firmware version, serial number, and uptime" -- none of which
    the XML API exposes. A description that oversells is worse than a terse one: the model calls the
    tool expecting a serial number and gets a message to interpret.
    """
    doc = (sophos_get_system_info.__doc__ or "").lower()

    assert "cannot return" in doc
    for unavailable in ("model", "serial number", "firmware version", "uptime"):
        assert unavailable in doc
    # The way out has to be in the description too, not only in the runtime message.
    assert "snmp" in doc
    assert "adminsettings" in doc
