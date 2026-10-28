"""Timeout and transport failures must never reach the caller as an empty message (issue #18).

``str(httpx.ReadTimeout())`` is the empty string, and the MCP layer formats failures as
``Error executing tool <name>: <str(exc)>``. A slow appliance therefore looked exactly like a dead server:
the error text was blank. These tests pin the message, not just the exception type.
"""

import logging
import os

import httpx
import pytest
import respx
from httpx import Response

from sophos_firewall_mcp.client import DEFAULT_TIMEOUT, SophosFirewallClient, SophosResponseError

API_URL = "https://192.168.1.1:4444/webconsole/APIController"


def _client(**kwargs) -> SophosFirewallClient:
    return SophosFirewallClient(host="192.168.1.1", port=4444, **kwargs)


@pytest.mark.asyncio
@respx.mock
async def test_read_timeout_is_reported_with_a_message():
    client = _client()
    respx.post(API_URL).mock(side_effect=httpx.ReadTimeout(""))

    with pytest.raises(SophosResponseError) as excinfo:
        await client.send_request(operation="Get", tag="FirewallRule")

    assert excinfo.value.code == "TIMEOUT"
    message = str(excinfo.value)
    assert message.strip()
    # The reader must learn what to change, not only that something took too long.
    assert "SOPHOS_TIMEOUT" in message
    assert "Get" in message and "FirewallRule" in message
    assert "192.168.1.1:4444" in message
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_connect_error_names_the_endpoint_and_the_knobs():
    client = _client()
    respx.post(API_URL).mock(side_effect=httpx.ConnectError(""))

    with pytest.raises(SophosResponseError) as excinfo:
        await client.send_request(operation="Get", tag="Interface")

    assert excinfo.value.code == "CONNECT"
    message = str(excinfo.value)
    assert "192.168.1.1:4444" in message
    assert "SOPHOS_HOST" in message and "API access" in message
    await client.close()


def test_timeout_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("SOPHOS_TIMEOUT", "5.5")
    assert _client().timeout == 5.5


def test_default_timeout_is_above_the_old_thirty_seconds(monkeypatch):
    """30s was below what a full FirewallRule listing takes; the default must not go back."""
    monkeypatch.delenv("SOPHOS_TIMEOUT", raising=False)
    client = _client()
    assert client.timeout == DEFAULT_TIMEOUT
    assert DEFAULT_TIMEOUT > 30


def test_invalid_timeout_falls_back_instead_of_crashing(monkeypatch, caplog):
    """A typo in an env var must not stop the server from booting."""
    monkeypatch.setenv("SOPHOS_TIMEOUT", "not-a-number")
    with caplog.at_level(logging.WARNING):
        client = _client()
    assert client.timeout == DEFAULT_TIMEOUT
    assert "SOPHOS_TIMEOUT" in caplog.text


def test_explicit_timeout_argument_still_wins(monkeypatch):
    monkeypatch.setenv("SOPHOS_TIMEOUT", "5")
    assert _client(timeout=7).timeout == 7


def test_unset_env_leaves_os_clean(monkeypatch):
    monkeypatch.delenv("SOPHOS_TIMEOUT", raising=False)
    assert os.getenv("SOPHOS_TIMEOUT") is None
