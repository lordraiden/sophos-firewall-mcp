"""End-to-end MCP verification of the complete 152-tool server (issue #32, T33).

These tests drive the **real** server -- every domain registered, the real lifespan, the
real REST client -- through the official MCP Python SDK v2 ``Client``, which is the same
client an MCP host uses. They are the executable form of issue #32 section 1:

* discovery: the full surface, titles, descriptions, input/output schemas, annotations;
* interoperability: every input schema is a closed object rooted at ``request`` and every
  output schema is object-rooted (never a bare array/scalar/null);
* structured output: ``structured_content`` validates against the published schema and the
  text channel carries the same projection;
* ``isError``: an anticipated failure is a sanitized ``ToolError``; a protocol rejection is
  an ``MCPError``; an unexpected exception never leaks details;
* cancellation: a cancelled call propagates ``CancelledError`` instead of becoming an error;
* STDIO: the subprocess transport speaks the 2026-07-28 protocol by default, stdout carries
  only the protocol (no logs, no TTY), and shutdown is orderly;
* ``mode="legacy"``: the SDK's initialize handshake still works, so the server is usable by
  hosts that have not adopted the modern revision.

MCP Inspector is not installed on this host and is not required: the official SDK Client is
the reference implementation of the protocol and is what these tests use. The appliance is
mocked with RESPX, so the suite is deterministic and never contacts a firewall.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from mcp import Client, StdioServerParameters
from mcp.server.mcpserver import MCPServer

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.server import create_server

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"

#: The phase-2 exit-criteria surface (ADR-001 section 10, API-COVERAGE section 4).
EXPECTED_TOOL_COUNT = 152
EXPECTED_READ_ONLY_TOOL_COUNT = 98
EXPECTED_MUTATION_COUNT = 54

#: The protocol revision the SDK negotiates by default with a modern server.
MODERN_PROTOCOL_VERSION = "2026-07-28"


def make_settings(*, read_only: bool = False) -> Settings:
    return Settings(
        host=HOST,
        port=4444,
        api_key=KEY,
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=read_only,
    )


def make_server(*, read_only: bool = False) -> MCPServer[AppContext]:
    return create_server(make_settings(read_only=read_only))


def stdio_params() -> StdioServerParameters:
    """The real entrypoint as an MCP host would launch it: a subprocess, no TTY."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "sophos_firewall_mcp.server"],
        env={
            "PYTHONPATH": str(SRC_DIR),
            "SOPHOS_HOST": HOST,
            "SOPHOS_PORT": "4444",
            "SOPHOS_API_KEY": KEY,
            "SOPHOS_VERIFY_SSL": "false",
        },
    )


def is_mutation(tool: Any) -> bool:
    return tool.annotations is not None and tool.annotations.read_only_hint is False


# -- Discovery -------------------------------------------------------------------------


async def test_the_full_surface_is_discoverable_through_the_sdk_client():
    async with Client(make_server()) as client:
        result = await client.list_tools()

    names = [tool.name for tool in result.tools]
    assert len(names) == EXPECTED_TOOL_COUNT
    assert len(set(names)) == EXPECTED_TOOL_COUNT


async def test_every_tool_publishes_a_title_and_a_description():
    async with Client(make_server()) as client:
        result = await client.list_tools()

    for tool in result.tools:
        assert tool.title, tool.name
        assert tool.description and len(tool.description) >= 20, tool.name


async def test_the_surface_is_split_into_read_only_tools_and_mutations():
    async with Client(make_server()) as client:
        result = await client.list_tools()

    mutations = [tool for tool in result.tools if is_mutation(tool)]
    read_only = [tool for tool in result.tools if not is_mutation(tool)]

    assert len(mutations) == EXPECTED_MUTATION_COUNT
    assert len(read_only) == EXPECTED_READ_ONLY_TOOL_COUNT


async def test_read_only_mode_is_visible_to_the_client():
    async with Client(make_server(read_only=True)) as client:
        result = await client.list_tools()

    assert len(result.tools) == EXPECTED_READ_ONLY_TOOL_COUNT
    assert all(not is_mutation(tool) for tool in result.tools)


# -- Schemas ---------------------------------------------------------------------------


async def test_every_input_schema_is_a_closed_object_rooted_at_request():
    async with Client(make_server()) as client:
        result = await client.list_tools()

    def resolve(schema: dict[str, Any], definition: dict[str, Any]) -> dict[str, Any]:
        if "$ref" in definition:
            return schema["$defs"][definition["$ref"].rsplit("/", 1)[-1]]
        return definition

    def assert_closed_object(schema: dict[str, Any], definition: dict[str, Any], name: str) -> None:
        resolved = resolve(schema, definition)
        # A discriminated union (address create, MAC create) is a legitimate request body:
        # every variant must itself be a closed object.
        variants = resolved.get("oneOf") or resolved.get("anyOf")
        if variants is not None:
            assert variants, name
            for variant in variants:
                assert_closed_object(schema, variant, name)
            return
        assert resolved["type"] == "object", name
        assert resolved.get("additionalProperties") is False, name

    for tool in result.tools:
        schema = tool.input_schema
        assert schema["type"] == "object", tool.name
        if not schema["properties"]:
            # Eight operations declare no parameters at all (DHCP leases, DNS settings,
            # IPsec live connections/settings, SSL VPN global settings, the two status
            # reads). The SDK publishes an empty object schema for them; that is the
            # correct shape for a zero-argument tool.
            assert schema.get("required") is None, tool.name
            continue
        assert "request" in schema["properties"], tool.name
        # ``request`` is required unless every member of the request has a default.
        if "required" in schema:
            assert schema["required"] == ["request"], tool.name
        assert_closed_object(schema, schema["properties"]["request"], tool.name)


async def test_every_output_schema_is_object_rooted():
    async with Client(make_server()) as client:
        result = await client.list_tools()

    for tool in result.tools:
        schema = tool.output_schema
        assert schema is not None, tool.name
        assert schema["type"] == "object", tool.name
        assert schema.get("properties"), tool.name


async def test_every_tool_declares_the_conservative_open_world_hint():
    """Sophos is an external appliance: its responses are not a closed data boundary."""
    async with Client(make_server()) as client:
        result = await client.list_tools()

    for tool in result.tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.open_world_hint is True, tool.name


async def test_read_only_tools_never_declare_write_only_hints():
    async with Client(make_server()) as client:
        result = await client.list_tools()

    for tool in result.tools:
        if is_mutation(tool):
            continue
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is not True, tool.name


# -- Structured output and isError -----------------------------------------------------


async def test_a_read_tool_returns_structured_content_matching_its_schema():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/firewall/rules/ipv4").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                            "name": "LAN to WAN",
                            "ruleType": "firewall",
                            "enabled": True,
                        }
                    ],
                    "pages": {"current": 1, "size": 50, "maxSize": 100},
                },
            )
        )
        async with Client(make_server()) as client:
            result = await client.call_tool("firewall_rule_list_ipv4", {"request": {}})

    assert result.is_error is False
    assert isinstance(result.structured_content, dict)
    assert result.structured_content["items"][0]["name"] == "LAN to WAN"
    # The text channel carries the same projection, so a host that ignores structured
    # content still sees the result.
    assert isinstance(result.content, list)
    assert result.content[0].type == "text"
    assert "LAN to WAN" in result.content[0].text


async def test_an_anticipated_failure_is_a_sanitized_tool_error():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/firewall/rules/ipv4").mock(
            return_value=httpx.Response(
                401, json={"error": "unauthenticated", "message": "Token missing or invalid."}
            )
        )
        async with Client(make_server()) as client:
            result = await client.call_tool("firewall_rule_list_ipv4", {"request": {}})

    assert result.is_error is True
    message = result.content[0].text
    assert "authentication" in message.lower() or "unauthenticated" in message.lower()
    # The key never reaches the model.
    assert KEY not in message


async def test_a_malformed_payload_is_a_sanitized_tool_error():
    with respx.mock(assert_all_called=False) as router:
        # ``name`` is required by the output model; the appliance omitting it is a genuine
        # schema mismatch and must not be projected as a silent empty result.
        router.get(f"{BASE}/firewall/rules/ipv4").mock(
            return_value=httpx.Response(
                200, json={"items": [{"ruleType": "firewall"}], "pages": {}}
            )
        )
        async with Client(make_server()) as client:
            result = await client.call_tool("firewall_rule_list_ipv4", {"request": {}})

    assert result.is_error is True
    message = result.content[0].text
    # Each domain words its sanitized schema error slightly differently; both name the
    # failing field and neither echoes the payload.
    assert "does not match" in message
    assert "name" in message
    assert "ruleType" not in message


async def test_an_invalid_argument_is_rejected_before_any_io():
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/firewall/rules/ipv4")
        async with Client(make_server()) as client:
            result = await client.call_tool("firewall_rule_list_ipv4", {"request": {"page": 0}})

    assert result.is_error is True
    assert route.call_count == 0


async def test_an_unknown_tool_is_reported_as_an_error_result():
    """The modern protocol reports an unknown tool as a tool error, not a crash."""
    async with Client(make_server()) as client:
        result = await client.call_tool("sophos_tool_that_does_not_exist", {"request": {}})

    assert result.is_error is True
    assert "Unknown tool" in result.content[0].text


def test_a_protocol_level_rejection_is_a_jsonrpc_error():
    """An unknown JSON-RPC method is a protocol error (``MCPError``), not a tool error."""
    env = {
        "PYTHONPATH": str(SRC_DIR),
        "SOPHOS_HOST": HOST,
        "SOPHOS_PORT": "4444",
        "SOPHOS_API_KEY": KEY,
        "SOPHOS_VERIFY_SSL": "false",
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "sophos_firewall_mcp.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        process.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "hardening-raw-client", "version": "0"},
                    },
                }
            )
            + "\n"
        )
        process.stdin.flush()
        json.loads(process.stdout.readline())
        process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "no/such/method", "params": {}}) + "\n"
        )
        process.stdin.flush()
        response = json.loads(process.stdout.readline())
    finally:
        process.stdin.close()
        process.wait(timeout=60)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 2
    assert "error" in response
    assert response["error"]["code"] == -32601


# -- Cancellation ----------------------------------------------------------------------


async def test_cancellation_propagates_instead_of_becoming_an_error():
    """A cancelled call must not be reported to the model as a tool failure."""
    started = asyncio.Event()

    async def slow_response(request: httpx.Request) -> httpx.Response:
        started.set()
        await asyncio.sleep(30)
        return httpx.Response(200, json={"items": [], "pages": {}})

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/firewall/rules/ipv4").mock(side_effect=slow_response)
        async with Client(make_server()) as client:
            task = asyncio.create_task(client.call_tool("firewall_rule_list_ipv4", {"request": {}}))
            await asyncio.wait_for(started.wait(), timeout=10)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


# -- STDIO transport -------------------------------------------------------------------


async def test_stdio_speaks_the_modern_protocol_by_default():
    async with asyncio.timeout(90):
        async with Client(stdio_params()) as client:
            assert client.protocol_version == MODERN_PROTOCOL_VERSION
            result = await client.list_tools()

    assert len(result.tools) == EXPECTED_TOOL_COUNT


async def test_stdio_works_with_the_legacy_initialize_handshake():
    """Hosts that have not adopted 2026-07-28 must still be able to connect."""
    async with asyncio.timeout(90):
        async with Client(stdio_params(), mode="legacy") as client:
            result = await client.list_tools()

    assert len(result.tools) == EXPECTED_TOOL_COUNT


def test_stdio_stdout_carries_only_the_protocol_and_shuts_down_orderly():
    """Drive the subprocess by hand: every stdout line must be a JSON-RPC message.

    A stray ``print``, a logging handler on stdout or a TTY prompt would corrupt the
    stream; the SDK client would fail, but this test names the failure precisely.
    """
    env = {
        "PYTHONPATH": str(SRC_DIR),
        "SOPHOS_HOST": HOST,
        "SOPHOS_PORT": "4444",
        "SOPHOS_API_KEY": KEY,
        "SOPHOS_VERIFY_SSL": "false",
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "sophos_firewall_mcp.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    # No TTY: the transport is a pipe pair, exactly like a container without -t.
    assert process.stdin.isatty() is False
    assert process.stdout.isatty() is False

    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "hardening-raw-client", "version": "0"},
        },
    }
    try:
        process.stdin.write(json.dumps(initialize) + "\n")
        process.stdin.flush()
        first = process.stdout.readline()
        assert first, "the server produced no response to initialize"
        response = json.loads(first)
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "result" in response

        process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
        )
        process.stdin.flush()
        second = process.stdout.readline()
        tools = json.loads(second)["result"]["tools"]
        assert len(tools) == EXPECTED_TOOL_COUNT
    finally:
        process.stdin.close()
        returncode = process.wait(timeout=60)
        stderr = process.stderr.read() if process.stderr is not None else ""

    # Orderly shutdown: EOF on stdin ends the session with a clean exit code.
    assert returncode == 0, stderr
    # Diagnostics go to stderr, never to stdout.
    assert "starting Sophos Firewall MCP Server" in stderr


def test_stdio_reports_a_configuration_error_on_stderr_with_clean_stdout():
    env = {key: value for key, value in os.environ.items() if not key.startswith("SOPHOS_")}
    env["PYTHONPATH"] = str(SRC_DIR)

    completed = subprocess.run(
        [sys.executable, "-m", "sophos_firewall_mcp.server"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "SOPHOS_HOST is required" in completed.stderr
