"""End-to-end MCP verification of the complete 152-tool server (issue #32, T33).

These tests drive the **real** server -- every domain registered, the real lifespan, the
real REST client -- through the official MCP Python SDK v2 ``Client``, which is the same
client an MCP host uses. They are the executable form of issue #32 section 1:

* discovery: the full surface, titles, descriptions, input/output schemas, annotations;
* interoperability: every input schema is a closed object rooted at ``request`` and every
  output schema is object-rooted (never a bare array/scalar/null);
* structured output: ``structured_content`` is a dict whose top-level shape matches the
  published output schema (every required member present, no undeclared member) and the
  text channel carries the same projection;
* ``isError``: an anticipated failure is a sanitized ``ToolError``; a protocol rejection is
  an ``MCPError``; an unexpected exception never leaks details;
* cancellation: a cancelled call cancels the server-side handler (observed through a
  synthetic tool) instead of becoming an error;
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
from mcp import Client, MCPError, StdioServerParameters
from mcp.server.mcpserver import MCPServer
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools import OPEN_WORLD_TOOLS

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"

#: The phase-2 exit-criteria surface (ADR-001 section 10, API-COVERAGE section 4).
EXPECTED_TOOL_COUNT = 112
EXPECTED_READ_ONLY_TOOL_COUNT = 74
EXPECTED_MUTATION_COUNT = 38

#: The protocol revision the SDK negotiates by default with a modern server.
MODERN_PROTOCOL_VERSION = "2026-07-28"

#: The protocol eras the server accepts, as ``Client`` keyword arguments: the latest legacy
#: handshake revision (``2025-11-25``) and the modern per-request envelope (``2026-07-28``).
#: The prompt error mapping must be identical on both.
PROTOCOL_ERAS = (
    pytest.param({"mode": "legacy"}, id="legacy-2025-11-25"),
    pytest.param({}, id="modern-2026-07-28"),
)


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


def stdio_env() -> dict[str, str]:
    """The environment an MCP host passes to the real entrypoint."""
    return {
        "PYTHONPATH": str(SRC_DIR),
        "SOPHOS_HOST": HOST,
        "SOPHOS_PORT": "4444",
        "SOPHOS_API_KEY": KEY,
        "SOPHOS_VERIFY_SSL": "false",
    }


def stdio_params() -> StdioServerParameters:
    """The real entrypoint as an MCP host would launch it: a subprocess, no TTY."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "sophos_firewall_mcp.server"],
        env=stdio_env(),
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
        if not schema.get("properties") and "oneOf" not in schema and "anyOf" not in schema:
            # Six operations declare no parameters at all (DNS settings, IPsec live
            # connections/settings, SSL VPN global settings, the two status reads). The
            # SDK publishes an empty object schema for them; that is the correct shape for
            # a zero-argument tool.
            assert schema.get("required") is None, tool.name
            continue
        # Arguments are flat: the request model's fields are the root properties, with no
        # ``request`` wrapper. A discriminated-union request publishes a root ``oneOf`` of
        # closed variants, which ``assert_closed_object`` walks.
        assert "request" not in schema.get("properties", {}), tool.name
        assert_closed_object(schema, schema, tool.name)


async def test_every_output_schema_is_object_rooted():
    async with Client(make_server()) as client:
        result = await client.list_tools()

    for tool in result.tools:
        schema = tool.output_schema
        assert schema is not None, tool.name
        assert schema["type"] == "object", tool.name
        assert schema.get("properties"), tool.name


async def test_every_tool_declares_the_per_tool_open_world_hint():
    """The hint describes the interaction domain, not the trustworthiness of the data.

    One configured appliance is a closed domain, so a tool that reads or writes its own
    configuration is ``openWorldHint: false``. Only the tools whose result is produced by
    entities the appliance does not own are open (``OPEN_WORLD_TOOLS``).
    """
    async with Client(make_server()) as client:
        result = await client.list_tools()

    for tool in result.tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.open_world_hint is (tool.name in OPEN_WORLD_TOOLS), tool.name

    open_names = {tool.name for tool in result.tools if tool.annotations.open_world_hint}
    assert open_names == set(OPEN_WORLD_TOOLS)


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
            tools = (await client.list_tools()).tools
            result = await client.call_tool("firewall_rule_list", {"ip_family": "ipv4"})

    tool = next(candidate for candidate in tools if candidate.name == "firewall_rule_list")
    schema = tool.output_schema
    assert schema is not None
    assert result.is_error is False
    assert isinstance(result.structured_content, dict)

    # The projection must carry every member the published schema marks required and no
    # member the schema does not declare. This is the dependency-free subset of a JSON
    # Schema validation: the project does not declare a validator, and a projection that
    # drifts from the published contract (a dropped required field or an extra one) fails
    # here instead of passing silently.
    assert set(schema.get("required", [])) <= set(result.structured_content)
    assert set(result.structured_content) <= set(schema["properties"])
    item_schema = schema["properties"]["items"]["items"]
    item_definition = schema["$defs"][item_schema["$ref"].rsplit("/", 1)[-1]]
    for item in result.structured_content["items"]:
        assert set(item_definition.get("required", [])) <= set(item)
        assert set(item) <= set(item_definition["properties"])

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
            result = await client.call_tool("firewall_rule_list", {"ip_family": "ipv4"})

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
            result = await client.call_tool("firewall_rule_list", {"ip_family": "ipv4"})

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
            result = await client.call_tool("firewall_rule_list", {"ip_family": "ipv4", "page": 0})

    assert result.is_error is True
    assert route.call_count == 0


async def test_an_unknown_tool_is_invalid_params_over_stdio():
    """An unknown tool name is a protocol error, not a tool execution error.

    The spec puts an unknown tool name in the invalid-params class (``-32602``). The SDK's
    tool handler turns it into an ``isError`` result, so the server's middleware corrects
    it; this drives the real STDIO subprocess, so it pins the wire behaviour a host sees.
    """
    async with asyncio.timeout(90):
        async with Client(stdio_params()) as client:
            with pytest.raises(MCPError) as caught:
                await client.call_tool("sophos_tool_that_does_not_exist", {})

    assert caught.value.code == INVALID_PARAMS
    assert "Unknown tool" in caught.value.message
    assert "sophos_tool_that_does_not_exist" in caught.value.message


@pytest.mark.parametrize("era", PROTOCOL_ERAS)
async def test_an_invalid_prompt_request_is_invalid_params_over_stdio(era: dict[str, str]) -> None:
    """An unknown prompt, missing arguments or a rejected argument is ``-32602``.

    The message names the rejected argument, so a client can fix the request without
    reading a traceback. Both protocol eras must agree.
    """
    cases = [
        ("nope", None, "Unknown prompt: nope"),
        ("explain_flow", {}, "Missing required arguments"),
        (
            "explain_flow",
            {"source": "1.1.1.1", "destination": "2.2.2.2", "service": "https", "bogus": "x"},
            "'bogus' is not an accepted argument",
        ),
        (
            "explain_flow",
            {"source": "1.1.1.1", "destination": "2.2.2.2", "service": "https", "port": "443"},
            "port requires protocol 'tcp' or 'udp'",
        ),
    ]
    async with asyncio.timeout(90):
        async with Client(stdio_params(), **era) as client:
            for name, arguments, message_fragment in cases:
                with pytest.raises(MCPError) as caught:
                    await client.get_prompt(name, arguments)
                assert caught.value.code == INVALID_PARAMS, (name, arguments)
                assert message_fragment in caught.value.message, (name, arguments)


@pytest.mark.parametrize("era", PROTOCOL_ERAS)
async def test_a_valid_prompt_renders_the_same_content_over_stdio(era: dict[str, str]) -> None:
    """The error mapping must not change what a valid prompt renders."""
    async with asyncio.timeout(90):
        async with Client(stdio_params(), **era) as client:
            over_stdio = await client.get_prompt("find_unused_objects", {})

    async with Client(make_server()) as in_process:
        direct = await in_process.get_prompt("find_unused_objects", {})

    assert over_stdio.messages == direct.messages
    text = over_stdio.messages[0].content.text
    assert "audit_firewall_rules" in text
    assert '"checks": ["unused-object"]' in text


@pytest.mark.parametrize("era", PROTOCOL_ERAS)
async def test_a_tool_execution_failure_stays_a_tool_error_over_stdio(
    era: dict[str, str],
) -> None:
    """A failure after a valid tool was invoked is ``isError``, not ``-32602``.

    The subprocess points at a closed local port, so the handler fails in the transport
    layer after the tool name and arguments were accepted: exactly the class that must
    stay a tool execution error.
    """
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sophos_firewall_mcp.server"],
        env={**stdio_env(), "SOPHOS_HOST": "127.0.0.1", "SOPHOS_PORT": "1"},
    )
    async with asyncio.timeout(90):
        async with Client(params, **era) as client:
            result = await client.call_tool("firewall_rule_list", {"ip_family": "ipv4"})

    assert result.is_error is True
    assert "could not be reached" in result.content[0].text


@pytest.mark.parametrize("era", PROTOCOL_ERAS)
async def test_a_genuine_prompt_renderer_crash_is_an_internal_error_over_stdio(
    tmp_path: Path, era: dict[str, str]
) -> None:
    """A programming error while rendering a valid prompt is ``-32603`` on every era.

    The real prompts cannot crash on their own, so the subprocess runs the real entrypoint
    with one renderer replaced by a crash. The client must see the generic internal error,
    never the exception text; ``tests/test_server.py`` pins the server-side log.
    """
    driver = tmp_path / "crashing_prompt_server.py"
    driver.write_text(
        "import sophos_firewall_mcp.prompts as prompts\n"
        "\n"
        "\n"
        "def _crash(*args, **kwargs):\n"
        "    raise RuntimeError('synthetic renderer crash')\n"
        "\n"
        "\n"
        "prompts._explain_message = _crash\n"
        "\n"
        "from sophos_firewall_mcp.server import main\n"
        "\n"
        "main()\n",
        encoding="utf-8",
    )
    params = StdioServerParameters(command=sys.executable, args=[str(driver)], env=stdio_env())

    async with asyncio.timeout(90):
        async with Client(params, **era) as client:
            with pytest.raises(MCPError) as caught:
                await client.get_prompt(
                    "explain_flow",
                    {"source": "1.1.1.1", "destination": "2.2.2.2", "service": "https"},
                )

    assert caught.value.code == INTERNAL_ERROR
    assert caught.value.message == "Internal server error"
    assert "synthetic renderer crash" not in caught.value.message


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


# -- Invocation-rate policy ------------------------------------------------------------


async def test_tool_calls_are_not_rate_limited_through_the_mcp_client():
    """The documented policy is concurrency-only at the tool-invocation layer too.

    The policy is about tool invocations, not HTTP requests, so the HTTP-client test in
    ``tests/test_client.py`` cannot catch a limiter added at the tool dispatch layer. Fifty
    ``tools/call`` requests through the real SDK ``Client`` must all succeed.
    """
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/firewall/rules/ipv4").mock(
            return_value=httpx.Response(
                200,
                json={"items": [], "pages": {"current": 1, "size": 50, "maxSize": 100}},
            )
        )
        async with Client(make_server()) as client:
            for _ in range(50):
                result = await client.call_tool("firewall_rule_list", {"ip_family": "ipv4"})
                assert result.is_error is False


# -- Cancellation ----------------------------------------------------------------------


async def test_cancellation_reaches_the_server_handler_instead_of_becoming_an_error():
    """A cancelled call must cancel the server-side handler, not surface as a tool error.

    Cancelling the client task and awaiting it proves only that asyncio honours
    ``task.cancel()``; it never observes the server. The property that matters is that the
    SDK propagates the cancellation to the *server* handler. A synthetic tool records
    ``CancelledError`` and this test waits for that signal, so a server that swallowed the
    cancellation (or turned it into an ``isError`` result) fails the test instead of
    passing it.
    """
    started = asyncio.Event()
    cancelled = asyncio.Event()

    server = make_server()

    @server.tool(
        name="synthetic_wait",
        description="Synthetic tool that waits until the caller cancels it.",
    )
    async def synthetic_wait() -> dict[str, bool]:
        started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return {"finished": True}

    async with Client(server) as client:
        task = asyncio.create_task(client.call_tool("synthetic_wait", {}))
        await asyncio.wait_for(started.wait(), timeout=10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # The server handler must observe the cancellation. If it does not, this wait times
        # out and the test fails: the assertion is on the server side, not on the client
        # task that asyncio already guarantees to cancel.
        await asyncio.wait_for(cancelled.wait(), timeout=10)


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
