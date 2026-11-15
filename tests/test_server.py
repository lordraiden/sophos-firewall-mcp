"""Tests for the MCP server factory, lifespan, registration contract and STDIO transport.

These tests are the executable form of issue #26: one shared REST client created by the
lifespan and closed exactly once, a fixed registration contract with a read-only filter,
typed tool contracts, structured output, sanitized error semantics, cancellation that
propagates, and a STDIO server whose stdout carries only the MCP protocol.

The synthetic domain modules defined here stand in for #27-#31: one read-only tool and
one mutation tool registered through the real contract.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Any, Callable

import pytest
from mcp import Client, MCPError, StdioServerParameters
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from sophos_firewall_mcp import server as server_module
from sophos_firewall_mcp.client import SophosRestClient
from sophos_firewall_mcp.config import ConfigurationError, Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import (
    SophosAmbiguousWriteError,
    SophosAPIError,
    SophosAuthError,
    SophosConflictError,
    SophosNotFoundError,
    SophosTransportError,
    SophosValidationError,
)
from sophos_firewall_mcp.server import (
    INSTRUCTIONS,
    SERVER_NAME,
    create_server,
    create_server_from_env,
)
from sophos_firewall_mcp.tools import (
    DomainAdapter,
    ToolKind,
    register_tool,
    tool_error,
)

SRC_DIR = Path(__file__).resolve().parents[1] / "src"

#: Set by the slow synthetic handler so the cancellation test knows the handler is running.
_SLOW_STARTED: asyncio.Event | None = None


# -- Synthetic domain models (module level so the SDK can resolve the annotations) -----


class EchoInput(BaseModel):
    """Closed input contract: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)


class EchoOutput(BaseModel):
    """Object-rooted structured output."""

    name: str
    read_only: bool
    client_id: int
    context_id: int


class EmptyOutput(BaseModel):
    """Minimal output for tools that only exercise an error path."""

    value: str


# -- Synthetic domain modules ----------------------------------------------------------


def register_synthetic_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """One read-only tool and one mutation tool, registered through the real contract."""

    class EchoAdapter(DomainAdapter):
        async def echo(self, name: str) -> EchoOutput:
            return EchoOutput(
                name=name,
                read_only=self.read_only,
                client_id=id(self.client),
                context_id=id(self.context),
            )

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sophos_synthetic_echo",
        title="Echo a name",
        description=(
            "Read-only synthetic tool used by the foundation tests. It echoes the name "
            "and reports the shared client identity; it never contacts the appliance."
        ),
    )
    async def echo(request: EchoInput, ctx: Context[AppContext]) -> EchoOutput:
        return await EchoAdapter.from_context(ctx).echo(request.name)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="sophos_synthetic_mutate",
        title="Synthetic mutation",
        description=(
            "Mutation synthetic tool used by the foundation tests. It exists only to "
            "prove the read-only filter; it never contacts the appliance."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=False),
    )
    async def mutate(request: EchoInput) -> EchoOutput:
        return EchoOutput(name=request.name, read_only=False, client_id=0, context_id=0)


def register_error_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Tools that exercise the error, structured-output and cancellation paths."""

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sophos_test_tool_error",
        title="Raise ToolError",
        description="Raises an anticipated ToolError for the error-semantics tests.",
    )
    async def raises_tool_error() -> EmptyOutput:
        raise ToolError("the object is not valid")

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sophos_test_crash",
        title="Raise an unexpected exception",
        description="Raises an unexpected exception for the crash-semantics tests.",
    )
    async def raises_unexpected() -> EmptyOutput:
        raise RuntimeError("secret internal detail")

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sophos_test_protocol_error",
        title="Raise MCPError",
        description="Raises a protocol MCPError for the protocol-error tests.",
    )
    async def raises_mcp_error() -> EmptyOutput:
        raise MCPError(code=-32602, message="invalid params")

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sophos_test_invalid_output",
        title="Return invalid structured output",
        description="Returns a value that does not match its declared output model.",
    )
    async def invalid_output() -> EmptyOutput:
        return {"unexpected": "shape"}  # type: ignore[return-value]

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sophos_test_slow",
        title="Block until cancelled",
        description="Blocks until cancelled, for the cancellation-propagation test.",
    )
    async def slow() -> EmptyOutput:
        assert _SLOW_STARTED is not None
        _SLOW_STARTED.set()
        await asyncio.Event().wait()
        return EmptyOutput(value="never")


# -- Helpers ---------------------------------------------------------------------------


def make_settings(**overrides: Any) -> Settings:
    """Build valid settings without touching the process environment."""
    values: dict[str, Any] = {
        "host": "192.0.2.10",
        "port": 4444,
        "api_key": "test-api-key",
        "verify_ssl": False,
        "timeout": 5.0,
        "read_only_mode": False,
    }
    values.update(overrides)
    return Settings(**values)


def lifespan_of(
    server: MCPServer[AppContext],
) -> Callable[[MCPServer[AppContext]], AbstractAsyncContextManager[AppContext]]:
    """Return the lifespan callable the factory installed on the server."""
    lifespan = server.settings.lifespan
    assert lifespan is not None
    return lifespan


async def tools_by_name(server: MCPServer[AppContext]) -> dict[str, Any]:
    """List the published tools through the public SDK API, keyed by name."""
    return {tool.name: tool for tool in await server.list_tools()}


class _FakeClient:
    """Counts ``aclose`` calls so exactly-once shutdown is observable."""

    instances: list["_FakeClient"] = []

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.close_calls = 0
        _FakeClient.instances.append(self)

    async def aclose(self) -> None:
        self.close_calls += 1


# -- Factory, configuration and entrypoint ---------------------------------------------


def test_create_server_builds_the_stdio_server():
    server = create_server(make_settings())

    assert server.name == SERVER_NAME
    assert server.instructions == INSTRUCTIONS
    # subscriptions=False unregisters subscriptions/listen: the catalog is static.
    #
    # This reaches into `_lowlevel_server` deliberately: the SDK exposes no public way to
    # ask whether a request handler is registered, and the assertion is the only direct
    # check that `subscriptions=False` took effect. The SDK is pinned (mcp>=2.3.0,<3) and
    # this is the one private access in the suite; if the pin moves, this line is the
    # tripwire, not a silent regression.
    assert server._lowlevel_server.get_request_handler("subscriptions/listen") is None


def test_create_server_rejects_non_settings():
    with pytest.raises(TypeError):
        create_server(object())  # type: ignore[arg-type]


def test_create_server_from_env_validates_the_environment():
    with pytest.raises(ConfigurationError) as excinfo:
        create_server_from_env({})

    assert "SOPHOS_HOST" in str(excinfo.value)


def test_create_server_from_env_never_echoes_the_api_key():
    with pytest.raises(ConfigurationError) as excinfo:
        create_server_from_env(
            {
                "SOPHOS_HOST": "192.0.2.10",
                "SOPHOS_API_KEY": "super-secret-api-key",
                "SOPHOS_PORT": "not-a-port",
            }
        )

    assert "super-secret-api-key" not in str(excinfo.value)


def test_create_server_from_env_builds_a_server():
    server = create_server_from_env(
        {
            "SOPHOS_HOST": "192.0.2.10",
            "SOPHOS_API_KEY": "test-api-key",
            "SOPHOS_VERIFY_SSL": "false",
        }
    )

    assert server.name == SERVER_NAME


def test_main_reports_a_configuration_error_on_stderr(capsys):
    with pytest.raises(SystemExit) as excinfo:
        server_module.main({})

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "SOPHOS_HOST" in captured.err


def test_main_runs_the_stdio_transport(monkeypatch):
    transports: list[str] = []

    class _RecordingServer:
        def run(self, transport: str) -> None:
            transports.append(transport)

    monkeypatch.setattr(
        server_module, "create_server_from_env", lambda env=None: _RecordingServer()
    )

    server_module.main({"SOPHOS_HOST": "192.0.2.10", "SOPHOS_API_KEY": "test-api-key"})

    assert transports == ["stdio"]


# -- Lifespan --------------------------------------------------------------------------


async def test_lifespan_yields_an_app_context_with_one_real_client():
    settings = make_settings()
    server = create_server(settings)

    async with lifespan_of(server)(server) as context:
        assert isinstance(context, AppContext)
        assert isinstance(context.client, SophosRestClient)
        assert context.settings is settings
        assert context.read_only is False

    # The lifespan closed the client: a request now fails before any network I/O.
    with pytest.raises(RuntimeError):
        await context.client.get("/administration/system-settings")


async def test_lifespan_read_only_flag_matches_the_settings():
    server = create_server(make_settings(read_only_mode=True))

    async with lifespan_of(server)(server) as context:
        assert context.read_only is True
        assert context.settings.read_only_mode is True


async def test_lifespan_closes_the_client_exactly_once_on_normal_shutdown(monkeypatch):
    _FakeClient.instances = []
    monkeypatch.setattr(server_module, "SophosRestClient", _FakeClient)
    server = create_server(make_settings())

    async with lifespan_of(server)(server) as context:
        assert len(_FakeClient.instances) == 1
        assert context.client is _FakeClient.instances[0]

    assert len(_FakeClient.instances) == 1
    assert _FakeClient.instances[0].close_calls == 1


async def test_lifespan_closes_the_client_exactly_once_on_exceptional_shutdown(monkeypatch):
    _FakeClient.instances = []
    monkeypatch.setattr(server_module, "SophosRestClient", _FakeClient)
    server = create_server(make_settings())

    with pytest.raises(RuntimeError, match="boom"):
        async with lifespan_of(server)(server):
            raise RuntimeError("boom")

    assert len(_FakeClient.instances) == 1
    assert _FakeClient.instances[0].close_calls == 1


# -- Registration contract -------------------------------------------------------------


async def test_registered_tools_have_names_titles_and_descriptions():
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    tools = await tools_by_name(server)

    assert set(tools) == {"sophos_synthetic_echo", "sophos_synthetic_mutate"}
    assert tools["sophos_synthetic_echo"].title == "Echo a name"
    assert "Read-only synthetic tool" in tools["sophos_synthetic_echo"].description
    assert tools["sophos_synthetic_mutate"].title == "Synthetic mutation"


async def test_no_legacy_raw_rest_xml_or_router_tools_are_advertised():
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    names = set(await tools_by_name(server))

    assert "sophos_raw_api_request" not in names
    assert "route_tools" not in names
    assert "call_routed_tool" not in names
    assert not any("xml" in name for name in names)


async def test_read_only_mode_does_not_register_mutation_tools():
    server = create_server(make_settings(read_only_mode=True), domains=[register_synthetic_tools])

    names = set(await tools_by_name(server))

    assert names == {"sophos_synthetic_echo"}
    assert "sophos_synthetic_mutate" not in names


async def test_write_mode_registers_both_tools():
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    names = set(await tools_by_name(server))

    assert names == {"sophos_synthetic_echo", "sophos_synthetic_mutate"}


async def test_tool_annotations_use_the_wire_names_and_expected_values():
    server = create_server(make_settings(), domains=[register_synthetic_tools])
    tools = await tools_by_name(server)

    read_wire = tools["sophos_synthetic_echo"].annotations.model_dump(
        by_alias=True, exclude_none=True
    )
    assert read_wire == {
        "title": "Echo a name",
        "readOnlyHint": True,
        "openWorldHint": True,
    }

    write_wire = tools["sophos_synthetic_mutate"].annotations.model_dump(
        by_alias=True, exclude_none=True
    )
    assert write_wire == {
        "title": "Synthetic mutation",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    }


async def test_input_schema_is_closed_and_excludes_the_context_parameter():
    server = create_server(make_settings(), domains=[register_synthetic_tools])
    tool = (await tools_by_name(server))["sophos_synthetic_echo"]

    schema = tool.input_schema

    assert schema["type"] == "object"
    assert schema["required"] == ["request"]
    assert set(schema["properties"]) == {"request"}
    assert "ctx" not in schema["properties"]
    assert schema["$defs"]["EchoInput"]["additionalProperties"] is False


async def test_output_schema_is_object_rooted_and_typed():
    server = create_server(make_settings(), domains=[register_synthetic_tools])
    tool = (await tools_by_name(server))["sophos_synthetic_echo"]

    schema = tool.output_schema

    assert schema is not None
    assert schema["type"] == "object"
    assert set(schema["required"]) == {"name", "read_only", "client_id", "context_id"}


def test_register_tool_rejects_invalid_metadata():
    server = create_server(make_settings())

    with pytest.raises(ValueError, match="lower snake_case"):
        register_tool(
            server,
            read_only=False,
            kind=ToolKind.READ,
            name="Bad-Name",
            title="Title",
            description="Description",
        )

    with pytest.raises(ValueError, match="non-empty title"):
        register_tool(
            server,
            read_only=False,
            kind=ToolKind.READ,
            name="sophos_test_tool",
            title="  ",
            description="Description",
        )

    with pytest.raises(ValueError, match="non-empty description"):
        register_tool(
            server,
            read_only=False,
            kind=ToolKind.READ,
            name="sophos_test_tool",
            title="Title",
            description="",
        )


def test_register_tool_rejects_contradictory_annotations():
    server = create_server(make_settings())

    with pytest.raises(ValueError, match="cannot declare readOnlyHint=False"):
        register_tool(
            server,
            read_only=False,
            kind=ToolKind.READ,
            name="sophos_test_read",
            title="Title",
            description="Description",
            annotations=ToolAnnotations(read_only_hint=False),
        )

    with pytest.raises(ValueError, match="must not declare destructiveHint"):
        register_tool(
            server,
            read_only=False,
            kind=ToolKind.READ,
            name="sophos_test_read",
            title="Title",
            description="Description",
            annotations=ToolAnnotations(destructive_hint=True),
        )

    with pytest.raises(ValueError, match="must declare destructiveHint"):
        register_tool(
            server,
            read_only=False,
            kind=ToolKind.MUTATION,
            name="sophos_test_write",
            title="Title",
            description="Description",
        )

    with pytest.raises(ValueError, match="cannot declare readOnlyHint=True"):
        register_tool(
            server,
            read_only=False,
            kind=ToolKind.MUTATION,
            name="sophos_test_write",
            title="Title",
            description="Description",
            annotations=ToolAnnotations(
                read_only_hint=True, destructive_hint=False, idempotent_hint=True
            ),
        )


def test_domain_adapter_exposes_the_shared_client():
    context = AppContext(  # type: ignore[arg-type]
        client=_FakeClient(make_settings()), settings=make_settings(), read_only=True
    )

    adapter = DomainAdapter(context)

    assert adapter.context is context
    assert adapter.client is context.client
    assert adapter.read_only is True


def test_domain_adapter_rejects_a_non_context():
    with pytest.raises(TypeError):
        DomainAdapter(object())  # type: ignore[arg-type]


# -- Handler behavior through the official SDK client ----------------------------------


async def test_context_identity_is_stable_across_handler_calls():
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    async with Client(server) as client:
        first = await client.call_tool("sophos_synthetic_echo", {"request": {"name": "one"}})
        second = await client.call_tool("sophos_synthetic_echo", {"request": {"name": "two"}})

    assert first.is_error is False
    assert second.is_error is False
    assert first.structured_content["client_id"] == second.structured_content["client_id"]
    assert first.structured_content["context_id"] == second.structured_content["context_id"]
    assert first.structured_content["read_only"] is False


async def test_structured_output_is_published_on_both_channels():
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_synthetic_echo", {"request": {"name": "x"}})

    assert result.is_error is False
    assert result.structured_content["name"] == "x"
    # The SDK derives content from the return value; it is not hand-duplicated.
    assert isinstance(result.content, list)
    assert result.content[0].type == "text"
    assert '"name": "x"' in result.content[0].text


async def test_invalid_structured_output_is_a_generic_error():
    server = create_server(make_settings(), domains=[register_error_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_test_invalid_output", {})

    assert result.is_error is True
    assert result.content[0].text == "Error executing tool sophos_test_invalid_output"


async def test_tool_error_reaches_the_model():
    server = create_server(make_settings(), domains=[register_error_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_test_tool_error", {})

    assert result.is_error is True
    assert "the object is not valid" in result.content[0].text


async def test_unexpected_exception_does_not_leak_details():
    server = create_server(make_settings(), domains=[register_error_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_test_crash", {})

    assert result.is_error is True
    assert result.content[0].text == "Error executing tool sophos_test_crash"
    assert "secret internal detail" not in result.content[0].text


async def test_protocol_error_propagates_as_mcp_error():
    server = create_server(make_settings(), domains=[register_error_tools])

    async with Client(server) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.call_tool("sophos_test_protocol_error", {})

    assert excinfo.value.code == -32602


async def test_cancellation_propagates_instead_of_becoming_an_error():
    global _SLOW_STARTED
    _SLOW_STARTED = asyncio.Event()
    server = create_server(make_settings(), domains=[register_error_tools])

    task = asyncio.create_task(server.call_tool("sophos_test_slow", {}))
    await _SLOW_STARTED.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


async def test_crashes_are_reported_as_unexpected_tool_errors():
    """The SDK wraps crashes in ``UnexpectedToolError``; the foundation must not catch them."""
    server = create_server(make_settings(), domains=[register_error_tools])

    with pytest.raises(UnexpectedToolError):
        await server.call_tool("sophos_test_crash", {})


# -- Error mapping ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "fragment"),
    [
        (
            SophosNotFoundError("GET /x failed with HTTP 404", method="GET", path="/x", status=404),
            "does not exist",
        ),
        (
            SophosAuthError("GET /x failed with HTTP 403", method="GET", path="/x", status=403),
            "not allowed",
        ),
        (
            SophosValidationError(
                "POST /x failed with HTTP 400", method="POST", path="/x", status=400
            ),
            "rejected the request as invalid",
        ),
        (
            SophosConflictError(
                "POST /x failed with HTTP 409", method="POST", path="/x", status=409
            ),
            "conflicts with the current firewall state",
        ),
        (
            SophosAmbiguousWriteError("POST /x may have been applied", method="POST", path="/x"),
            "may or may not have been applied",
        ),
        (
            SophosTransportError("GET /x failed: ConnectError", method="GET", path="/x"),
            "could not be reached",
        ),
        (
            SophosAPIError("GET /x failed with HTTP 500", method="GET", path="/x", status=500),
            "unexpected error",
        ),
    ],
)
def test_tool_error_maps_each_typed_failure(exc: SophosAPIError, fragment: str):
    error = tool_error(exc)

    assert isinstance(error, ToolError)
    assert fragment in str(error)


def test_tool_error_includes_the_sanitized_error_code():
    exc = SophosValidationError(
        "GET /x failed with HTTP 400",
        method="GET",
        path="/x",
        status=400,
        error_code="invalidPageSizeParam",
    )

    message = str(tool_error(exc))

    assert "HTTP 400" in message
    assert "[error: invalidPageSizeParam]" in message


def test_tool_error_sanitizes_untrusted_text_and_bounds_the_length():
    exc = SophosAPIError(
        "Authorization: Bearer super-secret-api-key",
        method="GET",
        path="/x\x00\x01<script>",
        status=500,
        error_code="bad\ncode<script>",
    )

    message = str(tool_error(exc))

    assert "super-secret-api-key" not in message
    assert "\x00" not in message
    assert "<script>" not in message
    assert len(message) <= 300


# -- STDIO transport -------------------------------------------------------------------


async def test_stdio_transport_works_with_the_official_client():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sophos_firewall_mcp.server"],
        env={
            "PYTHONPATH": str(SRC_DIR),
            "SOPHOS_HOST": "192.0.2.10",
            "SOPHOS_API_KEY": "test-api-key-not-real",
            "SOPHOS_VERIFY_SSL": "false",
        },
    )

    async with asyncio.timeout(60):
        async with Client(params) as client:
            assert client.protocol_version == "2026-07-28"
            result = await client.list_tools()

    # No domain tools exist in phase 1, and a stray stdout write would have broken the
    # protocol framing before this assertion was reached.
    assert result.tools == []


def test_stdio_keeps_stdout_clean_when_configuration_is_invalid():
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
