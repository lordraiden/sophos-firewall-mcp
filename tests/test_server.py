"""Tests for the MCP server factory, lifespan, registration contract and STDIO transport.

These tests are the executable form of issue #26: one shared REST client created by the
lifespan and closed exactly once, a fixed registration contract with a read-only filter,
typed tool contracts, structured output, sanitized error semantics, cancellation that
propagates, and a STDIO server whose stdout carries only the MCP protocol.

The synthetic domain modules defined here stand in for #27-#31: one read-only tool and
one mutation tool registered through the real contract.
"""

from __future__ import annotations

import ast
import asyncio
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tomllib
from contextlib import AbstractAsyncContextManager
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable

import pytest
from mcp import Client, MCPError, StdioServerParameters
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from mcp.types import INVALID_PARAMS, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sophos_firewall_mcp import resources as resources_module
from sophos_firewall_mcp import server as server_module
from sophos_firewall_mcp.client import SophosRestClient
from sophos_firewall_mcp.config import API_PATH_PREFIX, ConfigurationError, Settings
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
from sophos_firewall_mcp.models.common import ListPage, ObjectRef
from sophos_firewall_mcp.server import (
    INSTRUCTIONS,
    SERVER_NAME,
    SERVER_TITLE,
    create_server,
    create_server_from_env,
)
from sophos_firewall_mcp.tools import (
    DomainAdapter,
    ToolKind,
    _registered_tool,
    register_tool,
    tool_error,
)

# jsonschema is a transitive dependency of mcp, not a declared dev dependency; skip the
# schema-validation test rather than fail collection if it ever disappears.
jsonschema = pytest.importorskip("jsonschema")

SRC_DIR = Path(__file__).resolve().parents[1] / "src"

#: The project metadata the installed distribution is built from. The version test reads
#: it directly so a stale install cannot pass by comparing the metadata to itself.
PYPROJECT_PATH = Path(__file__).resolve().parents[1] / "pyproject.toml"

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


def register_pages_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """One read-only tool whose output carries the shared ``Pages`` metadata."""

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sophos_synthetic_page",
        title="Return one page",
        description="Returns one page of object references for the output-schema tests.",
    )
    async def page(request: EchoInput) -> ListPage[ObjectRef]:
        return ListPage[ObjectRef](items=[ObjectRef(name=request.name)])


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
    # check that `subscriptions=False` took effect. The SDK is pinned (mcp==2.3.0) and
    # this is the one private access in the server tests; if the pin moves, this line is
    # the tripwire, not a silent regression.
    assert server._lowlevel_server.get_request_handler("subscriptions/listen") is None


def test_create_server_rejects_non_settings():
    with pytest.raises(TypeError):
        create_server(object())  # type: ignore[arg-type]


# -- Server identity and catalog caching (H1, M2) --------------------------------------
#
# ``serverInfo`` is how a client identifies the build in its UI, its logs and its bug
# reports, and ``ttlMs`` is how long it may cache the static catalog. Both were empty or
# zero before this change: ``version: ""`` and ``ttlMs: 0`` ("immediately stale").


def test_instructions_document_the_calling_conventions():
    """H2/M1: flat arguments and the duplicated-payload rule are stated once, server-wide."""
    assert "takes them flat" in INSTRUCTIONS
    assert "no wrapper object" in INSTRUCTIONS
    assert "`oneOf`" in INSTRUCTIONS
    assert "`structuredContent`" in INSTRUCTIONS
    assert "read one of them, not both" in INSTRUCTIONS


def test_package_identity_reads_the_distribution_metadata(monkeypatch):
    """M2: the version, summary and homepage come from the installed metadata."""
    metadata = EmailMessage()
    metadata["Version"] = "9.9.9"
    metadata["Summary"] = "A fake summary."
    metadata["Project-URL"] = "Repository, https://example.test/repo"
    metadata["Project-URL"] = "Homepage, https://example.test/home"
    monkeypatch.setattr(server_module.importlib.metadata, "metadata", lambda name: metadata)

    identity = server_module._package_identity()

    assert identity.version == "9.9.9"
    assert identity.description == "A fake summary."
    assert identity.website_url == "https://example.test/home"


def test_package_identity_falls_back_when_the_distribution_is_not_installed(monkeypatch):
    """M2: a source checkout that was never installed still starts, with an honest version."""

    def missing(name: str) -> Any:
        raise server_module.importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(server_module.importlib.metadata, "metadata", missing)

    identity = server_module._package_identity()

    assert identity.version == server_module._UNKNOWN_VERSION
    assert identity.version
    assert identity.description is None
    assert identity.website_url is None


def declared_project_version() -> str:
    """The ``project.version`` declared in ``pyproject.toml``.

    Parsed with :mod:`tomllib` (standard library, Python 3.11+) rather than read from the
    installed metadata: the installed metadata is exactly what the server reports, so
    comparing it to itself cannot detect a stale install.
    """
    document = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    version = document["project"]["version"]
    assert isinstance(version, str) and version.strip()
    return version


def declared_project_description() -> str:
    """The ``project.description`` declared in ``pyproject.toml``.

    Read the same way as :func:`declared_project_version`, and for the same reason: the
    installed summary is what the server publishes, so only the declared one can detect
    that the install is stale.
    """
    document = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    description = document["project"]["description"]
    assert isinstance(description, str) and description.strip()
    return description


async def test_server_info_carries_the_package_identity():
    """M2: ``serverInfo`` identifies the build instead of reporting an empty version.

    The version is compared against ``pyproject.toml``, not against
    :func:`importlib.metadata.version`: the server reads the installed metadata, so a test
    that reads the same source is tautological and cannot catch the drift this test exists
    to catch (a checkout whose editable install was never refreshed after a version bump).
    """
    try:
        importlib.metadata.version("sophos-firewall-mcp-server")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - installed in CI
        pytest.skip("the distribution is not installed; the fallback is covered separately")

    declared_version = declared_project_version()
    server = create_server(make_settings())

    async with Client(server) as client:
        info = client.server_info

    assert info.name == SERVER_NAME
    assert info.title == SERVER_TITLE
    assert info.version
    assert info.version == declared_version
    assert info.description
    assert info.website_url == "https://github.com/lordraiden/sophos-firewall-mcp"


async def test_server_info_description_matches_the_declared_summary():
    """M3: ``serverInfo.description`` must not drift from ``pyproject.toml``.

    The description is read from the installed distribution metadata, which lags behind
    ``pyproject.toml`` in a checkout that was never reinstalled: 0.7.0 published "152 typed
    tools" against 112 registered tools, and the drift test only checked the version. The
    server substitutes the count it actually registered, so the published description must
    equal the declared summary exactly.
    """
    try:
        importlib.metadata.version("sophos-firewall-mcp-server")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - installed in CI
        pytest.skip("the distribution is not installed; the fallback is covered separately")

    server = create_server(make_settings())

    async with Client(server) as client:
        info = client.server_info

    assert info.description == declared_project_description()


def test_the_published_description_substitutes_the_real_tool_count():
    """M3: a stale installed summary cannot publish a count that contradicts ``tools/list``."""
    stale = (
        "MCP server for the Sophos Firewall 23 (SFOS 23.0) Configuration REST API: 152 "
        "typed tools for firewall, NAT, objects, users, network and audit over STDIO"
    )

    published = server_module._published_description(stale, 112)

    assert published is not None
    assert "112 typed tools" in published
    assert "152" not in published
    assert server_module._published_description(None, 112) is None
    # A summary without a count is published unchanged rather than rewritten.
    assert server_module._published_description("No count here.", 112) == "No count here."


async def test_the_read_only_description_publishes_the_read_only_count():
    """M3: the read-only surface publishes its own count, not the full one."""
    server = create_server(make_settings(read_only_mode=True))

    async with Client(server) as client:
        info = client.server_info

    assert info.description is not None
    assert "74 typed tools" in info.description
    assert "112 typed tools" not in info.description


async def test_tools_list_advertises_a_cache_hint():
    """H1/L7: the static catalog is cacheable, so ``ttlMs`` must not be zero."""
    server = create_server(make_settings())

    async with Client(server) as client:
        result = await client.list_tools()

    assert result.ttl_ms == server_module._CATALOG_TTL_MS
    assert result.ttl_ms > 0
    # The catalog is per-connection state, not a public document.
    assert result.cache_scope == "private"


async def test_server_discover_advertises_the_cache_hint_on_the_wire():
    """H1/L7: ``server/discover`` carries ``ttlMs`` on the wire, not only in the config.

    The SDK's ``Client`` has no ``discover()`` helper in 2.3.0, but its public ``session``
    does, and in ``auto`` mode the client probes ``server/discover`` during connect: the
    result asserted here is the parsed response of that wire exchange. A regression in the
    SDK's application of the hint to this method, or a dropped ``cache_hints`` entry, fails
    here instead of only in the module-level dict.
    """
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
            # The modern handshake proves the probe ran and was adopted.
            assert client.protocol_version == "2026-07-28"
            discovered = await client.session.discover()

    assert discovered.ttl_ms == server_module._CATALOG_TTL_MS
    assert discovered.ttl_ms > 0
    # The catalog is per-connection state, not a public document.
    assert discovered.cache_scope == "private"


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
    # A synthetic tool is not in OPEN_WORLD_TOOLS, so the closed default applies.
    assert read_wire == {
        "readOnlyHint": True,
        "openWorldHint": False,
    }

    write_wire = tools["sophos_synthetic_mutate"].annotations.model_dump(
        by_alias=True, exclude_none=True
    )
    assert write_wire == {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    }


async def test_input_schema_is_closed_and_excludes_the_context_parameter():
    server = create_server(make_settings(), domains=[register_synthetic_tools])
    tool = (await tools_by_name(server))["sophos_synthetic_echo"]

    schema = tool.input_schema

    assert schema["type"] == "object"
    # Flat arguments: the request model's own fields are the top-level properties.
    assert set(schema["properties"]) == {"name"}
    assert schema["required"] == ["name"]
    assert "ctx" not in schema["properties"]
    assert schema["additionalProperties"] is False


async def test_output_schema_is_object_rooted_and_typed():
    server = create_server(make_settings(), domains=[register_synthetic_tools])
    tool = (await tools_by_name(server))["sophos_synthetic_echo"]

    schema = tool.output_schema

    assert schema is not None
    assert schema["type"] == "object"
    assert set(schema["required"]) == {"name", "read_only", "client_id", "context_id"}


async def test_published_output_schema_documents_the_pages_semantics():
    """L1: the ``Pages`` field descriptions must reach the published outputSchema."""
    server = create_server(make_settings(), domains=[register_pages_tools])
    tool = (await tools_by_name(server))["sophos_synthetic_page"]

    schema = tool.output_schema
    assert schema is not None
    pages = schema["$defs"]["Pages"]["properties"]

    assert "current page" in pages["current"]["description"]
    assert "page size" in pages["size"]["description"]
    assert "maximum page size" in pages["maxSize"]["description"]
    # The trap the finding records: ``total`` is pages, ``items`` is items.
    assert "number of PAGES" in pages["total"]["description"]
    assert "number of ITEMS" in pages["items"]["description"]


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
        first = await client.call_tool("sophos_synthetic_echo", {"name": "one"})
        second = await client.call_tool("sophos_synthetic_echo", {"name": "two"})

    assert first.is_error is False
    assert second.is_error is False
    assert first.structured_content["client_id"] == second.structured_content["client_id"]
    assert first.structured_content["context_id"] == second.structured_content["context_id"]
    assert first.structured_content["read_only"] is False


async def test_structured_output_is_published_on_both_channels():
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_synthetic_echo", {"name": "x"})

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


def test_tool_error_reports_401_as_an_authentication_failure():
    """H3: a 401 is a bad key, not a permission problem."""
    exc = SophosAuthError(
        "GET /x failed with HTTP 401",
        method="GET",
        path="/x",
        status=401,
        error_code="unauthenticated",
    )

    message = str(tool_error(exc))

    assert "authentication failed" in message
    assert "SOPHOS_API_KEY" in message
    assert "SOPHOS_API_KEY_FILE" in message
    assert "(HTTP 401)" in message
    assert "[error: unauthenticated]" in message
    # The old shared wording sent the caller to the administrator profile.
    assert "not allowed" not in message
    assert "profile permissions" not in message


def test_tool_error_reports_403_as_an_authorization_failure():
    """H3: a 403 is the profile, not the key."""
    exc = SophosAuthError(
        "GET /x failed with HTTP 403",
        method="GET",
        path="/x",
        status=403,
    )

    message = str(tool_error(exc))

    assert "not allowed" in message
    assert "profile permissions" in message
    assert "(HTTP 403)" in message
    assert "authentication failed" not in message


def test_tool_error_reports_an_auth_failure_without_a_status_neutrally():
    """Neither message is safe to guess when the status is unknown."""
    message = str(tool_error(SophosAuthError("GET /x failed")))

    assert "authentication or authorization failed" in message
    assert "not allowed" not in message
    assert "authentication failed" not in message


# -- Argument validation ---------------------------------------------------------------


async def test_unknown_argument_is_rejected_with_a_sanitized_message():
    """L4: the model sees the field and the rule, not the pydantic dump."""
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_synthetic_echo", {"name": "x", "bogus": 1})

    assert result.is_error is True
    text = result.content[0].text
    assert "bogus is not an accepted argument" in text
    assert "accepted arguments are name" in text
    # Nothing from the raw pydantic dump may reach the model.
    assert "validation error for" not in text
    assert "Arguments" not in text
    assert "https://" not in text
    assert "input_value" not in text


async def test_argument_rule_violation_names_the_field_and_the_rule():
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_synthetic_echo", {"name": ""})

    assert result.is_error is True
    text = result.content[0].text
    assert "name must be at least 1 characters" in text
    assert "https://" not in text


async def test_missing_argument_is_reported_as_required():
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_synthetic_echo", {})

    assert result.is_error is True
    assert "name is required" in result.content[0].text


async def test_no_argument_tool_rejects_unknown_arguments():
    """L5: a typo on a no-argument tool is reported, not silently ignored."""
    server = create_server(make_settings(), domains=[register_error_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_test_tool_error", {"bogus": 1})

    assert result.is_error is True
    text = result.content[0].text
    assert "bogus is not an accepted argument" in text
    assert "this tool accepts no arguments" in text
    assert "https://" not in text


async def test_published_input_schema_rejects_unknown_arguments():
    """The published contract must say what the runtime enforces."""
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    async with Client(server) as client:
        tools = (await client.list_tools()).tools

    echo = next(tool for tool in tools if tool.name == "sophos_synthetic_echo")
    assert echo.input_schema["additionalProperties"] is False


def _is_union_schema(schema: dict[str, Any]) -> bool:
    """Whether a published input schema is a root union of variants."""
    return "oneOf" in schema or "anyOf" in schema


# -- Flat arguments (H2) ---------------------------------------------------------------
#
# The SDK derives one argument field per handler parameter, so a handler that takes a
# single ``request`` model would publish a ``request`` wrapper. ``register_tool`` publishes
# the request model's own fields at the top level instead: MCP's own examples are flat and
# a model's prior is flat, so the wrapper was a per-call failure mode. A discriminated-union
# request keeps a root ``oneOf``, because flattening it into one object would lose the
# per-variant required fields.


async def test_tool_description_is_the_domain_description():
    """The description is the domain's own text: there is no wrapper sentence to append."""
    server = create_server(make_settings(), domains=[register_synthetic_tools])
    tools = await tools_by_name(server)

    description = tools["sophos_synthetic_echo"].description

    assert description == (
        "Read-only synthetic tool used by the foundation tests. It echoes the name "
        "and reports the shared client identity; it never contacts the appliance."
    )


async def test_no_tool_publishes_a_request_wrapper():
    """H2: the wrapper is gone from the whole surface."""
    server = create_server(make_settings())
    tools = await tools_by_name(server)

    wrapped = [
        tool.name for tool in tools.values() if "request" in tool.input_schema.get("properties", {})
    ]

    assert wrapped == []


async def test_every_tool_with_arguments_publishes_them_flat_and_closed():
    """H2: the request model's fields are the top-level properties, and the root is closed."""
    server = create_server(make_settings())
    tools = await tools_by_name(server)

    flat = [
        tool
        for tool in tools.values()
        if tool.input_schema.get("properties") and not _is_union_schema(tool.input_schema)
    ]
    unions = [tool for tool in tools.values() if _is_union_schema(tool.input_schema)]
    no_argument = [
        tool
        for tool in tools.values()
        if not tool.input_schema.get("properties") and not _is_union_schema(tool.input_schema)
    ]

    assert len(flat) == 96, "the sweep must cover every flat-argument tool"
    assert len(unions) == 9, "the sweep must cover every union-request tool"
    assert len(flat) + len(unions) + len(no_argument) == 112
    for tool in flat:
        assert tool.input_schema["additionalProperties"] is False, tool.name
        assert "ctx" not in tool.input_schema["properties"], tool.name


async def test_union_request_tools_publish_a_root_union_of_closed_variants():
    """H2: a union request keeps its per-variant required fields under a root union.

    A discriminated union is published as ``oneOf`` (exactly one variant matches); the one
    undiscriminated union (``mac_address_create``, resolved left to right) keeps pydantic's
    ``anyOf``, where ``oneOf`` would be wrong.
    """
    server = create_server(make_settings())
    tools = await tools_by_name(server)

    unions = [tool for tool in tools.values() if _is_union_schema(tool.input_schema)]

    assert len(unions) == 9, "the sweep must cover every union-request tool"
    for tool in unions:
        schema = tool.input_schema
        assert schema["type"] == "object", tool.name
        # A root ``additionalProperties: false`` would reject every variant's fields.
        assert "additionalProperties" not in schema, tool.name
        branches = schema.get("oneOf") or schema.get("anyOf")
        assert branches, tool.name
        for branch in branches:
            target = schema["$defs"][branch["$ref"].rsplit("/", 1)[-1]]
            assert target["additionalProperties"] is False, tool.name
            assert target["required"], tool.name


async def test_flat_arguments_reach_the_handler_as_the_request_model():
    """H2: the handler still receives the request model, so no domain module changed."""
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    async with Client(server) as client:
        result = await client.call_tool("sophos_synthetic_echo", {"name": "flat"})

    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["name"] == "flat"


# -- Private SDK seam (L4) -------------------------------------------------------------
#
# ``tools/__init__.py`` closes each tool's argument model through the SDK's private
# ``MCPServer._tool_manager``. mcp 2.3.0 has no public equivalent, so the seam is pinned
# here: these tests fail loudly if the SDK moves it, and they assert the mutation landed
# on the object the SDK actually validates with -- not merely that the seam is readable.


def test_argument_model_seam_mutates_the_object_the_sdk_validates_with():
    """L4: the seam must change the model the SDK validates with, not just be readable."""
    server = create_server(make_settings(), domains=[register_synthetic_tools])

    tool = _registered_tool(server, "sophos_synthetic_echo")

    assert tool is not None
    # The accessor must return the very object the SDK keeps in its registry.
    assert tool is server._tool_manager.get_tool("sophos_synthetic_echo")
    # The mutation: ``Tool.run`` validates every call against this model, and it now
    # accepts the flat arguments the published schema advertises.
    assert tool.fn_metadata.arg_model.model_config.get("extra") == "forbid"
    with pytest.raises(ValidationError) as rejected:
        tool.fn_metadata.arg_model.model_validate({"name": "x", "bogus": 1})
    assert "bogus is not an accepted argument" in str(rejected.value)
    # ...and ``MCPServer.list_tools`` publishes this schema.
    assert tool.parameters["additionalProperties"] is False


def test_the_private_sdk_seam_is_confined_to_one_accessor():
    """L4: one accessor, so a future SDK move is a one-line fix rather than a hunt."""
    source = (SRC_DIR / "sophos_firewall_mcp" / "tools" / "__init__.py").read_text(encoding="utf-8")
    # The accessor reaches the attribute through ``getattr``, so both the attribute form
    # and the string form count as a reference to the seam.
    references = [
        node
        for node in ast.walk(ast.parse(source))
        if (isinstance(node, ast.Attribute) and node.attr == "_tool_manager")
        or (isinstance(node, ast.Constant) and node.value == "_tool_manager")
    ]

    assert len(references) == 1, "the private SDK seam must stay inside _registered_tool"


def test_the_private_sdk_seam_fails_loudly_when_it_moves(monkeypatch):
    """L4: a missing seam must not silently leave every tool's arguments open."""
    server = create_server(make_settings(), domains=[register_synthetic_tools])
    monkeypatch.delattr(server, "_tool_manager")

    with pytest.raises(RuntimeError) as moved:
        _registered_tool(server, "sophos_synthetic_echo")

    assert "MCPServer._tool_manager" in str(moved.value)
    assert "mcp 2.3.0" in str(moved.value)


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

    # Phase 2 registers the domain families through DEFAULT_DOMAINS. Reaching this
    # assertion at all proves the protocol framing survived: a stray stdout write would
    # have broken it before the tool list arrived.
    names = {tool.name for tool in result.tools}
    assert names, "the server must advertise the phase-2 domain tools over stdio"
    assert "firewall_rule_list" in names
    assert "network_status_dns_protection" in names


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


# -- Resources and prompts (M3) --------------------------------------------------------
#
# The server publishes all three MCP primitives. These tests pin the resource and prompt
# catalogs: non-empty, accurate against the generated coverage document and the live tool
# registry, cheap to read, and free of internal planning markers. The tool surface itself
# is pinned by ``tests/test_tool_surface.py``; nothing here changes it.

#: The resource catalog, in registration order.
RESOURCE_URIS = (
    "sophos://api/surface",
    "sophos://coverage",
    "sophos://read-only-policy",
    "sophos://conventions",
)

#: The prompt catalog, in registration order.
PROMPT_NAMES = ("audit_firewall", "explain_flow", "find_unused_objects")

#: The arguments each prompt needs to render. ``explain_flow`` is the only one with
#: required arguments; the other two render with none.
PROMPT_ARGUMENTS: dict[str, dict[str, str]] = {
    "audit_firewall": {},
    "explain_flow": {"source": "10.0.0.5", "destination": "8.8.8.8", "service": "HTTPS"},
    "find_unused_objects": {},
}

#: Every documented prompt argument combination, including the values that used to render
#: an invalid tool call (``fqdn`` for ``find_unused_objects``). Each rendered call is
#: validated against the named tool's published input schema.
PROMPT_ARGUMENT_MATRIX: dict[str, tuple[dict[str, str], ...]] = {
    "audit_firewall": (
        {},
        {"ip_family": "ipv4"},
        {"ip_family": "ipv6"},
        {"checks": "any-any, shadowed"},
        {"rule_name_contains": "Allow LAN to WAN"},
        {"ip_family": "ipv6", "checks": "disabled", "rule_name_contains": "WAN"},
    ),
    "explain_flow": (
        {"source": "10.0.0.5", "destination": "8.8.8.8", "service": "HTTPS"},
        {"source": "DMZ", "destination": "WAN", "service": "HTTPS", "endpoint_type": "zone"},
        {
            "source": "a.example",
            "destination": "b.example",
            "service": "HTTPS",
            "endpoint_type": "fqdn",
        },
        {
            "source": "10.0.0.5",
            "destination": "8.8.8.8",
            "service": "HTTPS",
            "protocol": "tcp",
            "port": "443",
        },
        {
            "source": "10.0.0.5",
            "destination": "8.8.8.8",
            "service": "HTTPS",
            "protocol": "udp",
            "port": "53",
        },
    ),
    "find_unused_objects": (
        {},
        {"object_type": "service"},
        {"object_type": "address-group"},
        {"ip_family": "ipv4"},
        {"ip_family": "ipv6"},
        {"ip_family": "fqdn"},
        {"object_type": "address-group", "ip_family": "fqdn"},
    ),
}

#: A rendered tool call starts a line with a JSON object (``_request`` emits compact JSON).
_RENDERED_CALL = re.compile(r"^[ \t]*(\{.*)$", re.MULTILINE)

#: A backticked snake_case token, which is how the prompt text names a tool.
_BACKTICKED_NAME = re.compile(r"`([a-z][a-z0-9_]*)`")

#: Upper bound for one resource body. A resource is passive context a client may inject
#: into every turn, so it must stay cheap: the four bodies together are under 10 KB.
MAX_RESOURCE_CHARS = 6_000
MAX_RESOURCE_TOTAL_CHARS = 10_000

#: Internal planning markers that must not reach published text (M4). The same rule the
#: tool surface follows applies to resources and prompts: a model reads them as
#: instructions, and a decision ID or a reference to the checked-in OpenAPI file is
#: meaningless to it.
PUBLISHED_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("decision id (M<n>)", re.compile(r"\bM\d+\b")),
    ("'contract'", re.compile(r"\bcontract", re.IGNORECASE)),
    ("'lab appliance'", re.compile(r"\blab appliance\b", re.IGNORECASE)),
    ("'issue #'", re.compile(r"\bissue #", re.IGNORECASE)),
    ("'live observation'", re.compile(r"\blive observation\b", re.IGNORECASE)),
)

#: Repository root, for the generated coverage document the matrix summarises.
REPO_ROOT = Path(__file__).resolve().parents[1]


async def read_all_resources(server: MCPServer[AppContext]) -> dict[str, str]:
    """Read every published resource, keyed by URI."""
    contents: dict[str, str] = {}
    for uri in RESOURCE_URIS:
        result = await server.read_resource(uri)
        contents[uri] = result[0].content
    return contents


def coverage_document_operation_counts() -> dict[str, int]:
    """Parse the per-domain operation counts out of ``docs/API-COVERAGE.md`` section 5."""
    text = (REPO_ROOT / "docs" / "API-COVERAGE.md").read_text(encoding="utf-8")
    return {
        title: int(count)
        for title, count in re.findall(
            r"^### 5\.\d+ (.+?) \((\d+) operations\)$", text, re.MULTILINE
        )
    }


async def test_resources_list_publishes_the_four_resources():
    """M3: the declared ``resources`` capability must not be empty."""
    server = create_server(make_settings())

    resources = await server.list_resources()

    assert [resource.uri for resource in resources] == list(RESOURCE_URIS)
    for resource in resources:
        assert resource.name
        assert resource.title
        assert resource.description
        assert resource.mime_type == "text/markdown"


async def test_every_resource_reads_to_bounded_marker_free_markdown():
    """M3/M4: each resource is a short Markdown document with no internal markers."""
    server = create_server(make_settings())

    contents = await read_all_resources(server)

    assert set(contents) == set(RESOURCE_URIS)
    for uri, text in contents.items():
        assert text.strip(), f"{uri} is empty"
        assert text.startswith("# "), f"{uri} must open with a Markdown title"
        assert len(text) <= MAX_RESOURCE_CHARS, f"{uri} is {len(text)} characters"
        for label, pattern in PUBLISHED_MARKERS:
            match = pattern.search(text)
            assert match is None, f"{uri} carries a {label}: {match.group(0)!r}"
    assert sum(len(text) for text in contents.values()) <= MAX_RESOURCE_TOTAL_CHARS


def test_the_coverage_matrix_matches_the_generated_document():
    """M3: the matrix is a summary of the generated document, not a second opinion."""
    documented = coverage_document_operation_counts()

    assert documented, "the coverage document must list its domains"
    assert sum(documented.values()) == resources_module.API_OPERATIONS
    for domain in resources_module.COVERAGE_DOMAINS:
        assert domain.title in documented, f"{domain.title} is not a section of the document"
        assert domain.api_operations == documented[domain.title], domain.title
    assert (
        sum(domain.api_operations for domain in resources_module.COVERAGE_DOMAINS)
        == resources_module.API_OPERATIONS
    )


async def test_the_coverage_matrix_tool_counts_match_the_live_registry():
    """M3: the tool column is the real surface, and the prefixes partition it."""
    server = create_server(make_settings())
    names = {tool.name for tool in await server.list_tools()}

    assert len(names) == resources_module.TOTAL_TOOL_COUNT
    claimed: dict[str, str] = {}
    for domain in resources_module.COVERAGE_DOMAINS:
        matched = {name for name in names if name.startswith(domain.tool_prefixes)}
        assert len(matched) == domain.tools, f"{domain.title}: {sorted(matched)}"
        for name in matched:
            assert name not in claimed, f"{name} is claimed by {claimed[name]} and {domain.title}"
            claimed[name] = domain.title
    assert claimed.keys() == names, "every published tool must belong to exactly one domain"
    assert (
        sum(domain.tools for domain in resources_module.COVERAGE_DOMAINS)
        == resources_module.TOTAL_TOOL_COUNT
    )


async def test_the_surface_resource_states_the_real_api_facts():
    """M3: the surface resource must not drift from the API it describes."""
    server = create_server(make_settings())

    text = (await server.read_resource("sophos://api/surface"))[0].content

    assert API_PATH_PREFIX in text
    for fact in ("384", "700", "145", "107", "112", "74", "38"):
        assert fact in text, f"the surface resource omits {fact}"
    for name in resources_module.COMPOSITE_TOOLS:
        assert f"`{name}`" in text, f"the surface resource omits the composite {name}"


async def test_the_read_only_policy_states_the_mode_of_this_process():
    """M3: the policy resource reports the mode the process actually runs in."""
    writable = create_server(make_settings())
    writable_text = (await writable.read_resource("sophos://read-only-policy"))[0].content

    assert "**disabled**" in writable_text
    assert f"all {resources_module.TOTAL_TOOL_COUNT} tools are registered" in writable_text

    read_only = create_server(make_settings(read_only_mode=True))
    read_only_text = (await read_only.read_resource("sophos://read-only-policy"))[0].content

    assert "**enabled**" in read_only_text
    assert "not registered at all" in read_only_text
    assert len(await read_only.list_tools()) == resources_module.READ_ONLY_TOOL_COUNT


async def test_the_conventions_resource_names_the_real_no_argument_tools():
    """M3: the argument-tool count and the no-argument list are the published surface."""
    server = create_server(make_settings())

    text = (await server.read_resource("sophos://conventions"))[0].content
    tools = {tool.name: tool for tool in await server.list_tools()}

    assert len(resources_module.NO_ARGUMENT_TOOLS) == 7
    for name in resources_module.NO_ARGUMENT_TOOLS:
        assert f"`{name}`" in text
        assert not tools[name].input_schema.get("properties"), name
    with_arguments = [
        tool
        for tool in tools.values()
        if tool.input_schema.get("properties") or _is_union_schema(tool.input_schema)
    ]
    assert len(with_arguments) == resources_module.ARGUMENT_TOOL_COUNT
    assert (
        f"{resources_module.ARGUMENT_TOOL_COUNT} of the {resources_module.TOTAL_TOOL_COUNT}" in text
    )


async def test_prompts_list_publishes_the_three_workflows():
    """M3: the declared ``prompts`` capability must not be empty."""
    server = create_server(make_settings())

    prompts = await server.list_prompts()

    assert [prompt.name for prompt in prompts] == list(PROMPT_NAMES)
    for prompt in prompts:
        assert prompt.title
        assert prompt.description
        assert prompt.arguments
        for argument in prompt.arguments:
            assert argument.description, f"{prompt.name}.{argument.name} has no description"

    by_name = {prompt.name: prompt for prompt in prompts}
    assert {argument.name for argument in by_name["audit_firewall"].arguments} == {
        "ip_family",
        "checks",
        "rule_name_contains",
    }
    assert {argument.name for argument in by_name["explain_flow"].arguments} == {
        "source",
        "destination",
        "endpoint_type",
        "service",
        "protocol",
        "port",
    }
    assert {argument.name for argument in by_name["find_unused_objects"].arguments} == {
        "object_type",
        "ip_family",
    }
    required = {
        argument.name for argument in by_name["explain_flow"].arguments if argument.required
    }
    assert required == {"source", "destination", "service"}


async def test_each_prompt_renders_a_self_contained_instruction():
    """M3: a rendered prompt names the real tool and the real call shape."""
    server = create_server(make_settings())

    for name, arguments in PROMPT_ARGUMENTS.items():
        result = await server.get_prompt(name, arguments)

        assert len(result.messages) == 1, name
        message = result.messages[0]
        assert message.role == "user"
        text = message.content.text
        assert _RENDERED_CALL.search(text), f"{name} does not show a rendered tool call"
        assert "read-only" in text.lower() or "nothing" in text.lower(), name


async def test_prompt_arguments_reach_the_tool_call():
    """M3: an argument the user supplies must appear in the rendered call."""
    server = create_server(make_settings())

    audit = await server.get_prompt(
        "audit_firewall", {"ip_family": "ipv6", "checks": "any-any, shadowed"}
    )
    audit_text = audit.messages[0].content.text
    assert '"ip_family": "ipv6"' in audit_text
    assert '"checks": ["any-any", "shadowed"]' in audit_text

    flow = await server.get_prompt(
        "explain_flow",
        {
            "source": "10.0.0.5",
            "destination": "8.8.8.8",
            "service": "HTTPS",
            "protocol": "tcp",
            "port": "443",
        },
    )
    flow_text = flow.messages[0].content.text
    assert '"source": {"ip": "10.0.0.5"}' in flow_text
    assert '"destination": {"ip": "8.8.8.8"}' in flow_text
    assert '"service": {"name": "HTTPS", "protocol": "tcp", "port": 443}' in flow_text

    zone_flow = await server.get_prompt(
        "explain_flow",
        {"source": "DMZ", "destination": "WAN", "service": "HTTPS", "endpoint_type": "zone"},
    )
    zone_text = zone_flow.messages[0].content.text
    assert '"source": {"zone": "DMZ"}' in zone_text
    assert '"destination": {"zone": "WAN"}' in zone_text

    unused = await server.get_prompt(
        "find_unused_objects", {"object_type": "service", "ip_family": "ipv4"}
    )
    unused_text = unused.messages[0].content.text
    assert '"object_type": "service"' in unused_text
    assert '"ip_family": "ipv4"' in unused_text


async def test_explain_flow_requires_its_endpoints():
    """M3: a prompt that cannot describe a flow must fail instead of rendering one."""
    server = create_server(make_settings())

    with pytest.raises(ValueError):
        await server.get_prompt("explain_flow", {})


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("nope", None),
        ("explain_flow", {}),
        (
            "explain_flow",
            {"source": "1.1.1.1", "destination": "2.2.2.2", "service": "https", "bogus": "x"},
        ),
    ],
)
async def test_a_caller_fixable_prompt_failure_is_invalid_params(
    name: str, arguments: dict[str, Any] | None
) -> None:
    """M4: an unknown prompt or bad arguments is ``-32602``, not ``-32603``.

    The spec puts an invalid prompt name and missing or invalid arguments in the invalid
    params class. The SDK maps every ``ValueError`` from ``prompts/get`` to an internal
    error, so the server's middleware corrects the caller-fixable ones.
    """
    server = create_server(make_settings())

    async with Client(server) as client:
        with pytest.raises(MCPError) as caught:
            await client.get_prompt(name, arguments)

    assert caught.value.code == INVALID_PARAMS


def rendered_tool_calls(text: str, tool_names: set[str]) -> list[tuple[str, dict[str, Any]]]:
    """Extract every rendered call object and the tool it belongs to.

    The prompt text names the tool immediately before the call, so the nearest preceding
    backticked token that is a registered tool is the callee. ``raw_decode`` parses the
    nested object without needing to know where it ends.
    """
    calls: list[tuple[str, dict[str, Any]]] = []
    for match in _RENDERED_CALL.finditer(text):
        prefix = text[: match.start(1)]
        names = [name for name in _BACKTICKED_NAME.findall(prefix) if name in tool_names]
        assert names, f"no tool name before the call at offset {match.start(1)}"
        payload, _ = json.JSONDecoder().raw_decode(text[match.start(1) :])
        calls.append((names[-1], payload))
    return calls


async def test_every_rendered_prompt_call_validates_against_its_tool_schema():
    """L10: a rendered prompt must emit a call the named tool accepts.

    This is the regression guard for the two defects CI missed: ``explain_flow`` used to
    omit the required ``service``, and ``find_unused_objects`` used to forward
    ``ip_family="fqdn"`` to ``audit_firewall_rules``, whose enum is ``ipv4|ipv6``.
    """
    server = create_server(make_settings())
    tools = {tool.name: tool for tool in await server.list_tools()}

    for name, argument_sets in PROMPT_ARGUMENT_MATRIX.items():
        for arguments in argument_sets:
            result = await server.get_prompt(name, arguments)
            text = result.messages[0].content.text
            calls = rendered_tool_calls(text, set(tools))
            assert calls, f"{name} rendered no tool call for {arguments}"

            for tool_name, payload in calls:
                jsonschema.validate(payload, tools[tool_name].input_schema)


async def test_explain_flow_rejects_a_port_without_a_tcp_or_udp_protocol():
    """L10: a port the tool cannot accept must fail to render, not render an invalid call."""
    server = create_server(make_settings())

    with pytest.raises(ValueError) as raised:
        await server.get_prompt(
            "explain_flow",
            {"source": "10.0.0.5", "destination": "8.8.8.8", "service": "HTTPS", "port": "443"},
        )

    # The SDK wraps the render failure; the actionable message is in the cause chain.
    messages: list[str] = []
    error: BaseException | None = raised.value
    while error is not None:
        messages.append(str(error))
        error = error.__cause__
    assert any("port requires protocol" in message for message in messages)


async def test_published_resource_and_prompt_text_names_only_real_tools():
    """M3: every tool-shaped name in the published text is a registered tool."""
    server = create_server(make_settings())
    names = {tool.name for tool in await server.list_tools()}
    prefixes = tuple(
        prefix for domain in resources_module.COVERAGE_DOMAINS for prefix in domain.tool_prefixes
    )

    texts = list((await read_all_resources(server)).values())
    for name, arguments in PROMPT_ARGUMENTS.items():
        result = await server.get_prompt(name, arguments)
        texts.append(result.messages[0].content.text)

    for text in texts:
        for token in re.findall(r"`([a-z][a-z0-9_]*)`", text):
            if token.startswith(prefixes):
                assert token in names, f"{token} looks like a tool but is not registered"


async def test_resources_and_prompts_are_registered_in_read_only_mode():
    """M3: a read-only deployment is exactly where an audit prompt is useful."""
    server = create_server(make_settings(read_only_mode=True))

    assert len(await server.list_resources()) == len(RESOURCE_URIS)
    assert len(await server.list_prompts()) == len(PROMPT_NAMES)


async def test_resources_and_prompts_are_served_over_the_wire_with_cache_hints():
    """M3/L7: the catalogs reach a real client, and they are cacheable like ``tools/list``."""
    server = create_server(make_settings())

    async with Client(server) as client:
        resources = await client.list_resources()
        prompts = await client.list_prompts()
        read = await client.read_resource("sophos://coverage")
        rendered = await client.get_prompt("find_unused_objects", {})

    assert [resource.uri for resource in resources.resources] == list(RESOURCE_URIS)
    assert resources.ttl_ms == server_module._CATALOG_TTL_MS
    assert [prompt.name for prompt in prompts.prompts] == list(PROMPT_NAMES)
    assert prompts.ttl_ms == server_module._CATALOG_TTL_MS
    assert read.ttl_ms == server_module._CATALOG_TTL_MS
    assert read.contents[0].text
    assert rendered.messages[0].content.text


# -- Domain selection (SOPHOS_TOOL_DOMAINS) --------------------------------------------
#
# ``SOPHOS_TOOL_DOMAINS`` narrows the tool surface to the domains a deployment needs. The
# exact per-domain tool names and counts are pinned in ``tests/test_tool_surface.py``; these
# tests cover the wiring: the factory honours the setting, an explicit registrar list still
# overrides it, an invalid selection fails startup, and the resources, prompts and
# instructions describe the surface this process actually registered.


def domain_settings(*domains: str, read_only: bool = False) -> Settings:
    """Settings that select exactly *domains*."""
    return make_settings(read_only_mode=read_only, tool_domains=domains)


async def domain_tool_names(domain: str, *, read_only: bool = False) -> list[str]:
    """The tools one domain registers, through its real registrar."""
    server = create_server(
        make_settings(read_only_mode=read_only),
        domains=[server_module.DOMAIN_REGISTRARS[domain]],
    )
    return [tool.name for tool in await server.list_tools()]


async def test_create_server_honours_the_domain_selection():
    """A selection publishes the union of its domains, in canonical order."""
    server = create_server(domain_settings("firewall", "nat", "audit"))

    names = [tool.name for tool in await server.list_tools()]
    expected: list[str] = []
    for domain in ("firewall", "nat", "audit"):
        expected.extend(await domain_tool_names(domain))

    assert names == expected
    assert len(names) == 17


async def test_a_selection_publishes_nothing_from_an_excluded_domain():
    server = create_server(domain_settings("firewall", "nat"))

    names = {tool.name for tool in await server.list_tools()}
    excluded = set(await domain_tool_names("objects")) | set(await domain_tool_names("network"))

    assert not names & excluded
    assert len(names) == 14


async def test_create_server_from_env_honours_the_domain_selection():
    server = create_server_from_env(
        {
            "SOPHOS_HOST": "192.0.2.10",
            "SOPHOS_API_KEY": "test-api-key",
            "SOPHOS_TOOL_DOMAINS": "nat,firewall",
        }
    )

    names = [tool.name for tool in await server.list_tools()]

    assert names == await domain_tool_names("firewall") + await domain_tool_names("nat")


async def test_an_explicit_domains_iterable_overrides_the_setting():
    """The registrar seam wins over the setting, which is what the domain tests rely on."""
    server = create_server(
        domain_settings("firewall"),
        domains=[server_module.DOMAIN_REGISTRARS["nat"]],
    )

    assert [tool.name for tool in await server.list_tools()] == await domain_tool_names("nat")


def test_an_invalid_domain_selection_fails_startup():
    with pytest.raises(ConfigurationError) as excinfo:
        create_server_from_env(
            {
                "SOPHOS_HOST": "192.0.2.10",
                "SOPHOS_API_KEY": "test-api-key",
                "SOPHOS_TOOL_DOMAINS": "firewall,firewal",
            }
        )

    message = str(excinfo.value)
    assert "SOPHOS_TOOL_DOMAINS" in message
    assert "firewal" in message


def test_main_reports_an_invalid_domain_selection_on_stderr(capsys):
    with pytest.raises(SystemExit) as excinfo:
        server_module.main(
            {
                "SOPHOS_HOST": "192.0.2.10",
                "SOPHOS_API_KEY": "test-api-key",
                "SOPHOS_TOOL_DOMAINS": "firewall,",
            }
        )

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "SOPHOS_TOOL_DOMAINS" in captured.err


async def test_the_surface_resource_describes_the_registered_surface():
    server = create_server(domain_settings("firewall", "nat"))
    text = (await server.read_resource("sophos://api/surface"))[0].content

    assert "| Domains enabled in this process | firewall and nat (2 of 6) |" in text
    assert "| Tools registered in this process | 14 (4 read-only, 10 mutations) |" in text
    # The catalog facts stay, because they describe the API rather than this process.
    assert "| Operations exposed as tools | 145 |" in text
    # Only the composites of the enabled domains are listed: the two firewall ones are
    # registered, the three audit ones are not.
    assert "2 composite tools compose audited operations" in text
    assert "`firewall_rule_clone`" in text
    assert "`firewall_rule_set_enabled`" in text
    for name in ("audit_firewall_rules", "explain_connectivity", "find_object_usage"):
        assert f"`{name}`" not in text


async def test_the_coverage_resource_marks_the_domains_this_process_did_not_enable():
    server = create_server(domain_settings("firewall", "nat"))
    text = (await server.read_resource("sophos://coverage"))[0].content

    assert "This process enables 2 of the 6 domains (firewall and nat)" in text
    assert "14 of the 112 catalog tools (4 read-only, 10 mutations)" in text
    assert "The objects, users, network and audit domains are not enabled" in text
    assert "| Addresses and address groups | 48 | 27 (not enabled) | read + write |" in text
    assert "| Firewall rules | 14 | 8 | read + write |" in text


async def test_the_read_only_policy_states_the_counts_of_this_process():
    writable = create_server(domain_settings("firewall", "nat"))
    writable_text = (await writable.read_resource("sophos://read-only-policy"))[0].content

    assert "all 14 tools are registered" in writable_text
    assert "including the 10 mutations" in writable_text
    assert "This process enables 2 of the 6 domains (firewall and nat)" in writable_text

    read_only = create_server(domain_settings("firewall", "nat", read_only=True))
    read_only_text = (await read_only.read_resource("sophos://read-only-policy"))[0].content

    assert "the mutation tools of the enabled domains are" in read_only_text
    assert "not registered at all" in read_only_text
    assert len(await read_only.list_tools()) == 4


async def test_the_conventions_resource_lists_only_registered_no_argument_tools():
    server = create_server(domain_settings("users"))
    text = (await server.read_resource("sophos://conventions"))[0].content

    assert "`live_user_list`" in text
    assert "`dns_settings_get`" not in text
    assert "8 of the 8 tools take arguments" not in text
    assert "7 of the 8 tools take arguments" in text


@pytest.mark.parametrize(
    ("domains", "expected"),
    [
        (("firewall", "nat", "objects", "users", "network", "audit"), PROMPT_NAMES),
        (("firewall", "nat", "objects", "network", "audit"), PROMPT_NAMES),
        (("firewall", "nat", "objects", "network"), ()),
        (("firewall", "nat"), ()),
        (("audit",), ("find_unused_objects",)),
        (("objects", "audit"), ("find_unused_objects",)),
        (("firewall", "nat", "objects", "audit"), ("audit_firewall", "find_unused_objects")),
    ],
)
async def test_a_prompt_is_registered_only_when_its_tools_are(
    domains: tuple[str, ...], expected: tuple[str, ...]
) -> None:
    """A prompt names concrete tools, so it is absent when one of them is absent."""
    server = create_server(domain_settings(*domains))

    assert tuple(prompt.name for prompt in await server.list_prompts()) == expected


async def test_the_instructions_name_the_enabled_domains_and_prompts():
    server = create_server(domain_settings("firewall", "nat"))
    instructions = server.instructions

    assert instructions is not None
    assert "This process enables 2 of the 6 domains (firewall and nat)" in instructions
    assert "14 of the 112 catalog tools (4 read-only, 10 mutations)" in instructions
    for name in PROMPT_NAMES:
        assert name not in instructions


async def test_the_complete_surface_keeps_the_unchanged_instructions():
    server = create_server(make_settings())

    assert server.instructions == INSTRUCTIONS
    assert "the prompts `audit_firewall`, `explain_flow`, `find_unused_objects`" in INSTRUCTIONS


@pytest.mark.parametrize(
    "domains",
    [
        ("firewall",),
        ("users",),
        ("audit",),
        ("firewall", "nat"),
        ("firewall", "nat", "objects", "network", "audit"),
    ],
)
async def test_a_filtered_instance_never_names_an_unregistered_tool(
    domains: tuple[str, ...],
) -> None:
    """Every tool-shaped name in the published text is a tool this process registered."""
    server = create_server(domain_settings(*domains))
    names = {tool.name for tool in await server.list_tools()}
    prefixes = tuple(
        prefix for domain in resources_module.COVERAGE_DOMAINS for prefix in domain.tool_prefixes
    )

    texts = list((await read_all_resources(server)).values())
    for name, arguments in PROMPT_ARGUMENTS.items():
        if name in {prompt.name for prompt in await server.list_prompts()}:
            result = await server.get_prompt(name, arguments)
            texts.append(result.messages[0].content.text)

    for text in texts:
        for token in re.findall(r"`([a-z][a-z0-9_]*)`", text):
            if token.startswith(prefixes):
                assert token in names, f"{token} looks like a tool but is not registered"


@pytest.mark.parametrize(
    "domains",
    [
        ("firewall",),
        ("users",),
        ("audit",),
        ("firewall", "nat"),
        ("firewall", "nat", "objects", "network", "audit"),
    ],
)
async def test_a_filtered_instance_stays_within_the_resource_budget(
    domains: tuple[str, ...],
) -> None:
    """The passive context stays bounded for every selection, not only the default one."""
    server = create_server(domain_settings(*domains))

    contents = await read_all_resources(server)

    for uri, text in contents.items():
        assert len(text) <= MAX_RESOURCE_CHARS, f"{uri} is {len(text)} characters"
    assert sum(len(text) for text in contents.values()) <= MAX_RESOURCE_TOTAL_CHARS
