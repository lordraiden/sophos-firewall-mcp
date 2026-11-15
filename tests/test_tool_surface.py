"""Global surface invariants for the complete 152-tool server (phase-2 review finding 8).

Every other domain test asserts its own subset, so a duplicated, stray or missing tool could
pass CI unnoticed. These tests build the real server with every domain registered and assert
the invariants that only the whole surface can prove:

* the registered set is exactly the curated ``tool_map`` (145 operationIds) plus the seven
  declared composites -- 152 tools with 152 unique names;
* the full surface declares exactly 54 mutations, and ``SOPHOS_READ_ONLY_MODE`` removes
  exactly those, leaving 98 read-only tools and zero mutations;
* every tool publishes an object-rooted output schema, a non-empty input schema and
  ``openWorldHint=true``;
* every published input parameter name is snake_case (M1, the 0.5.0 breaking change).

The curated file is read directly: it is the human decision record the server is built from,
and ``tests/test_coverage.py`` already validates its structure against the contract.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from mcp.server.mcpserver import MCPServer

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.server import create_server

ROOT = Path(__file__).resolve().parents[1]
CURATED_PATH = ROOT / "scripts" / "coverage_curated.yaml"

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"

#: The phase-2 exit-criteria counts (ADR-001 section 10, API-COVERAGE section 4).
EXPECTED_TOOL_COUNT = 152
EXPECTED_READ_ONLY_TOOL_COUNT = 98
EXPECTED_MUTATION_COUNT = 54
EXPECTED_TOOL_MAP_COUNT = 145
EXPECTED_COMPOSITE_COUNT = 7


def make_settings(*, read_only: bool = False) -> Settings:
    """Build valid settings without touching the process environment."""
    return Settings(
        host=HOST,
        port=443,
        api_key=KEY,
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=read_only,
    )


def make_server(*, read_only: bool = False) -> MCPServer[AppContext]:
    """The real server with every default domain registered."""
    return create_server(make_settings(read_only=read_only))


def curated_document() -> dict[str, Any]:
    """The curated decisions file, parsed as a mapping."""
    document = yaml.safe_load(CURATED_PATH.read_text())
    assert isinstance(document, dict)
    return document


def curated_tool_names() -> set[str]:
    """The tool names the curated file declares: ``tool_map`` plus the composites."""
    document = curated_document()
    tool_map = document["tool_map"]
    composites = document["composite_tools"]
    assert isinstance(tool_map, dict)
    assert len(tool_map) == EXPECTED_TOOL_MAP_COUNT
    assert len(composites) == EXPECTED_COMPOSITE_COUNT
    return set(tool_map.values()) | {tool["name"] for tool in composites}


async def published_tools(*, read_only: bool = False) -> list[Any]:
    """The tools the server publishes, in registration order."""
    return list(await make_server(read_only=read_only).list_tools())


async def tools_by_name(*, read_only: bool = False) -> dict[str, Any]:
    """The published tools, keyed by name."""
    return {tool.name: tool for tool in await published_tools(read_only=read_only)}


def mutation_names(tools: dict[str, Any]) -> set[str]:
    """The names of the tools the server classifies as mutations."""
    return {
        name
        for name, tool in tools.items()
        if tool.annotations is not None and tool.annotations.read_only_hint is False
    }


async def test_the_server_publishes_exactly_the_curated_surface() -> None:
    published = await published_tools()
    names = [tool.name for tool in published]

    assert len(names) == EXPECTED_TOOL_COUNT
    assert len(set(names)) == EXPECTED_TOOL_COUNT
    assert set(names) == curated_tool_names()
    assert len(curated_tool_names()) == EXPECTED_TOOL_COUNT


async def test_the_surface_declares_exactly_the_expected_mutations() -> None:
    tools = await tools_by_name()

    mutations = mutation_names(tools)

    assert len(mutations) == EXPECTED_MUTATION_COUNT
    assert len(tools) - len(mutations) == EXPECTED_READ_ONLY_TOOL_COUNT


async def test_read_only_mode_removes_exactly_the_mutations() -> None:
    full = await tools_by_name()
    read_only = await tools_by_name(read_only=True)

    mutations = mutation_names(full)

    assert len(read_only) == EXPECTED_READ_ONLY_TOOL_COUNT
    assert set(read_only) == set(full) - mutations
    assert mutation_names(read_only) == set()


async def test_every_tool_publishes_an_object_rooted_output() -> None:
    tools = await tools_by_name()

    for name, tool in tools.items():
        schema = tool.output_schema
        assert schema is not None, name
        assert schema["type"] == "object", name


async def test_every_tool_publishes_an_input_schema_and_an_open_world_hint() -> None:
    tools = await tools_by_name()

    for name, tool in tools.items():
        schema = tool.input_schema
        assert schema["type"] == "object", name
        # Tools whose operation declares no request parameters accept no arguments.
        assert set(schema["properties"]) <= {"request"}, name

        annotations = tool.annotations
        assert annotations is not None, name
        assert annotations.title, name
        assert annotations.open_world_hint is True, name


def resolve_ref(schema: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    """Follow a local ``$ref`` to the definition it names."""
    while "$ref" in node:
        node = schema["$defs"][node["$ref"].rsplit("/", 1)[-1]]
    return node


async def test_every_published_input_property_is_snake_case() -> None:
    """M1 (0.5.0): the published MCP input names use one convention, snake_case.

    The convention applies to the tool's own parameters -- the properties of the
    ``request`` object the caller sends. The counting method is the one recorded in
    ``PHASE-3-REVIEW.md``: classify each tool's ``request`` object's own ``properties``
    (camelCase = any uppercase letter). Nested request-body models keep the Sophos
    contract's field names and are serialized with ``by_alias=True``; they are the wire
    body, not tool parameters.

    There is no exception list: every published input property must be snake_case.
    """
    tools = await tools_by_name()

    camel_case: dict[str, list[str]] = {}
    scanned = 0
    for name, tool in tools.items():
        schema = tool.input_schema
        request = schema.get("properties", {}).get("request")
        if request is None:
            continue
        properties = resolve_ref(schema, request).get("properties", {})
        if not properties:
            # A union request (for example the address/MAC create payloads) publishes no
            # own properties; its variants are nested request-body models.
            continue
        scanned += 1
        offending = [prop for prop in properties if any(ch.isupper() for ch in prop)]
        if offending:
            camel_case[name] = offending

    # Guard against a schema-shape change that would make the assertion vacuous.
    assert scanned > 0
    assert camel_case == {}
