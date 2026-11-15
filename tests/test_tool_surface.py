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
* every published input property name, at every depth of the request body, is snake_case
  (M1, the 0.5.0 breaking change);
* every published output property name, at every depth of the response body, is camelCase
  (the 0.6.0 output contract).

The curated file is read directly: it is the human decision record the server is built from,
and ``tests/test_coverage.py`` already validates its structure against the contract.
"""

from __future__ import annotations

import re
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

#: Tools whose operation declares no request parameters: they publish no ``request``.
EXPECTED_NO_ARGUMENT_TOOL_COUNT = 8

#: The published input surface, pinned: property occurrences at every depth and the number
#: of distinct names. A change here means the input schema changed.
EXPECTED_INPUT_PROPERTY_COUNT = 1495
EXPECTED_INPUT_PROPERTY_NAME_COUNT = 167

#: The published output surface, pinned: property occurrences at every depth and the number
#: of distinct names. A change here means the output schema changed.
EXPECTED_OUTPUT_PROPERTY_COUNT = 4547
EXPECTED_OUTPUT_PROPERTY_NAME_COUNT = 430

#: The published input naming convention (M1): lowercase words joined by underscores.
SNAKE_CASE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

#: The published output naming convention (0.6.0): camelCase, the Sophos wire names.
CAMEL_CASE_PATTERN = re.compile(r"^[a-z][a-zA-Z0-9]*$")


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


def _walk_properties(
    schema: dict[str, Any],
    node: dict[str, Any],
    path: str,
    found: list[tuple[str, str]],
    seen: frozenset[str],
) -> None:
    """Collect every property name reachable from ``node``, at every depth.

    Local ``$ref`` targets, array ``items`` and every ``allOf``/``oneOf``/``anyOf`` branch
    are followed, so a union body is scanned variant by variant instead of being skipped.
    A ``$ref`` already on the current path is not followed again, which keeps a recursive
    model from looping.

    One walker serves both conventions: the input test starts it at the request schema and
    the output test at the response schema, so the two scans cannot drift apart.
    """
    if "$ref" in node:
        target = node["$ref"].rsplit("/", 1)[-1]
        if target in seen:
            return
        seen = seen | {target}
        node = schema["$defs"][target]
    for keyword in ("allOf", "oneOf", "anyOf"):
        for branch in node.get(keyword) or ():
            _walk_properties(schema, branch, path, found, seen)
    items = node.get("items")
    if isinstance(items, dict):
        _walk_properties(schema, items, f"{path}[]", found, seen)
    properties = node.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            found.append((f"{path}.{name}", name))
            _walk_properties(schema, child, f"{path}.{name}", found, seen)


def input_properties(schema: dict[str, Any]) -> list[tuple[str, str]]:
    """Every published input property of one tool as ``(path, name)``, at every depth."""
    found: list[tuple[str, str]] = []
    _walk_properties(schema, schema, "input", found, frozenset())
    return found


def output_properties(schema: dict[str, Any]) -> list[tuple[str, str]]:
    """Every published output property of one tool as ``(path, name)``, at every depth."""
    found: list[tuple[str, str]] = []
    _walk_properties(schema, schema, "output", found, frozenset())
    return found


async def test_every_published_input_property_is_snake_case_at_every_depth() -> None:
    """M1 (0.5.0): every published MCP input property, at every depth, is snake_case.

    The scan starts at each tool's published input schema and walks the whole request
    body: local ``$ref`` targets, array ``items`` and every ``allOf``/``oneOf``/``anyOf``
    branch. The union-request tools (the address and MAC create payloads) are therefore
    covered variant by variant rather than skipped. Every property name the walk reaches
    is a name a caller can send, so every one of them must be snake_case -- a camelCase
    name one level down is exactly the split M1 removes.

    ``snake_case`` is checked as ``^[a-z][a-z0-9_]*$``: no uppercase letter, no leading
    digit or underscore. A single lowercase word such as ``from`` or ``to`` is identical
    in both conventions and passes.

    The counts are pinned deliberately. 144 tools publish a ``request`` object (152 minus
    the 8 tools whose operation declares no parameters), and the walk reaches 1,495
    property occurrences over 167 distinct names, at every depth the schema nests. A
    change to any of those numbers means the published input surface changed and must be
    acknowledged here rather than silently shrinking the scan.
    """
    tools = await tools_by_name()

    scanned: dict[str, list[tuple[str, str]]] = {}
    offending: dict[str, list[str]] = {}
    for name, tool in tools.items():
        properties = input_properties(tool.input_schema)
        scanned[name] = properties
        bad = [path for path, prop in properties if not SNAKE_CASE_PATTERN.match(prop)]
        if bad:
            offending[name] = bad

    occurrences = sum(len(properties) for properties in scanned.values())
    distinct = {prop for properties in scanned.values() for _, prop in properties}

    # The scan must reach the whole surface, not a subset of it.
    assert sum(1 for properties in scanned.values() if properties) == (
        EXPECTED_TOOL_COUNT - EXPECTED_NO_ARGUMENT_TOOL_COUNT
    )
    assert occurrences == EXPECTED_INPUT_PROPERTY_COUNT
    assert len(distinct) == EXPECTED_INPUT_PROPERTY_NAME_COUNT

    # The union-request tools are the ones a top-level-only scan skipped; prove they are in.
    for name in ("address_create_ipv4", "address_create_ipv6", "mac_address_create"):
        assert scanned[name], name

    assert offending == {}


async def test_every_published_output_property_is_camel_case_at_every_depth() -> None:
    """0.6.0: every published MCP output property, at every depth, is camelCase.

    The output convention is the Sophos wire name, because an output is a projection of
    the appliance payload. It is the mirror of the input convention above, and it needs the
    same global test: the per-domain tests only cover the domains that were converted, so
    three audit composites kept publishing snake_case output properties through the whole
    phase and CI stayed green (phase-5 review finding 1). This test walks the published
    ``outputSchema`` of all 152 tools -- local ``$ref`` targets, array ``items`` and every
    ``allOf``/``oneOf``/``anyOf`` branch -- so a snake_case name at any depth fails here
    instead of reaching a caller.

    ``camelCase`` is checked as ``^[a-z][a-zA-Z0-9]*$``: a lowercase first letter, then
    letters and digits only -- no underscore and no leading uppercase letter. A single
    lowercase word such as ``name`` or ``kind`` is identical in both conventions and passes.

    The counts are pinned deliberately. All 152 tools publish an object-rooted output
    schema, and the walk reaches 4,547 property occurrences over 430 distinct names, at
    every depth the schema nests. A change to any of those numbers means the published
    output surface changed and must be acknowledged here rather than silently shrinking the
    scan.
    """
    tools = await tools_by_name()

    scanned: dict[str, list[tuple[str, str]]] = {}
    offending: dict[str, list[str]] = {}
    for name, tool in tools.items():
        schema = tool.output_schema
        assert schema is not None, name
        properties = output_properties(schema)
        scanned[name] = properties
        bad = [path for path, prop in properties if not CAMEL_CASE_PATTERN.match(prop)]
        if bad:
            offending[name] = bad

    occurrences = sum(len(properties) for properties in scanned.values())
    distinct = {prop for properties in scanned.values() for _, prop in properties}

    # The scan must reach the whole surface, not a subset of it: every tool publishes an
    # object-rooted output, so every tool contributes at least one property.
    assert sum(1 for properties in scanned.values() if properties) == EXPECTED_TOOL_COUNT
    assert occurrences == EXPECTED_OUTPUT_PROPERTY_COUNT
    assert len(distinct) == EXPECTED_OUTPUT_PROPERTY_NAME_COUNT

    # The three audit composites are the tools that published snake_case output until
    # 0.6.0; prove the walk reaches them rather than trusting the totals.
    for name in ("audit_firewall_rules", "explain_connectivity", "find_object_usage"):
        assert scanned[name], name

    assert offending == {}
