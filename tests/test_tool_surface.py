"""Global surface invariants for the complete 112-tool server (phase-2 review finding 8).

Every other domain test asserts its own subset, so a duplicated, stray or missing tool could
pass CI unnoticed. These tests build the real server with every domain registered and assert
the invariants that only the whole surface can prove:

* the registered set is exactly the curated ``tool_map`` (145 operationIds) plus the seven
  declared composites -- 112 tools with 112 unique names;
* the full surface declares exactly 38 mutations, and ``SOPHOS_READ_ONLY_MODE`` removes
  exactly those, leaving 74 read-only tools and zero mutations;
* every tool publishes an object-rooted output schema, a non-empty input schema and
  ``openWorldHint=true``;
* every published input property name, at every depth of the request body, is snake_case
  (M1, the 0.5.0 breaking change);
* every published output property name, at every depth of the response body, is camelCase
  (the 0.6.0 output contract);
* no internal planning marker (a decision ID, any reference to "the contract", "the lab
  appliance", an issue number, a dated live observation) reaches any published description,
  title, annotations, schema or the server instructions (M4).

The curated file is read directly: it is the human decision record the server is built from,
and ``tests/test_coverage.py`` already validates its structure against the contract.
"""

from __future__ import annotations

import json
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
EXPECTED_TOOL_COUNT = 112
EXPECTED_READ_ONLY_TOOL_COUNT = 74
EXPECTED_MUTATION_COUNT = 38
EXPECTED_TOOL_MAP_COUNT = 145
EXPECTED_COMPOSITE_COUNT = 5

#: Tools whose operation declares no request parameters: they publish no ``request``.
EXPECTED_NO_ARGUMENT_TOOL_COUNT = 6

#: The published input surface, pinned: property occurrences at every depth and the number
#: of distinct names. A change here means the input schema changed.
EXPECTED_INPUT_PROPERTY_COUNT = 1428
EXPECTED_INPUT_PROPERTY_NAME_COUNT = 167

#: The published output surface, pinned: property occurrences at every depth and the number
#: of distinct names. A change here means the output schema changed.
EXPECTED_OUTPUT_PROPERTY_COUNT = 3518
EXPECTED_OUTPUT_PROPERTY_NAME_COUNT = 430

#: The published input naming convention (M1): lowercase words joined by underscores.
SNAKE_CASE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

#: The published output naming convention (0.6.0): camelCase, the Sophos wire names.
CAMEL_CASE_PATTERN = re.compile(r"^[a-z][a-zA-Z0-9]*$")

#: Internal planning markers that must never reach the published surface (M4).
#:
#: Tool descriptions, titles, annotations, input schemas, output schemas and the server
#: instructions are all model-facing: the MCP specification tells clients to treat tool
#: definitions as untrusted input, and a model reads them as instructions. A decision ID
#: (``M11``), a reference to the checked-in OpenAPI file ("the contract", "whose contract",
#: "Query contract", "REST contract"), a note about the owner's lab ("the lab appliance"),
#: a GitHub issue number or a dated live observation is meaningless to a model, dilutes the
#: sentence that matters, and discloses internal process to anyone who runs ``tools/list``.
#: The rationale for those decisions belongs in the Python docstrings and the planning
#: documents, not in the published schema.
#:
#: The contract pattern is the bare word, not one phrase: the earlier exact-phrase pattern
#: let ten published strings through in variant forms ("whose contract declares", "Query
#: contract of", "contract default", "the REST contract", "the IPv6 contract"), so the
#: guard now fails on any occurrence and the published text says "the API" instead.
INTERNAL_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("decision id (M<n>)", re.compile(r"\bM\d+\b")),
    ("'contract'", re.compile(r"\bcontract", re.IGNORECASE)),
    ("'lab appliance'", re.compile(r"\blab appliance\b", re.IGNORECASE)),
    ("'issue #'", re.compile(r"\bissue #", re.IGNORECASE)),
    ("'live observation'", re.compile(r"\blive observation\b", re.IGNORECASE)),
)


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

    The counts are pinned deliberately. 106 tools publish a ``request`` object (112 minus
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
    for name in ("address_create", "mac_address_create"):
        assert scanned[name], name

    assert offending == {}


async def test_every_published_output_property_is_camel_case_at_every_depth() -> None:
    """0.6.0: every published MCP output property, at every depth, is camelCase.

    The output convention is the Sophos wire name, because an output is a projection of
    the appliance payload. It is the mirror of the input convention above, and it needs the
    same global test: the per-domain tests only cover the domains that were converted, so
    three audit composites kept publishing snake_case output properties through the whole
    phase and CI stayed green (phase-5 review finding 1). This test walks the published
    ``outputSchema`` of all 112 tools -- local ``$ref`` targets, array ``items`` and every
    ``allOf``/``oneOf``/``anyOf`` branch -- so a snake_case name at any depth fails here
    instead of reaching a caller.

    ``camelCase`` is checked as ``^[a-z][a-zA-Z0-9]*$``: a lowercase first letter, then
    letters and digits only -- no underscore and no leading uppercase letter. A single
    lowercase word such as ``name`` or ``kind`` is identical in both conventions and passes.

    The counts are pinned deliberately. All 112 tools publish an object-rooted output
    schema, and the walk reaches 3,518 property occurrences over 430 distinct names, at
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


def _marker_snippet(text: str, match: re.Match[str]) -> str:
    """A one-line window around ``match`` so a failure names the offending sentence."""
    start = max(0, match.start() - 40)
    end = min(len(text), match.end() + 40)
    return " ".join(text[start:end].split())


async def test_the_published_surface_carries_no_internal_markers() -> None:
    """M4: no internal planning marker reaches the model-facing surface.

    Every string a tool publishes is read by the model, and the MCP specification tells
    clients to treat tool definitions as untrusted input. Internal process text therefore
    does not belong there: a decision ID (``M11``), a reference to the checked-in OpenAPI
    file ("the contract" and its variants), a note about the owner's lab ("the lab
    appliance"), a GitHub issue number or a dated live observation is meaningless to a
    model, dilutes the sentence that matters, and discloses internal process to anyone who
    runs ``tools/list``.

    The sweep is deliberately global and strict: it walks the description, the title, the
    annotations, the input schema and the output schema of all 112 tools plus the server
    instructions, with no allowlist, so a single reintroduced marker fails here instead of
    reaching a caller. The counts are pinned so the scan cannot silently shrink to a subset
    of the surface.

    The schemas are scanned as serialized JSON, which is what the client receives: a
    marker in a ``$defs`` model docstring, a field description or an enum description is
    published text even though it never appears in the tool's own ``description``. The
    title and annotations are scanned too: they are published on every tool object and the
    earlier sweep skipped them.
    """
    server = make_server()
    tools = list(await server.list_tools())
    instructions = server.instructions

    # The sweep must reach the whole surface, not a subset of it.
    assert len(tools) == EXPECTED_TOOL_COUNT
    assert isinstance(instructions, str) and instructions.strip()

    blobs: dict[str, str] = {"<server instructions>": instructions}
    for tool in tools:
        assert tool.description, tool.name
        assert tool.title, tool.name
        assert tool.annotations is not None, tool.name
        assert tool.input_schema, tool.name
        assert tool.output_schema is not None, tool.name
        blobs[f"{tool.name} description"] = tool.description
        blobs[f"{tool.name} title"] = tool.title
        blobs[f"{tool.name} annotations"] = json.dumps(
            tool.annotations.model_dump(), sort_keys=True, default=str
        )
        blobs[f"{tool.name} inputSchema"] = json.dumps(tool.input_schema, sort_keys=True)
        blobs[f"{tool.name} outputSchema"] = json.dumps(tool.output_schema, sort_keys=True)

    # 112 tools x 5 published strings, plus the server instructions.
    assert len(blobs) == EXPECTED_TOOL_COUNT * 5 + 1

    offenders: list[str] = []
    for where, text in blobs.items():
        for label, pattern in INTERNAL_MARKERS:
            for match in pattern.finditer(text):
                offenders.append(f"{where} [{label}]: ...{_marker_snippet(text, match)}...")

    if offenders:
        report = "\n".join(offenders)
        raise AssertionError(
            f"{len(offenders)} internal marker(s) reached the published surface:\n{report}"
        )
