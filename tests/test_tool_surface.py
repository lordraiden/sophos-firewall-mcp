"""Global surface invariants for the complete 112-tool server (phase-2 review finding 8).

Every other domain test asserts its own subset, so a duplicated, stray or missing tool could
pass CI unnoticed. These tests build the real server with every domain registered and assert
the invariants that only the whole surface can prove:

* the registered set is exactly the curated ``tool_map`` (145 operationIds mapped to 107
  one-to-one tools) plus the five declared composites -- 112 tools with 112 unique names;
* the full surface declares exactly 38 mutations, and ``SOPHOS_READ_ONLY_MODE`` removes
  exactly those, leaving 74 read-only tools and zero mutations;
* every tool publishes an object-rooted output schema, a non-empty input schema and the
  per-tool ``openWorldHint`` verdict from ``OPEN_WORLD_TOOLS`` (closed by default);
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

import pytest
import yaml
from mcp import Client
from mcp.server.mcpserver import MCPServer

from mcp.types import ToolAnnotations

from sophos_firewall_mcp.config import TOOL_DOMAINS, Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.server import DOMAIN_REGISTRARS, INSTRUCTIONS, create_server
from sophos_firewall_mcp.tools import (
    IP_FAMILY_DESCRIPTION,
    OPEN_WORLD_TOOLS,
    ToolKind,
    register_tool,
)

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

#: Tools whose operation declares no request parameters: they publish no arguments.
EXPECTED_NO_ARGUMENT_TOOL_COUNT = 6

#: Tools that publish no input properties at all. ``live_user_list`` is the seventh: its
#: operation declares no parameters either, but it is not in ``NO_ARGUMENT_TOOLS`` because
#: it still takes a (deliberately empty) request model.
EXPECTED_EMPTY_INPUT_TOOL_COUNT = 7

#: The published input surface, pinned: property occurrences at every depth and the number
#: of distinct names. A change here means the input schema changed.
EXPECTED_INPUT_PROPERTY_COUNT = 1322
EXPECTED_INPUT_PROPERTY_NAME_COUNT = 166

#: The published output surface, pinned: property occurrences at every depth and the number
#: of distinct names. A change here means the output schema changed.
EXPECTED_OUTPUT_PROPERTY_COUNT = 3518
EXPECTED_OUTPUT_PROPERTY_NAME_COUNT = 430

#: The eleven JSON Merge Patch update tools. A merge patch overwrites stored values, so
#: every one of them is destructive; before 0.7.1 only the two rule tools said so.
PATCH_UPDATE_TOOLS = frozenset(
    {
        "address_group_update",
        "address_group_update_fqdn",
        "address_update",
        "address_update_fqdn",
        "firewall_rule_update",
        "mac_address_update",
        "nat_rule_update",
        "network_interface_update_vlan",
        "network_user_update",
        "service_group_update",
        "service_update",
    }
)

#: The six IPsec tools whose API has no IPv6 counterpart. After the 0.7.0 collapse they are
#: the only ``_ipv4`` names left, so each description says why there is no pair.
IPV4_ONLY_IPSEC_TOOLS = frozenset(
    {
        "ipsec_connection_list_ipv4",
        "ipsec_live_connection_list_ipv4",
        "ipsec_policy_based_connection_get_ipv4",
        "ipsec_policy_based_connection_list_ipv4",
        "ipsec_route_based_connection_get_ipv4",
        "ipsec_route_based_connection_list_ipv4",
    }
)

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


async def test_the_live_suite_expects_the_read_only_surface() -> None:
    """The opt-in live suite must track the read-only surface, not a stale count.

    ``tests/live/`` is skipped without lab credentials, so a stale
    ``EXPECTED_LIVE_TOOL_COUNT`` or a stale ``LIVE_READ_TOOLS`` would only fail on the next
    lab run -- the phase-8 review found exactly that (98 expected, 74 published). This test
    runs in the default suite and pins both to the surface the server actually publishes in
    read-only mode.
    """
    from tests.live.conftest import EXPECTED_LIVE_TOOL_COUNT
    from tests.live.test_live_reads import LIVE_READ_TOOLS

    read_only = await tools_by_name(read_only=True)

    assert EXPECTED_LIVE_TOOL_COUNT == EXPECTED_READ_ONLY_TOOL_COUNT
    assert len(read_only) == EXPECTED_LIVE_TOOL_COUNT
    assert set(LIVE_READ_TOOLS) == set(read_only)
    assert len(LIVE_READ_TOOLS) == len(set(LIVE_READ_TOOLS)) == EXPECTED_LIVE_TOOL_COUNT


# -- Union argument errors (phase-8 review Low 4) --------------------------------------
#
# A union request publishes a root ``oneOf``/``anyOf``, so pydantic reports every variant's
# errors at once: the model saw contradictory rules ("ip_family must be one of 'ipv4' ...
# ip_family must be one of 'ipv6'") and the 300-character cap truncated the dump mid-word.
# The union argument model resolves the discriminator first and reports one line.


async def test_a_bad_discriminator_is_reported_once_with_the_accepted_values() -> None:
    async with Client(make_server()) as client:
        result = await client.call_tool("firewall_rule_create", {"ip_family": "ipv9", "name": "x"})

    assert result.is_error is True
    text = result.content[0].text
    assert "ip_family must be one of 'ipv4', 'ipv6'" in text
    # One discriminator rule, not one per variant, and no required-field noise.
    assert text.count("ip_family must be one of") == 1
    assert "source_zones is required" not in text


async def test_a_missing_discriminator_names_the_accepted_values() -> None:
    async with Client(make_server()) as client:
        result = await client.call_tool("address_create", {"ip_family": "ipv4"})

    assert result.is_error is True
    text = result.content[0].text
    assert "type is required" in text
    assert "accepted values are 'ipv4Address'" in text
    assert "ipv4_address is required" not in text


async def test_a_valid_discriminator_reports_only_the_selected_variant() -> None:
    async with Client(make_server()) as client:
        result = await client.call_tool(
            "address_create",
            {"ip_family": "ipv4", "type": "ipv4Address", "name": "x"},
        )

    assert result.is_error is True
    text = result.content[0].text
    assert "ipv4_address is required" in text
    # The other seven variants' required fields are not enumerated.
    assert "ipv4_network_address" not in text
    assert "ipv6_address" not in text
    assert text.count("is required") == 1


async def test_an_undiscriminated_union_offers_the_alternatives() -> None:
    async with Client(make_server()) as client:
        result = await client.call_tool("mac_address_create", {"name": "x"})

    assert result.is_error is True
    assert "mac_address is required or mac_addresses is required" in result.content[0].text


def test_the_instructions_state_the_anyof_exception() -> None:
    """Low 3: the one undiscriminated union publishes ``anyOf``, not ``oneOf``."""
    assert "`oneOf`" in INSTRUCTIONS
    assert "`anyOf`" in INSTRUCTIONS
    assert "mac_address_create" in INSTRUCTIONS


async def test_a_bad_secondary_selector_names_that_field() -> None:
    """M7: ``address_create`` is discriminated by ``type`` but also pins ``ip_family``.

    A caller that sends only a bad ``ip_family`` must be told about ``ip_family``, not
    about a ``type`` it never sent.
    """
    async with Client(make_server()) as client:
        result = await client.call_tool("address_create", {"ip_family": "ipv5", "name": "x"})

    assert result.is_error is True
    text = result.content[0].text
    assert "ip_family must be one of 'ipv4', 'ipv6'" in text
    assert "type is required" not in text


def test_the_instructions_mention_the_resources_and_prompts() -> None:
    """L7: a model that reads only ``instructions`` must learn the other two primitives."""
    assert "sophos://conventions" in INSTRUCTIONS
    for name in ("audit_firewall", "explain_flow", "find_unused_objects"):
        assert name in INSTRUCTIONS


async def test_every_patch_update_is_classified_destructive() -> None:
    """M1: a JSON Merge Patch overwrites stored values, so it is not an additive update.

    The spec defines ``destructiveHint`` as "may perform destructive updates"; the same
    operation class must not be classified two ways, or a client that gates on the hint
    treats an object update as safe and a rule update as dangerous for no principled
    reason.
    """
    tools = await tools_by_name()

    assert PATCH_UPDATE_TOOLS <= set(tools)
    for name in sorted(PATCH_UPDATE_TOOLS):
        annotations = tools[name].annotations
        assert annotations is not None, name
        assert annotations.read_only_hint is False, name
        assert annotations.destructive_hint is True, name
        assert annotations.idempotent_hint is True, name


def _required_ip_family_properties(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Every required ``ip_family`` property in ``schema``, at every depth.

    The union variants are reached through ``$defs``: their ``ip_family`` is a ``const``
    that selects the family, so it is the same argument one level down.
    """
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        properties = node.get("properties")
        if isinstance(properties, dict) and "ip_family" in properties:
            if "ip_family" in (node.get("required") or ()):
                found.append(properties["ip_family"])
        for definition in (node.get("$defs") or {}).values():
            walk(definition)

    walk(schema)
    return found


async def test_every_required_ip_family_publishes_the_shared_description() -> None:
    """M2: ``ip_family`` is the same argument on every tool, so it reads the same way.

    The six firewall tools published no description at all and the other tools published
    thirteen different ones. The published ``inputSchema`` is the model's only description
    of a parameter, so the description is normalised in one place.
    """
    tools = await tools_by_name()

    root_level = 0
    for name, tool in tools.items():
        schema = tool.input_schema
        root_properties = schema.get("properties") or {}
        if "ip_family" in root_properties and "ip_family" in (schema.get("required") or ()):
            root_level += 1
        for property_schema in _required_ip_family_properties(schema):
            assert property_schema.get("description") == IP_FAMILY_DESCRIPTION, name

    # 32 tools publish a required root-level ``ip_family``; the union tools carry it in
    # their variants instead, and those are covered by the loop above.
    assert root_level == 32


async def test_the_optional_ip_family_composites_keep_their_own_description() -> None:
    """M2: the three audit composites mean something different, so they are not normalised."""
    tools = await tools_by_name()

    for name in ("audit_firewall_rules", "explain_connectivity", "find_object_usage"):
        properties = tools[name].input_schema["properties"]
        assert "ip_family" in properties, name
        assert "ip_family" not in (tools[name].input_schema.get("required") or ()), name
        description = properties["ip_family"].get("description")
        assert description and description != IP_FAMILY_DESCRIPTION, name


async def test_the_ipv4_only_ipsec_tools_say_so() -> None:
    """L10: after the 0.7.0 collapse these are the only ``_ipv4`` names left."""
    tools = await tools_by_name()

    assert IPV4_ONLY_IPSEC_TOOLS <= set(tools)
    for name in sorted(IPV4_ONLY_IPSEC_TOOLS):
        assert "no IPv6 counterpart" in tools[name].description, name


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
        # Arguments are flat: a tool whose operation declares no request parameters
        # publishes no properties, and every other tool publishes its own fields.
        assert "request" not in schema.get("properties", {}), name
        assert "ctx" not in schema.get("properties", {}), name

        annotations = tool.annotations
        assert annotations is not None, name
        # The tool-level ``title`` is the one the spec's display precedence reads first, so
        # the annotations do not duplicate it.
        assert tool.title, name
        assert annotations.title is None, name
        assert annotations.open_world_hint is (name in OPEN_WORLD_TOOLS), name


async def test_the_open_world_set_is_exactly_the_documented_tools() -> None:
    """Pin the judgment: changing the set must be a deliberate, reviewed edit.

    ``openWorldHint`` describes the tool's interaction domain. This server talks to one
    configured appliance, so a tool that reads or writes that appliance's own
    configuration is closed. Only a result produced by entities the appliance does not own
    -- DHCP clients, live users, live IPsec peers, the cellular carrier, the vendor's DNS
    Protection verdict -- is open.
    """
    assert OPEN_WORLD_TOOLS == {
        "dhcp_lease_list",
        "ipsec_live_connection_list_ipv4",
        "live_user_disconnect",
        "live_user_list",
        "network_status_cellular_wan",
        "network_status_dns_protection",
    }


async def test_the_open_world_set_names_only_registered_tools() -> None:
    """A rename must not leave a stale entry behind: the set is checked against the surface."""
    tools = await tools_by_name()

    assert OPEN_WORLD_TOOLS <= set(tools)


async def test_an_explicit_open_world_hint_overrides_the_per_tool_default() -> None:
    """A domain module may still declare the hint itself; the table is only the default."""
    server = MCPServer[AppContext]("open-world-override")

    @register_tool(
        server,
        read_only=False,
        kind=ToolKind.READ,
        name="synthetic_closed_read",
        title="Synthetic closed read",
        description="A read-only tool that declares a closed interaction domain explicitly.",
        annotations=ToolAnnotations(open_world_hint=False),
    )
    async def synthetic_closed_read() -> dict[str, bool]:
        return {"ok": True}

    @register_tool(
        server,
        read_only=False,
        kind=ToolKind.READ,
        name="synthetic_open_read",
        title="Synthetic open read",
        description="A read-only tool that declares an open interaction domain explicitly.",
        annotations=ToolAnnotations(open_world_hint=True),
    )
    async def synthetic_open_read() -> dict[str, bool]:
        return {"ok": True}

    tools = {tool.name: tool for tool in await server.list_tools()}

    assert tools["synthetic_closed_read"].annotations.open_world_hint is False
    assert tools["synthetic_open_read"].annotations.open_world_hint is True


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

    The counts are pinned deliberately. 105 of the 112 tools publish at least one input
    property (the other 7 declare no parameters), and the walk reaches 1,322 property
    occurrences over 166 distinct names, at every depth the schema nests. A change to any
    of those numbers means the published input surface changed and must be acknowledged
    here rather than silently shrinking the scan.
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
        EXPECTED_TOOL_COUNT - EXPECTED_EMPTY_INPUT_TOOL_COUNT
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


# -- Domain selection (SOPHOS_TOOL_DOMAINS) --------------------------------------------
#
# ``SOPHOS_TOOL_DOMAINS`` narrows the published surface to the domains a deployment needs.
# The exact tools of every domain are pinned here, because the partition is the
# specification: a tool that moves between domains, or a new tool, has to be recorded
# deliberately instead of silently changing what a restricted deployment publishes.

#: The exact tools each domain registers, in registration order.
DOMAIN_TOOL_NAMES: dict[str, tuple[str, ...]] = {
    "firewall": (
        "firewall_rule_list",
        "firewall_rule_get",
        "firewall_rule_create",
        "firewall_rule_update",
        "firewall_rule_delete",
        "firewall_rule_move",
        "firewall_rule_set_enabled",
        "firewall_rule_clone",
    ),
    "nat": (
        "nat_rule_list",
        "nat_rule_get",
        "nat_rule_create",
        "nat_rule_update",
        "nat_rule_delete",
        "nat_rule_move",
    ),
    "objects": (
        "address_list",
        "address_get",
        "address_create",
        "address_update",
        "address_delete",
        "address_list_fqdn",
        "address_get_fqdn",
        "address_create_fqdn",
        "address_update_fqdn",
        "address_delete_fqdn",
        "address_group_list",
        "address_group_get",
        "address_group_create",
        "address_group_update",
        "address_group_delete",
        "address_group_list_fqdn",
        "address_group_get_fqdn",
        "address_group_create_fqdn",
        "address_group_update_fqdn",
        "address_group_delete_fqdn",
        "mac_address_list",
        "mac_address_get",
        "mac_address_create",
        "mac_address_update",
        "mac_address_delete",
        "country_group_list",
        "country_group_get",
        "service_list",
        "service_get",
        "service_create",
        "service_update",
        "service_delete",
        "service_group_list",
        "service_group_get",
        "service_group_create",
        "service_group_update",
        "service_group_delete",
    ),
    "users": (
        "user_list",
        "network_user_list",
        "network_user_get",
        "network_user_create",
        "network_user_update",
        "network_user_delete",
        "live_user_list",
        "live_user_disconnect",
    ),
    "network": (
        "network_interface_list",
        "network_interface_get",
        "network_interface_create_vlan",
        "network_interface_update_vlan",
        "network_interface_delete_vlan",
        "zone_list",
        "zone_get",
        "gateway_list",
        "wan_gateway_list",
        "wan_gateway_get",
        "custom_gateway_list",
        "custom_gateway_get",
        "unicast_route_list",
        "unicast_route_get",
        "sdwan_route_list",
        "sdwan_route_get",
        "dhcp_server_list",
        "dhcp_server_get",
        "dhcp_lease_list",
        "dhcp_relay_list",
        "dhcp_relay_get",
        "dns_settings_get",
        "dns_host_entry_list",
        "dns_host_entry_get",
        "dns_request_route_list",
        "dns_request_route_get",
        "static_neighbor_list",
        "static_neighbor_get",
        "ipsec_profile_list",
        "ipsec_profile_get",
        "ipsec_failover_group_list",
        "ipsec_failover_group_get",
        "ipsec_connection_list_ipv4",
        "ipsec_policy_based_connection_list_ipv4",
        "ipsec_policy_based_connection_get_ipv4",
        "ipsec_route_based_connection_list_ipv4",
        "ipsec_route_based_connection_get_ipv4",
        "ipsec_live_connection_list_ipv4",
        "ipsec_remote_access_settings_get",
        "sslvpn_remote_access_policy_list",
        "sslvpn_remote_access_policy_get",
        "sslvpn_bookmark_group_list",
        "sslvpn_bookmark_group_get",
        "sslvpn_bookmark_list",
        "sslvpn_bookmark_get",
        "sslvpn_clientless_policy_list",
        "sslvpn_clientless_policy_get",
        "sslvpn_global_settings_get",
        "network_status_dns_protection",
        "network_status_cellular_wan",
    ),
    "audit": ("audit_firewall_rules", "explain_connectivity", "find_object_usage"),
}

#: How many of each domain's tools are read-only; the rest are mutations.
DOMAIN_READ_ONLY_COUNTS: dict[str, int] = {
    "firewall": 2,
    "nat": 2,
    "objects": 16,
    "users": 4,
    "network": 47,
    "audit": 3,
}

#: The domain selections the tests exercise, including the two the issue suggests.
DOMAIN_SELECTIONS: tuple[tuple[str, ...], ...] = (
    ("firewall",),
    ("nat",),
    ("objects",),
    ("users",),
    ("network",),
    ("audit",),
    ("firewall", "nat"),
    ("firewall", "nat", "objects", "network", "audit"),
    ("firewall", "nat", "objects", "users", "network", "audit"),
)


def make_domain_server(
    domains: tuple[str, ...], *, read_only: bool = False
) -> MCPServer[AppContext]:
    """The real server with exactly *domains* registered, through the real registrars."""
    return create_server(
        make_settings(read_only=read_only),
        domains=[DOMAIN_REGISTRARS[name] for name in domains],
    )


def expected_names(domains: tuple[str, ...]) -> list[str]:
    """The exact tool names *domains* publish, in canonical registration order."""
    return [
        name for domain in TOOL_DOMAINS if domain in domains for name in DOMAIN_TOOL_NAMES[domain]
    ]


def test_the_domain_partition_covers_the_complete_surface() -> None:
    """The six domains partition the 112 tools: no gap, no overlap, no stray name."""
    assert tuple(DOMAIN_TOOL_NAMES) == TOOL_DOMAINS
    assert tuple(DOMAIN_READ_ONLY_COUNTS) == TOOL_DOMAINS
    every = [name for domain in TOOL_DOMAINS for name in DOMAIN_TOOL_NAMES[domain]]
    assert len(every) == len(set(every)) == EXPECTED_TOOL_COUNT
    assert sum(DOMAIN_READ_ONLY_COUNTS.values()) == EXPECTED_READ_ONLY_TOOL_COUNT
    assert EXPECTED_TOOL_COUNT - sum(DOMAIN_READ_ONLY_COUNTS.values()) == EXPECTED_MUTATION_COUNT


async def test_the_unset_setting_publishes_the_complete_surface_in_the_same_order() -> None:
    """Backward compatibility: no setting means exactly the 112 tools, in the same order."""
    server = create_server(make_settings())
    names = [tool.name for tool in await server.list_tools()]

    assert names == expected_names(TOOL_DOMAINS)
    assert len(names) == EXPECTED_TOOL_COUNT


@pytest.mark.parametrize("domains", DOMAIN_SELECTIONS)
async def test_a_selected_domain_set_publishes_exactly_its_tools(
    domains: tuple[str, ...],
) -> None:
    """A selection publishes the union of its domains and nothing from the others."""
    server = make_domain_server(domains)
    names = [tool.name for tool in await server.list_tools()]

    assert names == expected_names(domains)
    assert len(names) == sum(len(DOMAIN_TOOL_NAMES[domain]) for domain in domains)
    excluded = set(DOMAIN_TOOL_NAMES[name] for name in TOOL_DOMAINS if name not in domains)
    assert not set(names) & {tool for group in excluded for tool in group}


@pytest.mark.parametrize("domains", DOMAIN_SELECTIONS)
async def test_read_only_mode_removes_the_mutations_of_the_selected_domains(
    domains: tuple[str, ...],
) -> None:
    """The two filters compose: selection chooses the domains, read-only drops mutations."""
    writable = {tool.name: tool for tool in await make_domain_server(domains).list_tools()}
    read_only = {
        tool.name: tool for tool in await make_domain_server(domains, read_only=True).list_tools()
    }

    mutations = mutation_names(writable)
    expected_read_only = sum(DOMAIN_READ_ONLY_COUNTS[domain] for domain in domains)

    assert len(read_only) == expected_read_only
    assert set(read_only) == set(writable) - mutations
    assert mutation_names(read_only) == set()
    assert len(mutations) == len(writable) - expected_read_only


async def test_the_registration_order_does_not_depend_on_the_operator_order() -> None:
    """A selection is normalised, so two spellings publish the same catalog in one order."""
    forward = create_server(
        Settings(
            host=HOST,
            api_key=KEY,
            verify_ssl=False,
            timeout=5.0,
            tool_domains=("firewall", "nat", "audit"),
        )
    )
    reversed_server = create_server(
        Settings(
            host=HOST,
            api_key=KEY,
            verify_ssl=False,
            timeout=5.0,
            tool_domains=("audit", "nat", "firewall"),
        )
    )

    assert [tool.name for tool in await forward.list_tools()] == [
        tool.name for tool in await reversed_server.list_tools()
    ]


async def test_audit_registers_without_any_other_domain() -> None:
    """The audit composites call adapter classes, not registered tools.

    ``tools/audit.py`` imports ``FirewallRuleAdapter``, ``NatAdapter``, ``ObjectsAdapter``,
    ``ServicesAdapter`` and ``NetworkAdapter`` and instantiates them from the request
    context, so ``audit`` alone publishes all three composites with complete schemas. This
    is why the domain dependency model is empty.
    """
    server = make_domain_server(("audit",))
    tools = list(await server.list_tools())

    assert [tool.name for tool in tools] == list(DOMAIN_TOOL_NAMES["audit"])
    for tool in tools:
        assert tool.input_schema, tool.name
        assert tool.output_schema is not None, tool.name
