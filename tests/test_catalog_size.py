"""Catalog-size and output-schema invariants for the published ``tools/list``.

The catalog is the largest thing a client loads, so its size is measured and pinned here
rather than left to drift. The tests read the real server's published ``tools/list``:

* the total wire size stays within a measured budget, and the four-way split adds up;
* the output-schema trim removes only JSON Schema annotations (``description`` and
  ``default``), so no required property, enum, nullability, alias or ``$ref`` is lost;
* a representative instance still validates against every published output schema, which
  is the ``structuredContent`` contract the SDK enforces against the output model;
* the catalog is one page because the pinned SDK's ``MCPServer`` discards
  ``PaginatedRequestParams`` (documented below);
* the model-facing descriptions added for the tool-contract pass survive the trim.

The measurement script is ``scripts/measure_catalog.py``; run it before and after a
catalog change and compare the totals.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from mcp import Client
from mcp.server.mcpserver.utilities.func_metadata import StrictJsonSchema, _inline_root_ref
from mcp.types import ListToolsResult
from pydantic import TypeAdapter

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.models.common import trim_published_output_schema
from sophos_firewall_mcp.server import create_server

#: ``jsonschema`` is a transitive dependency of ``mcp``, not a declared dev dependency;
#: skip the validation test rather than fail collection when it is absent.
jsonschema = pytest.importorskip("jsonschema")

#: The measured total wire size of the catalog on the commit that introduced the trim.
#: The budget below allows 10% growth, which is enough for a new tool or a reworded
#: description but not for a schema regression.
MEASURED_CATALOG_BYTES = 493_965
CATALOG_GROWTH_LIMIT = 0.10

#: The sixteen getter sentences added by the tool-contract pass. The catalog trim must
#: not touch tool descriptions, so these are re-asserted here as a guard.
GETTER_SENTENCES = (
    "Returns the zone type, its description and the firewall services allowed for it.",
    "Returns the key-exchange and authentication mode, the phase-1 and phase-2 proposals "
    "and the dead-peer-detection settings.",
    "Returns the domain, the reverse-resolution flag and the host records with their TTL, "
    "weight and publish-on-WAN settings.",
    "Returns the domain and the DNS servers it is forwarded to.",
    "Returns the member connections, the liveness checks and the failback and alert settings.",
    "Returns the member users and groups and the bookmarks and bookmark groups the policy "
    "publishes.",
    "Returns the policy members, the full-tunnel flag, the permitted IPv4 and IPv6 networks "
    "and the idle-peer-detection settings.",
    "Returns the group's member bookmarks.",
    "Returns the gateway type, profile, tunnel interface, protected networks and activation "
    "state.",
    "Returns the connection type, gateway type, profile, protected networks and activation "
    "state.",
    "Returns the enabled state, interface, address pools and client reservations, plus the "
    "lease lifetimes, DNS/WINS servers and DHCP options.",
    "Returns the gateway role and weight, its interface and address, the backup activation "
    "settings and the health-check rules.",
    "Returns the service, application and user selectors, the link selection, the DSCP "
    "marking and the source and destination networks.",
    "Returns the interface, zone, address and health-check settings.",
    "Returns the destination and prefix, the gateway, interface, metric and administrative "
    "distance.",
    "Returns the IP address, MAC address and interface of the entry.",
)


def _settings() -> Settings:
    """Valid settings for a server that never contacts the appliance."""
    return Settings(
        host="fw.example.com",
        port=443,
        api_key="sfos_test_key_0123456789abcdef",
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=False,
    )


def _compact(value: Any) -> str:
    """Serialize ``value`` the way the wire does: compact, sorted and UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _untrimmed_output_schema(tool: Any) -> dict[str, Any]:
    """The output schema the SDK derives from the tool's output model, before the trim.

    The SDK builds the published schema with ``StrictJsonSchema`` and inlines the root
    ``$ref``; reproducing that here lets the test prove the published schema is exactly
    that schema with the annotations removed.
    """
    model = tool.fn_metadata.output_model
    assert model is not None, tool.name
    return _inline_root_ref(TypeAdapter(model).json_schema(schema_generator=StrictJsonSchema))


def _strip_annotations(node: Any) -> None:
    """Remove ``description`` and ``default`` from every schema node, in place."""
    if not isinstance(node, dict):
        return
    node.pop("description", None)
    node.pop("default", None)
    for keyword in ("items", "additionalProperties", "not", "contains", "propertyNames"):
        child = node.get(keyword)
        if isinstance(child, dict):
            _strip_annotations(child)
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        branches = node.get(keyword)
        if isinstance(branches, list):
            for branch in branches:
                _strip_annotations(branch)
    properties = node.get("properties")
    if isinstance(properties, dict):
        for child in properties.values():
            _strip_annotations(child)
    definitions = node.get("$defs")
    if isinstance(definitions, dict):
        for child in definitions.values():
            _strip_annotations(child)


def _sample(schema: dict[str, Any], root: dict[str, Any], depth: int = 0) -> Any:
    """Build one representative instance for ``schema``.

    The instance is not a real appliance response; it is the smallest value that satisfies
    the schema's required properties, enums, consts, formats and array bounds. Validating
    it against the published schema proves the schema still accepts the shape the output
    model produces.
    """
    if depth > 20:
        return None
    if "$ref" in schema:
        target = schema["$ref"].rsplit("/", 1)[-1]
        return _sample(root["$defs"][target], root, depth + 1)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    for keyword in ("anyOf", "oneOf"):
        if keyword in schema:
            for branch in schema[keyword]:
                if branch.get("type") == "null":
                    continue
                return _sample(branch, root, depth + 1)
    node_type = schema.get("type")
    if isinstance(node_type, list):
        node_type = next((value for value in node_type if value != "null"), "null")
    if node_type == "object":
        properties = schema.get("properties") or {}
        return {
            name: _sample(properties.get(name, {}), root, depth + 1)
            for name in schema.get("required") or ()
        }
    if node_type == "array":
        item = schema.get("items") or {}
        return [_sample(item, root, depth + 1) for _ in range(schema.get("minItems", 0))]
    if node_type == "string":
        if "[0-9a-fA-F]{2}" in schema.get("pattern", ""):
            return "00:11:22:33:44:55"
        return {
            "ipv4": "192.0.2.1",
            "ipv6": "2001:db8::1",
            "date-time": "2026-01-01T00:00:00Z",
            "uuid": "00000000-0000-0000-0000-000000000000",
        }.get(schema.get("format", ""), "x")
    if node_type == "integer":
        return 1
    if node_type == "number":
        return 1.0
    if node_type == "boolean":
        return True
    return None


async def test_the_catalog_stays_within_the_measured_budget() -> None:
    """A significant unintended catalog growth fails here instead of reaching clients."""
    server = create_server(_settings())
    tools = list(await server.list_tools())
    input_bytes = sum(len(_compact(tool.input_schema)) for tool in tools)
    output_bytes = sum(len(_compact(tool.output_schema)) for tool in tools)
    description_bytes = sum(len(tool.description or "") for tool in tools)
    result = ListToolsResult(tools=tools)
    wire = (
        '{"jsonrpc":"2.0","id":1,"result":'
        + result.model_dump_json(by_alias=True, exclude_none=True)
        + "}\n"
    )
    total = len(wire.encode("utf-8"))
    envelope = total - input_bytes - output_bytes - description_bytes

    assert len(tools) == 112
    assert input_bytes + output_bytes + description_bytes + envelope == total
    assert total <= int(MEASURED_CATALOG_BYTES * (1 + CATALOG_GROWTH_LIMIT)), (
        f"the catalog grew to {total} bytes; the measured budget is "
        f"{MEASURED_CATALOG_BYTES} bytes plus {CATALOG_GROWTH_LIMIT:.0%}"
    )
    # The output schemas are the part the trim targets; a regression there is the most
    # likely cause of growth, so it gets its own bound.
    assert output_bytes <= 260_000, output_bytes


async def test_the_output_schema_trim_is_annotation_only() -> None:
    """The published schema is the model's schema with only annotations removed.

    The SDK validates ``structuredContent`` against the output model, not the published
    schema, so the trim cannot change runtime validation. This test proves the published
    schema is exactly the derived schema after :func:`trim_published_output_schema`, and
    that removing ``description``/``default`` from both leaves them identical: no
    ``required``, ``enum``, ``const``, ``type``, ``format``, ``$ref`` or property is lost.
    """
    server = create_server(_settings())
    for tool in server._tool_manager.list_tools():
        published = tool.fn_metadata.output_schema
        assert published is not None, tool.name
        untrimmed = _untrimmed_output_schema(tool)
        expected = copy.deepcopy(untrimmed)
        trim_published_output_schema(expected)
        assert published == expected, tool.name

        structural_published = copy.deepcopy(published)
        structural_untrimmed = copy.deepcopy(untrimmed)
        _strip_annotations(structural_published)
        _strip_annotations(structural_untrimmed)
        assert structural_published == structural_untrimmed, tool.name


async def test_structured_content_still_validates_against_every_output_schema() -> None:
    """A representative instance validates against every published output schema.

    The instance is generated from the untrimmed schema (the shape the output model
    produces) and validated against the published schema. The two differ only in
    annotations, so this is the ``structuredContent`` contract the SDK enforces.
    """
    server = create_server(_settings())
    for tool in server._tool_manager.list_tools():
        published = tool.fn_metadata.output_schema
        assert published is not None, tool.name
        untrimmed = _untrimmed_output_schema(tool)
        instance = _sample(untrimmed, untrimmed)
        jsonschema.validate(instance, published)


async def test_the_catalog_is_one_page_because_the_sdk_has_no_pagination_hook() -> None:
    """``tools/list`` returns every tool in one page; the SDK discards the cursor.

    The pinned SDK's ``MCPServer._handle_list_tools`` accepts ``PaginatedRequestParams``
    and ignores it: it returns ``ListToolsResult(tools=await self.list_tools())`` with no
    ``next_cursor``. ``ListToolsResult.next_cursor`` and ``PaginatedRequestParams.cursor``
    exist, so the protocol supports pagination, but ``MCPServer`` exposes no public hook to
    supply a page: ``_handle_list_tools`` and ``_lowlevel_server`` are private, and the
    only public interception point is ``ServerMiddleware``, which is a generic workaround
    rather than native pagination. This test pins the single-page behaviour and will fail
    when the SDK grows a supported hook, which is the signal to implement pagination.

    Upstream path: give ``MCPServer`` a public ``list_tools_page(cursor, page_size)`` (or
    pass ``params`` through to an overridable ``list_tools``) and return
    ``ListToolsResult(tools=..., next_cursor=...)``. The server would then slice the
    registry and emit an opaque cursor; no partial result is faked here.
    """
    server = create_server(_settings())
    async with Client(server) as client:
        result = await client.list_tools()

    assert result.next_cursor is None
    assert len(result.tools) == 112


async def test_the_model_facing_descriptions_survive_the_trim() -> None:
    """The catalog trim touches output schemas only; tool descriptions are unchanged."""
    server = create_server(_settings())
    tools = {tool.name: tool for tool in await server.list_tools()}
    descriptions = "\n".join(tool.description or "" for tool in tools.values())

    for sentence in GETTER_SENTENCES:
        assert sentence in descriptions, sentence

    # The address/address-group selector sentences from the same pass.
    assert "`type` selects the variant" in tools["address_create"].description
    assert "`ip_family` selects the variant" in tools["address_update"].description
    assert "no `type` member" in tools["address_group_create"].description
    assert "no `type` member" in tools["address_group_update"].description


async def test_the_pinned_output_annotations_survive_the_trim() -> None:
    """The two models whose annotations are pinned keep their field descriptions/defaults.

    ``Pages`` documents the ``total``/``items`` trap and ``FirewallRuleOutput`` documents
    the 1-based position; both are distinctions a model needs, so the trim keeps their
    field annotations while dropping the repeated model docstring.
    """
    server = create_server(_settings())
    tools = {tool.name: tool for tool in await server.list_tools()}

    pages = tools["address_list"].output_schema["$defs"]["Pages"]
    assert pages.get("description") is None
    assert "PAGES" in pages["properties"]["total"]["description"]
    assert "ITEMS" in pages["properties"]["items"]["description"]
    assert pages["properties"]["current"]["default"] is None

    position = tools["firewall_rule_list"].output_schema["$defs"]["FirewallRuleOutput"][
        "properties"
    ]["position"]
    assert "1-based evaluation position" in position["description"]
    assert position["default"] is None
