"""Tests for the shared domain-model primitives."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.models.common import (
    ListPage,
    ObjectName,
    ObjectNameOrId,
    ObjectRef,
    Pages,
    validate_object_name,
    validate_object_name_or_id,
)
from sophos_firewall_mcp.models.firewall import ListFirewallRulesInput
from sophos_firewall_mcp.models.nat import NatRuleListInput
from sophos_firewall_mcp.models.network import PageInput
from sophos_firewall_mcp.models.objects import ListQuery
from sophos_firewall_mcp.models.users import UserListInput
from sophos_firewall_mcp.models.vpn import VpnPageInput
from sophos_firewall_mcp.server import create_server

UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

#: The pagination descriptions the six pagination input models publish (M7). They are
#: identical on purpose: a model reading any paginated tool learns the same two facts.
PAGE_DESCRIPTION = "1-based page number; 0 is rejected before the request is sent."
PAGE_TOTAL_DESCRIPTION = (
    "Also request pages.total (the number of pages) and pages.items (the number of "
    "items) in the response metadata."
)

#: The tools whose published input schema declares ``page``/``page_total`` (M7).
EXPECTED_PAGINATED_TOOL_COUNT = 41

#: The six pagination input models, one per domain family that paginates.
PAGINATION_INPUT_MODELS = [
    ListFirewallRulesInput,
    NatRuleListInput,
    PageInput,
    UserListInput,
    VpnPageInput,
    ListQuery,
]


def test_pages_parses_the_wire_shape_and_ignores_unknown_fields():
    pages = Pages.model_validate(
        {"current": 2, "size": 10, "maxSize": 100, "total": 47, "items": 10, "extra": True}
    )

    assert (pages.current, pages.size, pages.maxSize, pages.total, pages.items) == (
        2,
        10,
        100,
        47,
        10,
    )


def test_pages_fields_are_optional():
    pages = Pages.model_validate({"current": 1})

    assert pages.current == 1
    assert pages.size is None
    assert pages.maxSize is None


def test_pages_fields_document_their_semantics():
    """L1: ``total`` counts pages and ``items`` counts items, and the model says so."""
    fields = Pages.model_fields

    assert "current page" in fields["current"].description
    assert "page size" in fields["size"].description
    assert "maximum page size" in fields["maxSize"].description
    # The trap: ``total`` is the page count and ``items`` is the item count.
    assert "number of PAGES" in fields["total"].description
    assert "not the number of items" in fields["total"].description
    assert "number of ITEMS" in fields["items"].description
    assert "not the number of pages" in fields["items"].description


def test_pages_descriptions_reach_the_published_json_schema():
    """L1: the descriptions must be in the schema a client publishes, not just the model."""
    properties = Pages.model_json_schema()["properties"]

    assert set(properties) == {"current", "size", "maxSize", "total", "items"}
    for name, schema in properties.items():
        assert schema.get("description"), f"{name} must be documented in the schema"
    assert "PAGES" in properties["total"]["description"]
    assert "ITEMS" in properties["items"]["description"]


def test_list_page_output_schema_carries_the_pages_descriptions():
    """L1: ``Pages`` is nested in ``ListPage``, so the descriptions must survive nesting."""
    pages = ListPage[ObjectRef].model_json_schema()["$defs"]["Pages"]["properties"]

    assert "PAGES" in pages["total"]["description"]
    assert "ITEMS" in pages["items"]["description"]
    assert "page size" in pages["size"]["description"]


def test_list_page_validates_items_and_keeps_pages():
    page = ListPage[ObjectRef].model_validate(
        {"items": [{"name": "LAN"}, {"name": "WAN", "extra": 1}], "pages": {"current": 1}}
    )

    assert [item.name for item in page.items] == ["LAN", "WAN"]
    assert page.pages is not None
    assert page.pages.current == 1


def test_list_page_accepts_a_missing_pages_object():
    page = ListPage[ObjectRef].model_validate({"items": []})

    assert page.items == []
    assert page.pages is None


@pytest.mark.parametrize(
    "name",
    ["LAN", "allow.lan.to.wan", "My Rule 1", "vlan-10", "a" * 50],
)
def test_valid_object_names_are_accepted(name: str):
    assert validate_object_name(name) == name


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("", "empty"),
        (" leading", "leading whitespace"),
        ("trailing ", "trailing whitespace"),
        ("a,b", "comma"),
        ("a;b", "semicolon"),
        ("a\x00b", "control character"),
        ("a\x1fb", "control character"),
        (UUID, "UUID"),
        (UUID.upper(), "UUID"),
    ],
)
def test_invalid_object_names_are_rejected(name: str, reason: str):
    with pytest.raises(ValueError):
        validate_object_name(name)


def test_object_name_annotation_is_enforced_by_pydantic():
    class Model(BaseModel):
        name: ObjectName

    assert Model(name="LAN").name == "LAN"
    with pytest.raises(ValidationError):
        Model(name="bad,name")


@pytest.mark.parametrize(
    "value",
    [
        "LAN",
        "allow.lan.to.wan",
        UUID,
        UUID.upper(),
        # Built-in names the appliance returns from its list operations (M3).
        "##ALL_RW",
        "##ALL_IPSEC_RW6",
        # The adapters percent-encode the path segment, so these are addressable.
        "FQDN Group - Pipeline/parsing errors",
        "a/b",
        "a\\b",
        "a?b",
        "a#b",
        "a://b",
    ],
)
def test_object_name_or_id_accepts_names_and_uuids(value: str):
    assert validate_object_name_or_id(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        " leading",
        "a,b",
        "a;b",
        "a\x00b",
        # Only the sequences that survive percent-encoding are rejected.
        "..",
        "a..b",
        "a%2eb",
        "a%2Eb",
    ],
)
def test_object_name_or_id_rejects_invalid_names(value: str):
    with pytest.raises(ValueError):
        validate_object_name_or_id(value)


def test_object_name_or_id_rejection_names_the_uuid_fallback():
    with pytest.raises(ValueError, match="UUID"):
        validate_object_name_or_id("a..b")


def test_object_name_or_id_annotation_is_enforced_by_pydantic():
    class Model(BaseModel):
        identifier: ObjectNameOrId

    assert Model(identifier=UUID).identifier == UUID
    assert Model(identifier="LAN").identifier == "LAN"
    with pytest.raises(ValidationError):
        Model(identifier="bad,name")


# -- Pagination inputs (M7) -------------------------------------------------------------


def _published_input_properties(schema: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Every property the input schema publishes, at every depth, with its subschema.

    Local ``$ref`` targets, array ``items`` and every ``allOf``/``oneOf``/``anyOf`` branch
    are followed, so the request body is scanned wherever the SDK nests it. A ``$ref``
    already on the current path is not followed again, which keeps a recursive model from
    looping. Every occurrence is returned, not just the first, so a duplicated property
    cannot hide an undocumented one.
    """
    found: list[tuple[str, dict[str, Any]]] = []
    _collect_properties(schema, schema, found, frozenset())
    return found


def _collect_properties(
    schema: dict[str, Any],
    node: dict[str, Any],
    found: list[tuple[str, dict[str, Any]]],
    seen: frozenset[str],
) -> None:
    """Walk one schema node, appending every property it publishes to ``found``."""
    if "$ref" in node:
        target = node["$ref"].rsplit("/", 1)[-1]
        if target in seen:
            return
        seen = seen | {target}
        node = schema["$defs"][target]
    for keyword in ("allOf", "oneOf", "anyOf"):
        for branch in node.get(keyword) or ():
            _collect_properties(schema, branch, found, seen)
    for name, subschema in (node.get("properties") or {}).items():
        found.append((name, subschema))
        _collect_properties(schema, subschema, found, seen)
    items = node.get("items")
    if isinstance(items, dict):
        _collect_properties(schema, items, found, seen)


@pytest.mark.parametrize("model", PAGINATION_INPUT_MODELS)
def test_the_pagination_input_models_document_page_and_page_total(model: type[BaseModel]):
    """M7: the two flags are documented on the model, not only on ``page_size``."""
    fields = model.model_fields

    assert fields["page"].description == PAGE_DESCRIPTION
    assert fields["page_total"].description == PAGE_TOTAL_DESCRIPTION
    # Documentation only: the bounds and defaults are unchanged.
    assert fields["page"].default == 1
    assert fields["page_total"].default is False


async def test_every_paginated_tool_publishes_the_page_descriptions():
    """M7: the descriptions must reach the published input schema of every paginated tool.

    A model cannot discover ``page_total`` from a schema that does not describe it, so it
    never asks for ``pages.total``/``pages.items`` and pages blindly until an empty page.
    The sweep covers the whole surface: every tool whose input schema declares ``page`` or
    ``page_total`` must publish both descriptions, and the same two texts everywhere.
    """
    settings = Settings(
        host="fw.example.com",
        port=443,
        api_key="sfos_test_key_0123456789abcdef",
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=False,
    )
    tools = await create_server(settings).list_tools()

    paginated: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for tool in tools:
        properties = _published_input_properties(tool.input_schema)
        if any(name in {"page", "page_total"} for name, _ in properties):
            paginated[tool.name] = properties

    assert len(paginated) == EXPECTED_PAGINATED_TOOL_COUNT

    for name, properties in paginated.items():
        page = [schema for property_name, schema in properties if property_name == "page"]
        page_total = [
            schema for property_name, schema in properties if property_name == "page_total"
        ]

        assert len(page) == 1, name
        assert len(page_total) == 1, name
        assert page[0].get("description") == PAGE_DESCRIPTION, name
        assert page_total[0].get("description") == PAGE_TOTAL_DESCRIPTION, name
        # The published bounds and defaults are unchanged by the documentation fix.
        assert page[0]["default"] == 1, name
        assert page[0]["minimum"] == 1, name
        assert page_total[0]["default"] is False, name


# -- Published catalog trimming (H1, L2) ------------------------------------------------


def _schema_nodes(schema: dict[str, Any]) -> list[tuple[str, dict[str, Any], bool]]:
    """Every schema node reachable from one published schema, with its path.

    ``$defs``, ``properties``, array ``items``, ``additionalProperties`` and every
    ``allOf``/``oneOf``/``anyOf`` branch are followed, so a title or a nullable union
    cannot hide in a nested definition. The third member is true when the node is the
    value of a ``properties`` entry, which is what makes a ``title`` a property title.
    """
    found: list[tuple[str, dict[str, Any], bool]] = []

    def walk(node: dict[str, Any], path: str, is_property: bool) -> None:
        found.append((path, node, is_property))
        definitions = node.get("$defs")
        if isinstance(definitions, dict):
            for name, definition in definitions.items():
                if isinstance(definition, dict):
                    walk(definition, f"{path}.$defs.{name}", False)
        properties = node.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                if isinstance(child, dict):
                    walk(child, f"{path}.{name}", True)
        items = node.get("items")
        if isinstance(items, dict):
            walk(items, f"{path}[]", False)
        additional = node.get("additionalProperties")
        if isinstance(additional, dict):
            walk(additional, f"{path}.*", False)
        for keyword in ("allOf", "oneOf", "anyOf"):
            branches = node.get(keyword)
            if isinstance(branches, list):
                for index, branch in enumerate(branches):
                    if isinstance(branch, dict):
                        walk(branch, f"{path}.{keyword}[{index}]", False)

    walk(schema, "$", False)
    return found


async def _published_output_schemas() -> dict[str, dict[str, Any]]:
    """The output schema of every published tool, keyed by tool name."""
    settings = Settings(
        host="fw.example.com",
        port=443,
        api_key="sfos_test_key_0123456789abcdef",
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=False,
    )
    tools = await create_server(settings).list_tools()
    schemas: dict[str, dict[str, Any]] = {}
    for tool in tools:
        assert tool.output_schema is not None, tool.name
        schemas[tool.name] = tool.output_schema
    return schemas


async def test_output_schemas_publish_no_property_titles():
    """L2: the auto-generated property title is dropped from every published output.

    Pydantic derives a property title from the field name, which mangles it
    (``"Idorname"``, ``"Logtraffic"``) and adds ~52 KB to the catalog. A model-level title
    (the class name) is not a property title and is kept, so the sweep proves it reached
    the properties rather than a schema with no titles at all.
    """
    schemas = await _published_output_schemas()
    assert len(schemas) == 152

    property_titles = 0
    model_titles = 0
    offenders: list[str] = []
    for name, schema in schemas.items():
        for path, node, is_property in _schema_nodes(schema):
            if "title" not in node:
                continue
            if is_property:
                property_titles += 1
                offenders.append(f"{name}: {path}")
            else:
                model_titles += 1

    assert offenders == []
    assert property_titles == 0
    # The model-level titles are still published: the trim is scoped to properties.
    assert model_titles > 0


async def test_nullable_output_fields_use_the_compact_type_form():
    """H1: a nullable field is ``type: [X, "null"]``, not ``anyOf: [{type: X}, null]``.

    The sweep covers every published output schema. A remaining ``anyOf`` with a null
    branch is allowed only when folding it would lose information: a ``$ref`` branch
    cannot be folded without dropping the reference, and an ``enum``/``const`` branch
    cannot be folded without rejecting ``null``.
    """
    schemas = await _published_output_schemas()

    compacted = 0
    remaining = 0
    for name, schema in schemas.items():
        for path, node, _ in _schema_nodes(schema):
            node_type = node.get("type")
            if isinstance(node_type, list):
                assert len(node_type) == 2, (name, path, node_type)
                assert node_type[-1] == "null", (name, path, node_type)
                assert node_type[0] != "null", (name, path, node_type)
                compacted += 1
            branches = node.get("anyOf")
            if not isinstance(branches, list) or len(branches) != 2:
                continue
            nulls = [
                branch
                for branch in branches
                if isinstance(branch, dict) and branch.get("type") == "null"
            ]
            if len(nulls) != 1:
                continue
            other = branches[0] if branches[1] is nulls[0] else branches[1]
            assert isinstance(other, dict), (name, path)
            assert "$ref" in other or "enum" in other or "const" in other, (name, path, other)
            remaining += 1

    # The sweep must reach the whole surface, not a subset of it.
    assert compacted >= 1000
    assert remaining >= 1


async def test_compacted_nullable_fields_keep_their_default_description_and_bounds():
    """H1: folding the union keeps the default, the description and the bounds."""
    schemas = await _published_output_schemas()
    schema = schemas["firewall_rule_list_ipv4"]

    current = schema["$defs"]["Pages"]["properties"]["current"]
    assert current["type"] == ["integer", "null"]
    assert current["default"] is None
    assert current["description"] == "The current page number, 1-based."

    position = schema["$defs"]["FirewallRuleIpv4Output"]["properties"]["position"]
    assert position["type"] == ["integer", "null"]
    assert position["default"] is None
    assert position["minimum"] == 1
    assert "1-based evaluation position" in position["description"]


def _json_type_matches(value: Any, expected: str) -> bool:
    """Whether ``value`` is a JSON instance of the named type."""
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    raise AssertionError(f"unknown JSON type {expected}")


def _validate_instance(
    instance: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str = "$",
) -> None:
    """Validate one instance against the subset of JSON Schema the catalog publishes.

    The project does not declare a JSON Schema validator, so this is the dependency-free
    subset the output schemas use: ``$ref``, ``anyOf``, ``type`` (string or list),
    ``enum``, ``const``, ``properties``, ``required``, ``items``, ``minimum``,
    ``maximum``, ``minLength``, ``maxLength``, ``minItems`` and ``maxItems``.
    """
    if "$ref" in schema:
        target = schema["$ref"].rsplit("/", 1)[-1]
        _validate_instance(instance, root["$defs"][target], root, path)
        return
    branches = schema.get("anyOf")
    if isinstance(branches, list):
        failures: list[str] = []
        for branch in branches:
            try:
                _validate_instance(instance, branch, root, path)
                return
            except AssertionError as exc:
                failures.append(str(exc))
        raise AssertionError(f"{path}: no anyOf branch matched: {failures}")
    expected = schema.get("type")
    if isinstance(expected, str):
        assert _json_type_matches(
            instance, expected
        ), f"{path}: expected {expected}, got {instance!r}"
    elif isinstance(expected, list):
        assert any(
            _json_type_matches(instance, item) for item in expected
        ), f"{path}: expected one of {expected}, got {instance!r}"
    if "const" in schema:
        assert instance == schema["const"], f"{path}: expected const {schema['const']!r}"
    if "enum" in schema:
        assert instance in schema["enum"], f"{path}: {instance!r} is not in the enum"
    if isinstance(instance, dict):
        for name in schema.get("required", []):
            assert name in instance, f"{path}: missing required {name}"
        properties = schema.get("properties") or {}
        for name, value in instance.items():
            if name in properties:
                _validate_instance(value, properties[name], root, f"{path}.{name}")
    if isinstance(instance, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, value in enumerate(instance):
                _validate_instance(value, items, root, f"{path}[{index}]")
        if "minItems" in schema:
            assert len(instance) >= schema["minItems"], f"{path}: too few items"
        if "maxItems" in schema:
            assert len(instance) <= schema["maxItems"], f"{path}: too many items"
    if isinstance(instance, str):
        if "minLength" in schema:
            assert len(instance) >= schema["minLength"], f"{path}: too short"
        if "maxLength" in schema:
            assert len(instance) <= schema["maxLength"], f"{path}: too long"
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema:
            assert instance >= schema["minimum"], f"{path}: below the minimum"
        if "maximum" in schema:
            assert instance <= schema["maximum"], f"{path}: above the maximum"


def test_a_compacted_output_schema_still_validates_a_real_result():
    """H1: the trimmed schema accepts the model's own serialized output, nulls included."""
    page = ListPage[ObjectRef](
        items=[ObjectRef(name="LAN"), ObjectRef(name="WAN")],
        pages=Pages(current=1, size=10, maxSize=100, total=2, items=2),
    )
    schema = ListPage[ObjectRef].model_json_schema()

    _validate_instance(page.model_dump(mode="json", by_alias=True), schema, schema)
    # The nullable members are published in the compact form and still accept null.
    pages_schema = schema["$defs"]["Pages"]["properties"]
    assert pages_schema["current"]["type"] == ["integer", "null"]
    assert pages_schema["current"]["default"] is None
    _validate_instance({"items": [], "pages": None}, schema, schema)
