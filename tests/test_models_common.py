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
