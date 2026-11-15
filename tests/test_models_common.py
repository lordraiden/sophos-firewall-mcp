"""Tests for the shared domain-model primitives."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from sophos_firewall_mcp.models.common import (
    ListPage,
    ObjectName,
    ObjectNameOrId,
    ObjectRef,
    Pages,
    validate_object_name,
    validate_object_name_or_id,
)

UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"


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
