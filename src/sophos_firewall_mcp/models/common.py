"""Shared Pydantic primitives for the Sophos domain models.

The domain families (#27-#31, #35) build their request and response models on these
primitives so that pagination metadata, nested object references and the documented
``sfos-object-name`` format are defined exactly once.

Nothing here performs I/O or knows about a specific domain: the modules are pure models.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Callable, Generic, Literal, TypeVar

from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from pydantic.json_schema import GetJsonSchemaHandler, JsonSchemaValue
from pydantic_core import CoreSchema

__all__ = [
    "IpFamily",
    "ListPage",
    "ObjectName",
    "ObjectNameOrId",
    "ObjectRef",
    "OutputModel",
    "Pages",
    "trim_published_output_schema",
    "validate_object_name",
    "validate_object_name_or_id",
]

#: The IP family a merged tool addresses.
#:
#: The server publishes one tool per concept and selects the IPv4 or IPv6 API path from
#: this value, instead of publishing a separate tool per family. It is the same type the
#: audit composites use, so the whole surface has one convention for the family axis.
#:
#: The value is **required** on every merged tool. A default would silently target one
#: family: for a read it would hide which family was read, and for a mutation (delete,
#: update, move, enable/disable, clone) it would make a destructive target a guess. The
#: server's safety policy is that a destructive target is never inferred (``enabled`` is
#: required on ``firewall_rule_set_enabled`` and ``position`` on create for the same
#: reason). The audit composites default to ``None`` because they are read-only and can
#: span both families; a single-family CRUD tool cannot.
IpFamily = Literal["ipv4", "ipv6"]

#: Characters the documented ``sfos-object-name`` format forbids: comma, semicolon and
#: non-printable characters. The YAML ``format`` is non-assertive (994 of 1,085 name
#: schemas carry no ``pattern``), so this validation is the only enforcement.
_FORBIDDEN_NAME_CHARS = re.compile(r"[,;\x00-\x1f\x7f]")

_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Keys a nullable union's non-null branch may carry and still be folded into a
#: ``type: [X, "null"]`` list. Every key here constrains only values of its own JSON type
#: (``maxLength`` only strings, ``minimum`` only numbers, ``items`` only arrays), so a
#: ``null`` instance passes the merged schema exactly as it passed the ``anyOf`` form.
#: ``$ref``, ``enum`` and ``const`` are deliberately absent: folding a ``$ref`` would lose
#: the reference, and folding an ``enum``/``const`` would reject ``null``.
_COMPACTABLE_NULLABLE_KEYS = frozenset(
    {
        "type",
        "format",
        "maxLength",
        "minLength",
        "pattern",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "properties",
        "required",
        "additionalProperties",
    }
)


def _strip_property_titles(node: dict[str, Any]) -> None:
    """Drop the auto-generated ``title`` from every property of ``node``, recursively.

    Pydantic derives a property title from the field name, which produces mangled values
    such as ``"Idorname"``, ``"Ruletype"`` and ``"Logtraffic"``. The title is display-only
    and the mangled form is worse than none, so it is removed from the published schema.
    A model-level title (the class name) is left alone: it is not a property title.
    """
    properties = node.get("properties")
    if isinstance(properties, dict):
        for child in properties.values():
            if isinstance(child, dict):
                child.pop("title", None)
                _strip_property_titles(child)
    for keyword in ("items", "additionalProperties"):
        child = node.get(keyword)
        if isinstance(child, dict):
            _strip_property_titles(child)
    for keyword in ("anyOf", "oneOf", "allOf"):
        branches = node.get(keyword)
        if isinstance(branches, list):
            for branch in branches:
                if isinstance(branch, dict):
                    _strip_property_titles(branch)
    definitions = node.get("$defs")
    if isinstance(definitions, dict):
        for definition in definitions.values():
            if isinstance(definition, dict):
                _strip_property_titles(definition)


def _compact_nullable_union(node: dict[str, Any]) -> None:
    """Fold ``anyOf: [{type: X, ...}, {type: null}]`` into ``type: [X, "null"]``.

    Only a non-null branch whose keys all constrain values of their own JSON type is
    folded (see :data:`_COMPACTABLE_NULLABLE_KEYS`). The parent's own keys -- ``default``,
    ``description`` and any other annotation -- are kept, so the published default and
    description are unchanged.
    """
    branches = node.get("anyOf")
    if not isinstance(branches, list) or len(branches) != 2:
        return
    null_branches = [
        branch for branch in branches if isinstance(branch, dict) and branch.get("type") == "null"
    ]
    if len(null_branches) != 1 or set(null_branches[0]) != {"type"}:
        return
    other = branches[0] if branches[1] is null_branches[0] else branches[1]
    if not isinstance(other, dict) or not set(other) <= _COMPACTABLE_NULLABLE_KEYS:
        return
    other_type = other.get("type")
    if not isinstance(other_type, str):
        return
    merged = {key: value for key, value in node.items() if key != "anyOf"}
    merged.update(other)
    merged["type"] = [other_type, "null"]
    node.clear()
    node.update(merged)


def _compact_nullable_unions(node: dict[str, Any]) -> None:
    """Compact every nullable union reachable from ``node``, children before parents."""
    for keyword in ("items", "additionalProperties"):
        child = node.get(keyword)
        if isinstance(child, dict):
            _compact_nullable_unions(child)
    for keyword in ("anyOf", "oneOf", "allOf"):
        branches = node.get(keyword)
        if isinstance(branches, list):
            for branch in branches:
                if isinstance(branch, dict):
                    _compact_nullable_unions(branch)
    properties = node.get("properties")
    if isinstance(properties, dict):
        for child in properties.values():
            if isinstance(child, dict):
                _compact_nullable_unions(child)
    definitions = node.get("$defs")
    if isinstance(definitions, dict):
        for definition in definitions.values():
            if isinstance(definition, dict):
                _compact_nullable_unions(definition)
    _compact_nullable_union(node)


def _trim_published_schema(schema: dict[str, Any]) -> None:
    """Apply the two lossless trims to one model's published JSON schema, in place."""
    _strip_property_titles(schema)
    _compact_nullable_unions(schema)


#: The output models whose published field annotations stay in the catalog.
#:
#: ``Pages`` documents the ``total``/``items`` trap (``total`` counts pages, ``items``
#: counts items) and ``FirewallRuleOutput`` documents the 1-based evaluation position;
#: both are distinctions a model needs to interpret a response, and both are pinned by
#: existing tests. Every other ``$defs`` description and default is dropped from the
#: published catalog: the same model docstring and field descriptions repeat in every tool
#: that embeds the model (``ObjectRef`` 64 times, ``Pages`` 33 times), and the tool
#: description plus the property names, types and enums carry the interpretation.
_PINNED_DEFS = frozenset({"Pages", "FirewallRuleOutput"})


def _walk_schema_nodes(
    node: Any, visit: Callable[[dict[str, Any]], None], *, skip_defs: bool = False
) -> None:
    """Visit every JSON Schema node reachable from ``node``.

    A ``properties`` map is not a schema node: its keys are field names, so a field called
    ``description`` or ``title`` must not be mistaken for the annotation keyword. Only the
    values of ``properties`` (and of ``items``, the union branches and ``$defs``) are
    visited.
    """
    if not isinstance(node, dict):
        return
    visit(node)
    for keyword in ("items", "additionalProperties", "not", "contains", "propertyNames"):
        child = node.get(keyword)
        if isinstance(child, dict):
            _walk_schema_nodes(child, visit, skip_defs=skip_defs)
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        branches = node.get(keyword)
        if isinstance(branches, list):
            for branch in branches:
                _walk_schema_nodes(branch, visit, skip_defs=skip_defs)
    properties = node.get("properties")
    if isinstance(properties, dict):
        for child in properties.values():
            _walk_schema_nodes(child, visit, skip_defs=skip_defs)
    if not skip_defs:
        definitions = node.get("$defs")
        if isinstance(definitions, dict):
            for child in definitions.values():
                _walk_schema_nodes(child, visit, skip_defs=skip_defs)


def _drop_annotations(node: dict[str, Any]) -> None:
    """Remove the ``description`` and ``default`` annotations from one schema node."""
    node.pop("description", None)
    node.pop("default", None)


def trim_published_output_schema(schema: dict[str, Any]) -> None:
    """Drop the annotation-only material from one published output schema, in place.

    The catalog is the largest thing a client loads and the output schemas are ~60% of it.
    Two JSON Schema annotations are the redundant part:

    * ``description`` -- the same model docstring and field descriptions repeat in every
      tool that embeds the model (``ObjectRef`` 64 times, ``Pages`` 33 times). The tool
      description and the property names, types and enums carry the interpretation.
    * ``default`` -- a response always carries the field (or ``null``), so a default is
      never applied to an output.

    The two models in :data:`_PINNED_DEFS` keep their field descriptions and defaults
    because they document a distinction a model needs and existing tests pin them.

    Only annotations are removed: ``required``, ``properties``, ``type``, ``enum``,
    ``const``, ``format``, ``$ref``, ``anyOf``/``oneOf``, ``title`` and every other
    keyword are untouched, so an instance valid before the trim is valid after it.
    """
    _walk_schema_nodes(schema, _drop_annotations, skip_defs=True)
    for name, definition in (schema.get("$defs") or {}).items():
        if not isinstance(definition, dict):
            continue
        if name in _PINNED_DEFS:
            # Keep the field annotations; drop only the repeated model docstring.
            definition.pop("description", None)
            continue
        _walk_schema_nodes(definition, _drop_annotations)


class OutputModel(BaseModel):
    """Base class for every published output model.

    The published catalog is the largest thing a client loads, so an output model trims
    its own JSON schema in two ways that lose no validation information:

    * the auto-generated property-level ``title`` is dropped (Pydantic derives it from the
      field name, which mangles it -- ``"Idorname"`` -- and it is display-only);
    * a nullable field is published as ``type: [X, "null"]`` instead of
      ``anyOf: [{type: X}, {type: "null"}]`` when the non-null branch is a plain
      constraint on that type.

    The trim is applied by :meth:`__get_pydantic_json_schema__`, so it reaches every
    nested model that also inherits this base, and it changes only the published schema:
    the model's validation and serialization behaviour is untouched.
    """

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: CoreSchema, handler: GetJsonSchemaHandler, /
    ) -> JsonSchemaValue:
        schema = handler(core_schema)
        _trim_published_schema(schema)
        return schema


class Pages(OutputModel):
    """The ``pages`` metadata a paginated Sophos collection returns.

    The API's shape varies by operation: ``current``, ``size`` and ``maxSize`` are the
    common fields, while ``total`` and ``items`` appear only when ``pageTotal=true`` (live
    observation, 2026-11-15). Every field is optional so an operation that omits one is not
    rejected; unknown fields are ignored rather than echoed.

    ``total`` and ``items`` are easy to confuse, so each field carries a description that
    reaches the published ``outputSchema``: ``total`` counts PAGES and ``items`` counts
    ITEMS. A collection of 119 objects read with ``pageSize=10`` reports
    ``{"current": 1, "size": 10, "maxSize": 100, "total": 12, "items": 119}``.
    """

    model_config = ConfigDict(extra="ignore")

    current: int | None = Field(
        default=None,
        description="The current page number, 1-based.",
    )
    size: int | None = Field(
        default=None,
        description="The page size: the number of items one page may hold.",
    )
    maxSize: int | None = Field(  # noqa: N815 - the wire name is camelCase
        default=None,
        description="The maximum page size the appliance accepts for this operation.",
    )
    total: int | None = Field(
        default=None,
        description=(
            "The number of PAGES in the collection, not the number of items: with "
            "pageSize=10 and 119 objects, total is 12. Present only when pageTotal=true."
        ),
    )
    items: int | None = Field(
        default=None,
        description=(
            "The number of ITEMS in the whole collection, not the number of pages: with "
            "pageSize=10 and 119 objects, items is 119. Present only when pageTotal=true."
        ),
    )


ItemT = TypeVar("ItemT")


class ListPage(OutputModel, Generic[ItemT]):
    """One page of a Sophos collection: ``items`` plus optional ``pages`` metadata.

    ``pages`` is optional because the API declares it optional for at least one
    in-scope operation (``listNetworkInterfaces``). The metadata is preserved exactly and
    never invented.
    """

    model_config = ConfigDict(extra="ignore")

    items: list[ItemT]
    pages: Pages | None = None


class ObjectRef(OutputModel):
    """A nested Sophos object reference, for example ``{"name": "LAN"}``.

    References sometimes carry more members than ``name``; they are ignored rather than
    rejected so a server-side addition does not break the model.
    """

    model_config = ConfigDict(extra="ignore")

    name: str


def validate_object_name(value: str) -> str:
    """Validate the documented ``sfos-object-name`` format.

    Rules (PLAN.md §5, REFERENCES R02): valid UTF-8, no commas or semicolons, no
    non-printable characters, no leading or trailing whitespace, and never a UUID.

    Per-operation length limits (``maxLength``) stay in the domain model, because they
    differ between schemas.

    Raises:
        ValueError: The value is not a valid Sophos object name.
    """
    if not isinstance(value, str):
        raise ValueError("object name must be a string")
    if value == "":
        raise ValueError("object name must not be empty")
    if value != value.strip():
        raise ValueError("object name must not have leading or trailing whitespace")
    if _FORBIDDEN_NAME_CHARS.search(value):
        raise ValueError("object name must not contain commas, semicolons or control characters")
    if _UUID_PATTERN.match(value):
        raise ValueError("object name must not be a UUID")
    return value


#: ``str`` annotated with the documented Sophos object-name validation.
ObjectName = Annotated[str, AfterValidator(validate_object_name)]


def validate_object_name_or_id(value: str) -> str:
    """Validate the documented ``sfos-object-name-or-id`` format for a path identifier.

    A UUID is accepted as an identifier; anything else must be a valid object name **and**
    addressable as a single URL path segment. The adapters percent-encode the segment with
    ``quote(value, safe="")``, so characters such as ``/``, ``?``, ``#`` and ``\\`` are
    safe and are accepted: the appliance returns built-in names like ``##ALL_RW`` and
    names containing ``/`` (for example ``FQDN Group - Pipeline/parsing errors``) from its
    list operations, and a get or usage lookup must accept every name a list returns.
    Only ``..`` and ``%2e`` are rejected: ``..`` survives encoding and the shared client
    refuses it in a path, and ``%2e`` is refused by the client as defence in depth. GET,
    PATCH and DELETE paths use this form, so the same value may be a name or an id.

    Raises:
        ValueError: The value is neither a UUID nor an addressable object name.
    """
    if not isinstance(value, str):
        raise ValueError("object identifier must be a string")
    if _UUID_PATTERN.fullmatch(value):
        return value
    name = validate_object_name(value)
    if ".." in name:
        raise ValueError(
            "object identifier must not contain '..': it is not addressable as a single "
            "URL path segment; use the object's UUID instead"
        )
    if "%2e" in name.lower():
        raise ValueError(
            "object identifier must not contain percent-encoded dots ('%2e'); use the "
            "object's UUID instead"
        )
    return name


#: ``str`` annotated with the documented name-or-id validation.
ObjectNameOrId = Annotated[str, AfterValidator(validate_object_name_or_id)]
