"""Shared Pydantic primitives for the Sophos domain models.

The domain families (#27-#31, #35) build their request and response models on these
primitives so that pagination metadata, nested object references and the documented
``sfos-object-name`` format are defined exactly once.

Nothing here performs I/O or knows about a specific domain: the modules are pure models.
"""

from __future__ import annotations

import re
from typing import Annotated, Generic, TypeVar

from pydantic import AfterValidator, BaseModel, ConfigDict

__all__ = [
    "ListPage",
    "ObjectName",
    "ObjectNameOrId",
    "ObjectRef",
    "Pages",
    "validate_object_name",
    "validate_object_name_or_id",
]

#: Characters the documented ``sfos-object-name`` format forbids: comma, semicolon and
#: non-printable characters. The YAML ``format`` is non-assertive (994 of 1,085 name
#: schemas carry no ``pattern``), so this validation is the only enforcement.
_FORBIDDEN_NAME_CHARS = re.compile(r"[,;\x00-\x1f\x7f]")

_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class Pages(BaseModel):
    """The ``pages`` metadata a paginated Sophos collection returns.

    The contract's shape varies by operation: ``current``, ``size`` and ``maxSize`` are the
    common fields, while ``total`` and ``items`` appear only when ``pageTotal=true`` (live
    observation, 2026-11-15). Every field is optional so an operation that omits one is not
    rejected; unknown fields are ignored rather than echoed.
    """

    model_config = ConfigDict(extra="ignore")

    current: int | None = None
    size: int | None = None
    maxSize: int | None = None  # noqa: N815 - the wire name is camelCase
    total: int | None = None
    items: int | None = None


ItemT = TypeVar("ItemT")


class ListPage(BaseModel, Generic[ItemT]):
    """One page of a Sophos collection: ``items`` plus optional ``pages`` metadata.

    ``pages`` is optional because the contract declares it optional for at least one
    in-scope operation (``listNetworkInterfaces``). The metadata is preserved exactly and
    never invented.
    """

    model_config = ConfigDict(extra="ignore")

    items: list[ItemT]
    pages: Pages | None = None


class ObjectRef(BaseModel):
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
    """Validate the documented ``sfos-object-name-or-id`` format.

    A UUID is accepted as an identifier; anything else must be a valid object name. GET,
    PATCH and DELETE paths use this form, so the same value may be a name or an id.

    Raises:
        ValueError: The value is neither a UUID nor a valid Sophos object name.
    """
    if not isinstance(value, str):
        raise ValueError("object identifier must be a string")
    if _UUID_PATTERN.match(value):
        return value
    return validate_object_name(value)


#: ``str`` annotated with the documented name-or-id validation.
ObjectNameOrId = Annotated[str, AfterValidator(validate_object_name_or_id)]
