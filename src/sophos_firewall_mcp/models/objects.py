"""Typed Pydantic models for the Sophos network objects and services domain (#29).

The module keeps every Sophos family separate because the API gives them different
required fields, identifier semantics and validation:

* IPv4 and IPv6 addresses are discriminated unions of four shapes (``ipv4Address``,
  ``ipv4Network``, ``ipv4Range``, ``ipv4List`` and the IPv6 equivalents);
* FQDN addresses are one flat object with a ``fqdn`` string;
* address groups are per family and reference members as ``{"name": ...}``;
* MAC address objects are a discriminated union of a single address and a list;
* country groups are read-only and carry a list of country references;
* services and service groups have different payloads, and a service is a list of
  protocol-specific detail entries (TCP/UDP, IP protocol, ICMPv4, ICMPv6).

Conventions
-----------
* Request models are closed (``extra="forbid"``); response models ignore unknown members
  so a server-side addition does not break a read.
* Wire names are camelCase. Python field names are snake_case with an explicit alias, and
  ``populate_by_name=True`` so tests and adapters may use either spelling.
* PATCH bodies are partial: the adapter serializes them with ``exclude_unset=True`` so an
  omitted property keeps its persisted value and an explicit ``None`` removes a nullable
  one.
* Output models are explicit projections of the appliance payload, never a raw passthrough;
  a field is optional when the API does not list it as required.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal, Self, Union

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_serializer, model_validator

from sophos_firewall_mcp.models.common import (
    IpFamily,
    ObjectName,
    ObjectNameOrId,
    ObjectRef,
    OutputModel,
    validate_object_name_or_id,
)

__all__ = [
    "Address",
    "AddressCreateInput",
    "AddressGroupCreateInput",
    "AddressGroupListInput",
    "AddressGroupOutput",
    "AddressGroupUpdateInput",
    "AddressListInput",
    "AddressResult",
    "AddressUpdateInput",
    "CountryGroup",
    "CountryGroupListInput",
    "DeleteResult",
    "FqdnAddress",
    "FqdnAddressCreate",
    "FqdnAddressGroup",
    "FqdnAddressGroupCreate",
    "FqdnAddressGroupListInput",
    "FqdnAddressGroupUpdateInput",
    "FqdnAddressListInput",
    "FqdnAddressUpdateInput",
    "IcmpCode",
    "IcmpType",
    "Icmpv4ServiceDetail",
    "Icmpv4ServiceDetailOutput",
    "Icmpv6Code",
    "Icmpv6ServiceDetail",
    "Icmpv6ServiceDetailOutput",
    "Icmpv6Type",
    "IpProtocol",
    "IpProtocolServiceDetail",
    "IpProtocolServiceDetailOutput",
    "Ipv4Address",
    "Ipv4AddressCreate",
    "Ipv4AddressCreateIp",
    "Ipv4AddressCreateIpList",
    "Ipv4AddressCreateIpRange",
    "Ipv4AddressCreateNetwork",
    "Ipv4AddressGroup",
    "Ipv4AddressGroupCreate",
    "Ipv4AddressGroupUpdateInput",
    "Ipv4AddressIp",
    "Ipv4AddressIpList",
    "Ipv4AddressIpRange",
    "Ipv4AddressNetwork",
    "Ipv4AddressUpdateInput",
    "Ipv6Address",
    "Ipv6AddressCreate",
    "Ipv6AddressCreateIp",
    "Ipv6AddressCreateIpList",
    "Ipv6AddressCreateIpRange",
    "Ipv6AddressCreateNetwork",
    "Ipv6AddressGroup",
    "Ipv6AddressGroupCreate",
    "Ipv6AddressGroupUpdateInput",
    "Ipv6AddressIp",
    "Ipv6AddressIpList",
    "Ipv6AddressIpRange",
    "Ipv6AddressNetwork",
    "Ipv6AddressUpdateInput",
    "ListQuery",
    "MAC_ADDRESS_PATTERN",
    "MacAddress",
    "MacAddressCreate",
    "MacAddressCreateList",
    "MacAddressCreateSingle",
    "MacAddressListInput",
    "MacAddressMacAddress",
    "MacAddressMacList",
    "MacAddressResult",
    "MacAddressString",
    "MacAddressUpdateInput",
    "MemberRef",
    "ObjectNameOrId",
    "IpFamilyObjectIdentifierInput",
    "ObjectIdentifierInput",
    "Service",
    "ServiceCreate",
    "ServiceDetail",
    "ServiceDetailOutput",
    "ServiceGroup",
    "ServiceGroupCreate",
    "ServiceGroupListInput",
    "ServiceGroupUpdateInput",
    "ServiceListInput",
    "ServiceMemberRef",
    "ServicePortRange",
    "ServicePortRangeOutput",
    "ServiceType",
    "ServiceUpdateInput",
    "TcpUdpServiceDetail",
    "TcpUdpServiceDetailOutput",
    "validate_object_name_or_id",
]

#: Closed request models: the API is closed, an unknown member is a bug.
_INPUT_CONFIG = ConfigDict(extra="forbid", populate_by_name=True)

#: Response models ignore server additions but never echo them back to the model.
_OUTPUT_CONFIG = ConfigDict(extra="ignore", populate_by_name=True)


#: The appliance's "never" sentinel for ``createdAt``/``updatedAt``. Built-in objects
#: (``##ALL_RW``, ``Internet IPv4 group``, ``WAN - Port 1``, …) carry it instead of a real
#: creation time, so the projection publishes it as ``null`` (L6).
EPOCH_SENTINEL = "1970-01-01T00:00:00Z"

#: The sentinel as the two datetime values pydantic parses it into: aware UTC for the
#: appliance's ``Z`` form, naive for a payload that omits the offset.
_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=UTC)
_EPOCH_NAIVE = datetime(1970, 1, 1)


def serialize_epoch_sentinel(value: datetime | None) -> datetime | None:
    """Publish the appliance's epoch "never" sentinel as ``None`` (L6).

    Only the exact sentinel is mapped: ``1970-01-01T00:00:01Z`` and every other timestamp
    are preserved, so a real creation time is never hidden. The mapping happens at
    serialization time, not at validation time, so the parsed value stays available to
    server-side logic that needs it -- ``audit_firewall_rules`` detects built-in objects
    from the epoch stamp, and hiding it from the model would silently disable that
    heuristic.

    Args:
        value: The parsed timestamp of a ``createdAt``/``updatedAt`` member.

    Returns:
        ``None`` when *value* is the epoch sentinel, otherwise *value* unchanged.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return None if value == _EPOCH_NAIVE else value
    return None if value == _EPOCH_UTC else value


class _InputModel(BaseModel):
    """Base for every request model: closed and addressable by field name or alias."""

    model_config = _INPUT_CONFIG


class _OutputModel(OutputModel):
    """Base for every response projection: forward-compatible and alias-aware.

    The epoch "never" sentinel is published as ``null`` (L6); see
    :func:`serialize_epoch_sentinel`.
    """

    model_config = _OUTPUT_CONFIG

    @field_serializer(
        "createdAt", "updatedAt", "created_at", "updated_at", check_fields=False, when_used="json"
    )
    def _epoch_sentinel_is_absent(self, value: datetime | None) -> datetime | None:
        """Publish the appliance's epoch "never" sentinel as ``None`` (L6)."""
        return serialize_epoch_sentinel(value)


# -- Shared identifier and membership primitives --------------------------------------


class ObjectIdentifierInput(_InputModel):
    """The ``{idOrName}`` path parameter used by get and delete operations."""

    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)


class IpFamilyObjectIdentifierInput(ObjectIdentifierInput):
    """The ``{idOrName}`` path parameter plus the IP family that selects the collection.

    ``ObjectIdentifierInput`` stays family-neutral because the FQDN, MAC and country tools
    use it too; the merged IPv4/IPv6 tools take this subclass instead.
    """

    ip_family: IpFamily = Field(
        description="IP family of the object collection: 'ipv4' or 'ipv6'. Required."
    )


class MemberRef(_InputModel):
    """One address-group member: exactly ``{"name": "<address object name>"}``.

    The API's group payloads reference members by name only; an address family is
    implied by the group endpoint, so a mixed-family member is not representable.
    """

    name: ObjectName = Field(..., max_length=60)


class ServiceMemberRef(_InputModel):
    """One service-group member: exactly ``{"name": "<service name>"}``."""

    name: ObjectName = Field(..., max_length=50)


class DeleteResult(_OutputModel):
    """The documented delete response. ``deleted`` is optional in the API."""

    deleted: bool | None = None


class ListQuery(_InputModel):
    """Pagination and name filters shared by the paginated list operations.

    The API declares ``page``, ``pageSize``, ``pageTotal``, ``nameContains`` and
    ``nameNotEquals`` on every list operation in this domain. The two name filters are
    mutually exclusive; the validator rejects a request that sets both.

    ``page_size`` defaults to 10: a default call must stay small enough for a model
    context, and the caller raises it explicitly when it wants a bigger page.
    """

    page: int = Field(
        1,
        ge=1,
        description="1-based page number; 0 is rejected before the request is sent.",
    )
    page_size: int = Field(
        10,
        ge=1,
        le=100,
        description=(
            "Page size, 1-100. Defaults to 10 so a default call stays small; raise it "
            "explicitly for a bigger page."
        ),
    )
    page_total: bool = Field(
        False,
        description=(
            "Also request pages.total (the number of pages) and pages.items (the number "
            "of items) in the response metadata."
        ),
    )
    name_contains: str | None = Field(None, min_length=1, max_length=255)
    name_not_equals: str | None = Field(None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def _one_name_filter(self) -> Self:
        if self.name_contains is not None and self.name_not_equals is not None:
            raise ValueError("name_contains and name_not_equals are mutually exclusive")
        return self

    def filters(self) -> dict[str, str]:
        """Return only the name filters that were set, using the wire parameter names."""
        params: dict[str, str] = {}
        if self.name_contains is not None:
            params["nameContains"] = self.name_contains
        if self.name_not_equals is not None:
            params["nameNotEquals"] = self.name_not_equals
        return params


# -- IPv4 addresses --------------------------------------------------------------------


class _Ipv4AddressBase(_OutputModel):
    """Members shared by every IPv4 address response shape."""

    id: str | None = None
    name: str = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class Ipv4AddressIp(_Ipv4AddressBase):
    """A single IPv4 address (``type: ipv4Address``)."""

    type: Literal["ipv4Address"]
    ipv4_address: IPv4Address = Field(alias="ipv4Address")


class Ipv4AddressNetwork(_Ipv4AddressBase):
    """An IPv4 network (``type: ipv4Network``)."""

    type: Literal["ipv4Network"]
    ipv4_network_address: IPv4Address = Field(alias="ipv4NetworkAddress")
    cidr: int = Field(ge=1, le=31)


class Ipv4AddressIpRange(_Ipv4AddressBase):
    """An IPv4 address range (``type: ipv4Range``)."""

    type: Literal["ipv4Range"]
    ipv4_address_start: IPv4Address = Field(alias="ipv4AddressStart")
    ipv4_address_end: IPv4Address = Field(alias="ipv4AddressEnd")


class Ipv4AddressIpList(_Ipv4AddressBase):
    """A list of IPv4 addresses (``type: ipv4List``).

    The API declares ``ipv4Addresses`` with ``minItems: 1``, but the tested appliance
    (15 Nov 2026, ``GET /network/addresses/ipv4``) returns ``"ipv4Addresses": []`` for the
    built-in internal objects ``##ALL_RW``, ``##ALL_IPSEC_RW`` and ``##ALL_SSLVPN_RW``.
    The *output* model therefore accepts an empty list: one built-in object must not make
    the whole page unreadable. The create/update *input* models keep ``min_length=1``
    because creating an empty list is still invalid.
    """

    type: Literal["ipv4List"]
    ipv4_addresses: list[IPv4Address] = Field(alias="ipv4Addresses")


Ipv4Address = Annotated[
    Union[
        Ipv4AddressIp,
        Ipv4AddressNetwork,
        Ipv4AddressIpRange,
        Ipv4AddressIpList,
    ],
    Field(discriminator="type"),
]
"""Any IPv4 address object, discriminated on the required ``type`` member."""


class Ipv4AddressCreateIp(_InputModel):
    """Create a single IPv4 address."""

    ip_family: Literal["ipv4"]

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    type: Literal["ipv4Address"]
    ipv4_address: IPv4Address = Field(
        validation_alias=AliasChoices("ipv4_address", "ipv4Address"),
        serialization_alias="ipv4Address",
    )


class Ipv4AddressCreateNetwork(_InputModel):
    """Create an IPv4 network."""

    ip_family: Literal["ipv4"]

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    type: Literal["ipv4Network"]
    ipv4_network_address: IPv4Address = Field(
        validation_alias=AliasChoices("ipv4_network_address", "ipv4NetworkAddress"),
        serialization_alias="ipv4NetworkAddress",
    )
    cidr: int = Field(ge=1, le=31)


class Ipv4AddressCreateIpRange(_InputModel):
    """Create an IPv4 address range."""

    ip_family: Literal["ipv4"]

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    type: Literal["ipv4Range"]
    ipv4_address_start: IPv4Address = Field(
        validation_alias=AliasChoices("ipv4_address_start", "ipv4AddressStart"),
        serialization_alias="ipv4AddressStart",
    )
    ipv4_address_end: IPv4Address = Field(
        validation_alias=AliasChoices("ipv4_address_end", "ipv4AddressEnd"),
        serialization_alias="ipv4AddressEnd",
    )


class Ipv4AddressCreateIpList(_InputModel):
    """Create a list of IPv4 addresses."""

    ip_family: Literal["ipv4"]

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    type: Literal["ipv4List"]
    ipv4_addresses: list[IPv4Address] = Field(
        min_length=1,
        validation_alias=AliasChoices("ipv4_addresses", "ipv4Addresses"),
        serialization_alias="ipv4Addresses",
    )


Ipv4AddressCreate = Annotated[
    Union[
        Ipv4AddressCreateIp,
        Ipv4AddressCreateNetwork,
        Ipv4AddressCreateIpRange,
        Ipv4AddressCreateIpList,
    ],
    Field(discriminator="type"),
]
"""The create payload for ``createIpAddress``, discriminated on ``type``."""


class Ipv4AddressUpdateInput(_InputModel):
    """The ``updateIpAddressByIdOrName`` input: identifier plus partial PATCH fields."""

    ip_family: Literal["ipv4"]
    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    ipv4_address: IPv4Address | None = Field(
        None,
        validation_alias=AliasChoices("ipv4_address", "ipv4Address"),
        serialization_alias="ipv4Address",
    )
    ipv4_network_address: IPv4Address | None = Field(
        None,
        validation_alias=AliasChoices("ipv4_network_address", "ipv4NetworkAddress"),
        serialization_alias="ipv4NetworkAddress",
    )
    cidr: int | None = Field(None, ge=1, le=31)
    ipv4_address_start: IPv4Address | None = Field(
        None,
        validation_alias=AliasChoices("ipv4_address_start", "ipv4AddressStart"),
        serialization_alias="ipv4AddressStart",
    )
    ipv4_address_end: IPv4Address | None = Field(
        None,
        validation_alias=AliasChoices("ipv4_address_end", "ipv4AddressEnd"),
        serialization_alias="ipv4AddressEnd",
    )
    ipv4_addresses: list[IPv4Address] | None = Field(
        None,
        min_length=1,
        validation_alias=AliasChoices("ipv4_addresses", "ipv4Addresses"),
        serialization_alias="ipv4Addresses",
    )


class AddressListInput(ListQuery):
    """Filters for ``getAllIpAddresses``/``getAllIpv6Addresses``, plus the family."""

    ip_family: IpFamily = Field(
        description="IP family of the address collection: 'ipv4' or 'ipv6'. Required."
    )


# -- IPv6 addresses --------------------------------------------------------------------


class _Ipv6AddressBase(_OutputModel):
    """Members shared by every IPv6 address response shape."""

    id: str | None = None
    name: str = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class Ipv6AddressIp(_Ipv6AddressBase):
    """A single IPv6 address (``type: ipv6Address``)."""

    type: Literal["ipv6Address"]
    ipv6_address: IPv6Address = Field(alias="ipv6Address")


class Ipv6AddressNetwork(_Ipv6AddressBase):
    """An IPv6 network (``type: ipv6Network``)."""

    type: Literal["ipv6Network"]
    ipv6_network_address: IPv6Address = Field(alias="ipv6NetworkAddress")
    prefix_length: int = Field(ge=1, le=127, alias="prefixLength")


class Ipv6AddressIpRange(_Ipv6AddressBase):
    """An IPv6 address range (``type: ipv6Range``)."""

    type: Literal["ipv6Range"]
    ipv6_address_start: IPv6Address = Field(alias="ipv6AddressStart")
    ipv6_address_end: IPv6Address = Field(alias="ipv6AddressEnd")


class Ipv6AddressIpList(_Ipv6AddressBase):
    """A list of IPv6 addresses (``type: ipv6List``).

    Same live deviation as :class:`Ipv4AddressIpList`: the API declares
    ``ipv6Addresses`` with ``minItems: 1``, but the tested appliance (15 Nov 2026,
    ``GET /network/addresses/ipv6``) returns ``"ipv6Addresses": []`` for its built-in
    internal objects. The output model accepts an empty list; the create/update input
    models keep ``min_length=1``.
    """

    type: Literal["ipv6List"]
    ipv6_addresses: list[IPv6Address] = Field(alias="ipv6Addresses")


Ipv6Address = Annotated[
    Union[
        Ipv6AddressIp,
        Ipv6AddressNetwork,
        Ipv6AddressIpRange,
        Ipv6AddressIpList,
    ],
    Field(discriminator="type"),
]
"""Any IPv6 address object, discriminated on the required ``type`` member."""


class Ipv6AddressCreateIp(_InputModel):
    """Create a single IPv6 address."""

    ip_family: Literal["ipv6"]

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    type: Literal["ipv6Address"]
    ipv6_address: IPv6Address = Field(
        validation_alias=AliasChoices("ipv6_address", "ipv6Address"),
        serialization_alias="ipv6Address",
    )


class Ipv6AddressCreateNetwork(_InputModel):
    """Create an IPv6 network."""

    ip_family: Literal["ipv6"]

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    type: Literal["ipv6Network"]
    ipv6_network_address: IPv6Address = Field(
        validation_alias=AliasChoices("ipv6_network_address", "ipv6NetworkAddress"),
        serialization_alias="ipv6NetworkAddress",
    )
    prefix_length: int = Field(
        ge=1,
        le=127,
        validation_alias=AliasChoices("prefix_length", "prefixLength"),
        serialization_alias="prefixLength",
    )


class Ipv6AddressCreateIpRange(_InputModel):
    """Create an IPv6 address range."""

    ip_family: Literal["ipv6"]

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    type: Literal["ipv6Range"]
    ipv6_address_start: IPv6Address = Field(
        validation_alias=AliasChoices("ipv6_address_start", "ipv6AddressStart"),
        serialization_alias="ipv6AddressStart",
    )
    ipv6_address_end: IPv6Address = Field(
        validation_alias=AliasChoices("ipv6_address_end", "ipv6AddressEnd"),
        serialization_alias="ipv6AddressEnd",
    )


class Ipv6AddressCreateIpList(_InputModel):
    """Create a list of IPv6 addresses."""

    ip_family: Literal["ipv6"]

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    type: Literal["ipv6List"]
    ipv6_addresses: list[IPv6Address] = Field(
        min_length=1,
        validation_alias=AliasChoices("ipv6_addresses", "ipv6Addresses"),
        serialization_alias="ipv6Addresses",
    )


Ipv6AddressCreate = Annotated[
    Union[
        Ipv6AddressCreateIp,
        Ipv6AddressCreateNetwork,
        Ipv6AddressCreateIpRange,
        Ipv6AddressCreateIpList,
    ],
    Field(discriminator="type"),
]
"""The create payload for ``createIpv6Address``, discriminated on ``type``."""


AddressCreateInput = Annotated[
    Union[
        Ipv4AddressCreateIp,
        Ipv4AddressCreateNetwork,
        Ipv4AddressCreateIpRange,
        Ipv4AddressCreateIpList,
        Ipv6AddressCreateIp,
        Ipv6AddressCreateNetwork,
        Ipv6AddressCreateIpRange,
        Ipv6AddressCreateIpList,
    ],
    Field(discriminator="type"),
]
"""The create request of the merged ``address_create`` tool.

The eight shapes stay separate because each family's payload is different and the
``type`` member already discriminates them; every variant also pins ``ip_family`` to its
family, so a caller cannot send an IPv4 shape to the IPv6 path. ``ip_family`` is stripped
from the wire body, which is byte-identical to the pre-0.7 per-family tool.
"""


class Ipv6AddressUpdateInput(_InputModel):
    """The ``updateIpv6AddressByIdOrName`` input: identifier plus partial PATCH fields."""

    ip_family: Literal["ipv6"]
    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    ipv6_address: IPv6Address | None = Field(
        None,
        validation_alias=AliasChoices("ipv6_address", "ipv6Address"),
        serialization_alias="ipv6Address",
    )
    ipv6_network_address: IPv6Address | None = Field(
        None,
        validation_alias=AliasChoices("ipv6_network_address", "ipv6NetworkAddress"),
        serialization_alias="ipv6NetworkAddress",
    )
    prefix_length: int | None = Field(
        None,
        ge=1,
        le=127,
        validation_alias=AliasChoices("prefix_length", "prefixLength"),
        serialization_alias="prefixLength",
    )
    ipv6_address_start: IPv6Address | None = Field(
        None,
        validation_alias=AliasChoices("ipv6_address_start", "ipv6AddressStart"),
        serialization_alias="ipv6AddressStart",
    )
    ipv6_address_end: IPv6Address | None = Field(
        None,
        validation_alias=AliasChoices("ipv6_address_end", "ipv6AddressEnd"),
        serialization_alias="ipv6AddressEnd",
    )
    ipv6_addresses: list[IPv6Address] | None = Field(
        None,
        min_length=1,
        validation_alias=AliasChoices("ipv6_addresses", "ipv6Addresses"),
        serialization_alias="ipv6Addresses",
    )


AddressUpdateInput = Annotated[
    Union[Ipv4AddressUpdateInput, Ipv6AddressUpdateInput],
    Field(discriminator="ip_family"),
]
"""The update request of the merged ``address_update`` tool.

The two family merge-patch bodies differ in their address members, so ``ip_family``
discriminates them and is stripped from the PATCH body.
"""


Address = Annotated[
    Union[
        Ipv4AddressIp,
        Ipv4AddressNetwork,
        Ipv4AddressIpRange,
        Ipv4AddressIpList,
        Ipv6AddressIp,
        Ipv6AddressNetwork,
        Ipv6AddressIpRange,
        Ipv6AddressIpList,
    ],
    Field(discriminator="type"),
]
"""Any address object of either family, discriminated on the required ``type`` member."""


class AddressResult(_OutputModel):
    """Object-rooted wrapper for a single address response of either family.

    A plain union return annotation would be wrapped by the SDK under ``result``; this
    wrapper keeps the output object-rooted and the discriminated union named. The shape is
    the same one the per-family tools published before 0.7.
    """

    address: Address


# -- FQDN addresses --------------------------------------------------------------------


class FqdnAddress(_OutputModel):
    """An FQDN address object. The API only requires ``id`` in the response."""

    id: str
    name: str | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    fqdn: str | None = Field(None, min_length=1, max_length=253)
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class FqdnAddressCreate(_InputModel):
    """Create an FQDN address."""

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    fqdn: str = Field(..., min_length=1, max_length=253)


class FqdnAddressUpdateInput(_InputModel):
    """The ``updateFqdnByIdOrName`` input: identifier plus partial PATCH fields."""

    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    fqdn: str | None = Field(None, min_length=1, max_length=253)


class FqdnAddressListInput(ListQuery):
    """Filters for ``getAllFqdns``."""


# -- Address groups --------------------------------------------------------------------


class Ipv4AddressGroup(_OutputModel):
    """An IPv4 address group. Members are name references, never mixed families."""

    id: str
    name: str | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    ipv4_addresses: list[ObjectRef] = Field(default_factory=list, alias="ipv4Addresses")
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class Ipv4AddressGroupCreate(_InputModel):
    """Create an IPv4 address group from existing IPv4 address objects."""

    ip_family: Literal["ipv4"]
    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    ipv4_addresses: list[MemberRef] = Field(
        ...,
        validation_alias=AliasChoices("ipv4_addresses", "ipv4Addresses"),
        serialization_alias="ipv4Addresses",
    )


class Ipv4AddressGroupUpdateInput(_InputModel):
    """The ``updateIpv4AddressGroupByIdOrName`` input: identifier plus partial fields."""

    ip_family: Literal["ipv4"]
    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    ipv4_addresses: list[MemberRef] | None = Field(
        None,
        validation_alias=AliasChoices("ipv4_addresses", "ipv4Addresses"),
        serialization_alias="ipv4Addresses",
    )


class AddressGroupListInput(ListQuery):
    """Filters for ``getAllIpv4AddressGroups``/``getAllIpv6AddressGroups``, plus the family."""

    ip_family: IpFamily = Field(
        description="IP family of the address-group collection: 'ipv4' or 'ipv6'. Required."
    )


class Ipv6AddressGroup(_OutputModel):
    """An IPv6 address group. Members are name references, never mixed families."""

    id: str
    name: str | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    ipv6_addresses: list[ObjectRef] = Field(default_factory=list, alias="ipv6Addresses")
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class Ipv6AddressGroupCreate(_InputModel):
    """Create an IPv6 address group from existing IPv6 address objects."""

    ip_family: Literal["ipv6"]
    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    ipv6_addresses: list[MemberRef] = Field(
        ...,
        validation_alias=AliasChoices("ipv6_addresses", "ipv6Addresses"),
        serialization_alias="ipv6Addresses",
    )


class Ipv6AddressGroupUpdateInput(_InputModel):
    """The ``updateIpv6AddressGroupByIdOrName`` input: identifier plus partial fields."""

    ip_family: Literal["ipv6"]
    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    ipv6_addresses: list[MemberRef] | None = Field(
        None,
        validation_alias=AliasChoices("ipv6_addresses", "ipv6Addresses"),
        serialization_alias="ipv6Addresses",
    )


class AddressGroupOutput(Ipv4AddressGroup, Ipv6AddressGroup):
    """An address group of either family.

    The two family projections differ only in the member list (``ipv4Addresses`` or
    ``ipv6Addresses``), so the merged model carries both and the family that was read
    populates exactly one of them. The shape is the same one the per-family tools
    published before 0.7.
    """


AddressGroupCreateInput = Annotated[
    Union[Ipv4AddressGroupCreate, Ipv6AddressGroupCreate],
    Field(discriminator="ip_family"),
]
"""The create request of the merged ``address_group_create`` tool."""


AddressGroupUpdateInput = Annotated[
    Union[Ipv4AddressGroupUpdateInput, Ipv6AddressGroupUpdateInput],
    Field(discriminator="ip_family"),
]
"""The update request of the merged ``address_group_update`` tool."""


class FqdnAddressGroup(_OutputModel):
    """An FQDN address group. Members are name references to FQDN address objects."""

    id: str
    name: str | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    fqdns: list[ObjectRef] = Field(default_factory=list)
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class FqdnAddressGroupCreate(_InputModel):
    """Create an FQDN address group. ``fqdns`` is nullable in the API."""

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    fqdns: list[MemberRef] | None = None


class FqdnAddressGroupUpdateInput(_InputModel):
    """The ``updateFqdnGroupByIdOrName`` input: identifier plus partial fields."""

    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    fqdns: list[MemberRef] | None = None


class FqdnAddressGroupListInput(ListQuery):
    """Filters for ``getAllFqdnGroups``."""


class CountryGroup(_OutputModel):
    """A built-in country group. Read-only in v1: only list and get are exposed."""

    id: str
    name: str | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    countries: list[ObjectRef] = Field(default_factory=list)
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class CountryGroupListInput(ListQuery):
    """Filters for ``getAllCountryGroups``."""


# -- MAC address objects ---------------------------------------------------------------

#: The documented MAC-address pattern, including the ``|`` separator the API allows.
MAC_ADDRESS_PATTERN = (
    r"^[0-9a-fA-F]{2}[:|-][0-9a-fA-F]{2}[:|-][0-9a-fA-F]{2}[:|-]"
    r"[0-9a-fA-F]{2}[:|-][0-9a-fA-F]{2}[:|-][0-9a-fA-F]{2}$"
)

#: One MAC address string, validated against the documented pattern.
MacAddressString = Annotated[str, Field(max_length=17, pattern=MAC_ADDRESS_PATTERN)]


class _MacAddressBase(_OutputModel):
    """Members shared by both MAC address response shapes."""

    id: str | None = None
    name: str = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class MacAddressMacAddress(_MacAddressBase):
    """A single MAC address (``type: macAddress``)."""

    type: Literal["macAddress"]
    mac_address: MacAddressString = Field(alias="macAddress")


class MacAddressMacList(_MacAddressBase):
    """A list of MAC addresses (``type: macList``)."""

    type: Literal["macList"]
    mac_addresses: list[MacAddressString] = Field(
        alias="macAddresses", min_length=1, max_length=1000
    )


MacAddress = Annotated[
    Union[MacAddressMacAddress, MacAddressMacList],
    Field(discriminator="type"),
]
"""Any MAC address object, discriminated on the required ``type`` member."""


class MacAddressCreateSingle(_InputModel):
    """Create a single-MAC object. The create payload has no ``type`` member."""

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    mac_address: MacAddressString = Field(
        validation_alias=AliasChoices("mac_address", "macAddress"),
        serialization_alias="macAddress",
    )


class MacAddressCreateList(_InputModel):
    """Create a MAC-list object. The create payload has no ``type`` member."""

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    mac_addresses: list[MacAddressString] = Field(
        min_length=1,
        max_length=1000,
        validation_alias=AliasChoices("mac_addresses", "macAddresses"),
        serialization_alias="macAddresses",
    )

    @model_validator(mode="after")
    def _validate_mac_format(self) -> Self:
        for value in self.mac_addresses:
            if re.match(MAC_ADDRESS_PATTERN, value) is None:
                raise ValueError(f"invalid MAC address: {value!r}")
        return self


MacAddressCreate = Annotated[
    Union[MacAddressCreateSingle, MacAddressCreateList],
    Field(union_mode="left_to_right"),
]
"""The create payload for ``createMacAddress``: a single address or a list.

The API does not declare a discriminator on this request; the two shapes are
distinguished by which required member is present, so the union is resolved left to right
and both variants are closed.
"""


class MacAddressUpdateInput(_InputModel):
    """The ``updateMacAddressByIdOrName`` input: identifier plus partial PATCH fields."""

    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    mac_address: MacAddressString | None = Field(
        None,
        validation_alias=AliasChoices("mac_address", "macAddress"),
        serialization_alias="macAddress",
    )
    mac_addresses: list[MacAddressString] | None = Field(
        None,
        min_length=1,
        max_length=1000,
        validation_alias=AliasChoices("mac_addresses", "macAddresses"),
        serialization_alias="macAddresses",
    )

    @model_validator(mode="after")
    def _at_most_one_shape(self) -> Self:
        if self.mac_address is not None and self.mac_addresses is not None:
            raise ValueError("provide at most one of mac_address and mac_addresses")
        return self


class MacAddressResult(_OutputModel):
    """Object-rooted wrapper for a single MAC address response."""

    address: MacAddress


class MacAddressListInput(ListQuery):
    """Filters for ``getAllMacAddresses``."""


# -- Services --------------------------------------------------------------------------

ServiceType = Literal["tcpOrUdp", "ip", "icmp", "icmpv6"]

IpProtocol = Literal[
    "hopopt",
    "icmp",
    "igmp",
    "ggp",
    "ip",
    "st",
    "tcp",
    "cbt",
    "egp",
    "igp",
    "bbnRccMon",
    "nvpII",
    "pup",
    "argus",
    "emcon",
    "xnet",
    "chaos",
    "udp",
    "mux",
    "dcnMeas",
    "hmp",
    "prm",
    "xnsIdp",
    "trunk1",
    "trunk2",
    "leaf1",
    "leaf2",
    "rdp",
    "irtp",
    "isoTp4",
    "netblt",
    "mfeNsp",
    "meritInp",
    "dccp",
    "threePC",
    "idpr",
    "xtp",
    "ddp",
    "idprCmtp",
    "tpPlusPlus",
    "il",
    "ipv6",
    "sdrp",
    "ipv6Route",
    "ipv6Frag",
    "idrp",
    "rsvp",
    "gre",
    "dsr",
    "bna",
    "esp",
    "ah",
    "iNlsp",
    "swipe",
    "narp",
    "mobile",
    "tlsp",
    "skip",
    "ipv6Icmp",
    "ipv6NoNxt",
    "ipv6Opts",
    "ipProto61",
    "cftp",
    "ipProto63",
    "satExpak",
    "kryptolan",
    "rvd",
    "ippc",
    "ipProto68",
    "satMon",
    "visa",
    "ipcv",
    "cpnx",
    "cphb",
    "wsn",
    "pvp",
    "brSatMon",
    "sunNd",
    "wbMon",
    "wbExpak",
    "isoIp",
    "vmtp",
    "secureVmtp",
    "vines",
    "ttp",
    "nsfnetIgp",
    "dgp",
    "tcf",
    "eigrp",
    "ospfigp",
    "spriteRpc",
    "larp",
    "mtp",
    "ax25",
    "ipip",
    "micp",
    "sccSp",
    "etherip",
    "encap",
    "ipProto99",
    "gmtp",
    "ifmp",
    "pnni",
    "pim",
    "aris",
    "scps",
    "qnx",
    "aN",
    "ipComp",
    "snp",
    "compaqPeer",
    "ipxInIp",
    "vrrp",
    "pgm",
    "ipProto114",
    "l2tp",
    "ddx",
    "iatp",
    "stp",
    "srp",
    "uti",
    "smp",
    "sm",
    "ptp",
    "isis",
    "fire",
    "crtp",
    "crudp",
    "sscopmce",
    "iplt",
    "sps",
    "pipe",
    "sctp",
    "fc",
    "rsvpE2eIgnore",
    "ipProto135",
    "udpLite",
    "mplsInIp",
    "manet",
    "hip",
    "shim6",
    "wesp",
    "rohc",
    "ipProto143",
    "ipProto144",
    "ipProto145",
    "ipProto146",
    "ipProto147",
    "ipProto148",
    "ipProto149",
    "ipProto150",
    "ipProto151",
    "ipProto152",
    "ipProto153",
    "ipProto154",
    "ipProto155",
    "ipProto156",
    "ipProto157",
    "ipProto158",
    "ipProto159",
    "ipProto160",
    "ipProto161",
    "ipProto162",
    "ipProto163",
    "ipProto164",
    "ipProto165",
    "ipProto166",
    "ipProto167",
    "ipProto168",
    "ipProto169",
    "ipProto170",
    "ipProto171",
    "ipProto172",
    "ipProto173",
    "ipProto174",
    "ipProto175",
    "ipProto176",
    "ipProto177",
    "ipProto178",
    "ipProto179",
    "ipProto180",
    "ipProto181",
    "ipProto182",
    "ipProto183",
    "ipProto184",
    "ipProto185",
    "ipProto186",
    "ipProto187",
    "ipProto188",
    "ipProto189",
    "ipProto190",
    "ipProto191",
    "ipProto192",
    "ipProto193",
    "ipProto194",
    "ipProto195",
    "ipProto196",
    "ipProto197",
    "ipProto198",
    "ipProto199",
    "ipProto200",
    "ipProto201",
    "ipProto202",
    "ipProto203",
    "ipProto204",
    "ipProto205",
    "ipProto206",
    "ipProto207",
    "ipProto208",
    "ipProto209",
    "ipProto210",
    "ipProto211",
    "ipProto212",
    "ipProto213",
    "ipProto214",
    "ipProto215",
    "ipProto216",
    "ipProto217",
    "ipProto218",
    "ipProto219",
    "ipProto220",
    "ipProto221",
    "ipProto222",
    "ipProto223",
    "ipProto224",
    "ipProto225",
    "ipProto226",
    "ipProto227",
    "ipProto228",
    "ipProto229",
    "ipProto230",
    "ipProto231",
    "ipProto232",
    "ipProto233",
    "ipProto234",
    "ipProto235",
    "ipProto236",
    "ipProto237",
    "ipProto238",
    "ipProto239",
    "ipProto240",
    "ipProto241",
    "ipProto242",
    "ipProto243",
    "ipProto244",
    "ipProto245",
    "ipProto246",
    "ipProto247",
    "ipProto248",
    "ipProto249",
    "ipProto250",
    "ipProto251",
    "ipProto252",
    "ipProto253",
    "ipProto254",
    "ipProto255",
]
"""The IP-protocol names the API accepts for an ``ip`` service entry."""

IcmpType = Literal[
    "any",
    "echoReply",
    "destinationUnreachable",
    "sourceQuench",
    "redirectMessage",
    "alternateHostAddress",
    "echoRequest",
    "routerAdvertisement",
    "routerSolicitation",
    "timeExceeded",
    "parameterProblem",
    "timestamp",
    "timestampReply",
    "informationRequest",
    "informationReply",
    "addressMaskRequest",
    "addressMaskReply",
    "traceroute",
    "datagramConversionError",
    "mobileHostRedirect",
    "ipv6WhereAreYou",
    "ipv6IAmHere",
    "mobileRegistrationRequest",
    "mobileRegistrationReply",
    "domainNameRequest",
    "domainNameReply",
    "skip",
    "photuris",
]
"""The ICMPv4 types the API accepts."""

IcmpCode = Literal[
    "any",
    "noCode",
    "hopLimitExceededInTransit",
    "fragmentReassemblyTimeExceeded",
    "netUnreachable",
    "hostUnreachable",
    "protocolUnreachable",
    "portUnreachable",
    "fragmentationNeededAndDfSet",
    "sourceRouteFailed",
    "destinationNetworkUnknown",
    "destinationHostUnknown",
    "sourceHostIsolated",
    "networkAdministrativelyProhibited",
    "hostAdministrativelyProhibited",
    "networkUnreachableForTos",
    "hostUnreachableForTos",
    "communicationAdministrativelyProhibited",
    "hostPrecedenceViolation",
    "precedenceCutoffInEffect",
    "redirectForNetwork",
    "redirectForHost",
    "redirectForTosAndNetwork",
    "redirectForTosAndHost",
    "alternateAddressForHost",
    "ttlExceededInTransit",
    "pointerIndicatesError",
    "missingRequiredOption",
    "badLengthIndicatesError",
]
"""The ICMPv4 codes the API accepts."""

Icmpv6Type = Literal[
    "any",
    "destinationUnreachable",
    "packetTooBig",
    "timeExceeded",
    "parameterProblem",
    "privateExperimentation100",
    "privateExperimentation101",
    "echoRequest",
    "echoReply",
    "multicastListenerQuery",
    "multicastListenerReport",
    "multicastListenerDone",
    "routerSolicitation",
    "routerAdvertisement",
    "neighborSolicitation",
    "neighborAdvertisement",
    "redirectMessage",
    "routerRenumbering",
    "nodeInformationQuery",
    "nodeInformationResponse",
    "inverseNeighborDiscoverySolicitation",
    "inverseNeighborDiscoveryAdvertisement",
    "multicastListenerReportV2",
    "homeAgentDiscoveryRequest",
    "homeAgentDiscoveryReply",
    "mobilePrefixSolicitation",
    "mobilePrefixAdvertisement",
    "certificationPathSolicitation",
    "certificationPathAdvertisement",
    "experimentalMobilityProtocols",
    "multicastRouterAdvertisement",
    "multicastRouterSolicitation",
    "multicastRouterTermination",
    "fmipv6",
    "rplControl",
    "ilnpv6LocatorUpdate",
    "duplicateAddressRequest",
    "duplicateAddressConfirmation",
    "privateExperimentation200",
    "privateExperimentation201",
]
"""The ICMPv6 types the API accepts."""

Icmpv6Code = Literal[
    "any",
    "noCode",
    "noRouteToDestination",
    "communicationWithDestinationNetworkIsAdministrativelyProhibited",
    "beyondScopeOfSourceAddress",
    "addressUnreachable",
    "portUnreachable",
    "sourceAddressFailedIngressEgressPolicy",
    "rejectRouteToDestination",
    "errorInSourceRoutingHeader",
    "hopLimitExceededInTransit",
    "fragmentReassemblyTimeExceeded",
    "fragmentationNeededAndDfSet",
    "erroneousHeaderFieldEncountered",
    "unrecognizedNextHeaderType",
    "unrecognizedIpv6Option",
    "routerRenumberingCommand",
    "routerRenumberingResult",
    "sequenceNumberReset",
    "ipv6AddressSubject",
    "nameOrEmptySubject",
    "ipv4AddressSubject",
    "successfulReply",
    "responderRefuses",
    "unknownQtype",
]
"""The ICMPv6 codes the API accepts."""


class _ServicePortRangeFields(BaseModel):
    """A TCP/UDP port or port range. Both members are optional in the API."""

    from_port: int | None = Field(None, alias="from", ge=1, le=65535)
    to_port: int | None = Field(None, alias="to", ge=1, le=65535)

    @model_validator(mode="after")
    def _check_range(self) -> Self:
        if self.from_port is not None and self.to_port is None:
            raise ValueError("'to' is required when 'from' is set")
        if (
            self.from_port is not None
            and self.to_port is not None
            and self.to_port < self.from_port
        ):
            raise ValueError("'to' must be greater than or equal to 'from'")
        return self


class ServicePortRange(_ServicePortRangeFields):
    """A port range in a service create or update payload."""

    model_config = _INPUT_CONFIG


class ServicePortRangeOutput(ServicePortRange, _OutputModel):
    """A port range in a service response."""

    model_config = _OUTPUT_CONFIG


class TcpUdpServiceDetail(_InputModel):
    """A TCP or UDP service detail entry."""

    protocol: Literal["tcp", "udp"]
    source_port: ServicePortRange | None = Field(
        None,
        validation_alias=AliasChoices("source_port", "sourcePort"),
        serialization_alias="sourcePort",
    )
    destination_port: ServicePortRange | None = Field(
        None,
        validation_alias=AliasChoices("destination_port", "destinationPort"),
        serialization_alias="destinationPort",
    )


class IpProtocolServiceDetail(_InputModel):
    """An IP-protocol service detail entry."""

    ip_protocol: IpProtocol = Field(
        validation_alias=AliasChoices("ip_protocol", "ipProtocol"),
        serialization_alias="ipProtocol",
    )


class Icmpv4ServiceDetail(_InputModel):
    """An ICMPv4 service detail entry; both type and code are required."""

    icmp_type: IcmpType = Field(
        validation_alias=AliasChoices("icmp_type", "icmpType"),
        serialization_alias="icmpType",
    )
    icmp_code: IcmpCode = Field(
        validation_alias=AliasChoices("icmp_code", "icmpCode"),
        serialization_alias="icmpCode",
    )


class Icmpv6ServiceDetail(_InputModel):
    """An ICMPv6 service detail entry; both type and code are required."""

    icmpv6_type: Icmpv6Type = Field(
        validation_alias=AliasChoices("icmpv6_type", "icmpv6Type"),
        serialization_alias="icmpv6Type",
    )
    icmpv6_code: Icmpv6Code = Field(
        validation_alias=AliasChoices("icmpv6_code", "icmpv6Code"),
        serialization_alias="icmpv6Code",
    )


ServiceDetail = Annotated[
    Union[
        TcpUdpServiceDetail,
        IpProtocolServiceDetail,
        Icmpv4ServiceDetail,
        Icmpv6ServiceDetail,
    ],
    Field(union_mode="left_to_right"),
]
"""One protocol-specific service detail entry.

The API has no discriminator: the entry shape is identified by which required member
is present (``protocol``, ``ipProtocol``, ``icmpType``/``icmpCode`` or
``icmpv6Type``/``icmpv6Code``). Left-to-right resolution is deterministic because every
variant is closed.
"""


class TcpUdpServiceDetailOutput(TcpUdpServiceDetail, _OutputModel):
    """A TCP or UDP service detail entry in a response."""

    model_config = _OUTPUT_CONFIG
    source_port: ServicePortRangeOutput | None = Field(None, alias="sourcePort")
    destination_port: ServicePortRangeOutput | None = Field(None, alias="destinationPort")


class IpProtocolServiceDetailOutput(IpProtocolServiceDetail, _OutputModel):
    """An IP-protocol service detail entry in a response."""

    model_config = _OUTPUT_CONFIG
    # Re-declared with the wire alias: the response projection keeps the API's
    # camelCase name in its published schema, while the request model publishes the
    # snake_case name.
    ip_protocol: IpProtocol = Field(alias="ipProtocol")


class Icmpv4ServiceDetailOutput(Icmpv4ServiceDetail, _OutputModel):
    """An ICMPv4 service detail entry in a response."""

    model_config = _OUTPUT_CONFIG
    # Re-declared with the wire aliases so the response projection keeps the API's
    # camelCase names in its published schema (the convention applies to the input surface).
    icmp_type: IcmpType = Field(alias="icmpType")
    icmp_code: IcmpCode = Field(alias="icmpCode")


class Icmpv6ServiceDetailOutput(Icmpv6ServiceDetail, _OutputModel):
    """An ICMPv6 service detail entry in a response."""

    model_config = _OUTPUT_CONFIG
    # Re-declared with the wire aliases so the response projection keeps the API's
    # camelCase names in its published schema (the convention applies to the input surface).
    icmpv6_type: Icmpv6Type = Field(alias="icmpv6Type")
    icmpv6_code: Icmpv6Code = Field(alias="icmpv6Code")


ServiceDetailOutput = Annotated[
    Union[
        TcpUdpServiceDetailOutput,
        IpProtocolServiceDetailOutput,
        Icmpv4ServiceDetailOutput,
        Icmpv6ServiceDetailOutput,
    ],
    Field(union_mode="left_to_right"),
]
"""One protocol-specific service detail entry as returned by the appliance."""


class Service(_OutputModel):
    """A network service. The API requires ``name``, ``type`` and ``services``."""

    id: str | None = None
    name: str = Field(..., max_length=50)
    description: str | None = Field(None, max_length=255)
    type: ServiceType
    services: list[ServiceDetailOutput] = Field(..., min_length=1)
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class ServiceCreate(_InputModel):
    """Create a network service. ``type`` and at least one detail entry are required."""

    name: ObjectName = Field(..., max_length=50)
    description: str | None = Field(None, max_length=255)
    type: ServiceType
    services: list[ServiceDetail] = Field(..., min_length=1, max_length=100)


class ServiceUpdateInput(_InputModel):
    """The ``updateServiceByIdOrName`` input: identifier plus partial PATCH fields.

    ``type`` is deliberately absent: the API's PATCH schema does not allow changing
    the service type.
    """

    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=50)
    description: str | None = Field(None, max_length=255)
    services: list[ServiceDetail] | None = Field(None, min_length=1, max_length=100)


class ServiceListInput(ListQuery):
    """Filters for ``getAllServices``; ``type`` is the API's enum filter.

    The appliance ignores the ``type`` query parameter (observed on the appliance: all
    four enum values return the same mixed page), so the adapter also filters the projected
    page client-side. The parameter is still sent because the API declares it, and a
    firmware that honours it makes the client-side filter a no-op.
    """

    type: ServiceType | None = None

    def filters(self) -> dict[str, str]:
        params = super().filters()
        if self.type is not None:
            params["type"] = self.type
        return params


class ServiceGroup(_OutputModel):
    """A service group. Members are name references to existing services."""

    id: str
    name: str = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    services: list[ObjectRef] = Field(..., min_length=1)
    created_at: datetime | None = Field(None, alias="createdAt")
    updated_at: datetime | None = Field(None, alias="updatedAt")


class ServiceGroupCreate(_InputModel):
    """Create a service group from existing network services."""

    name: ObjectName = Field(..., max_length=60)
    description: str | None = Field(None, max_length=255)
    services: list[ServiceMemberRef] = Field(..., min_length=1)


class ServiceGroupUpdateInput(_InputModel):
    """The ``updateServiceGroupByIdOrName`` input: identifier plus partial fields."""

    id_or_name: ObjectNameOrId = Field(..., min_length=1, max_length=60)
    name: ObjectName | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=255)
    services: list[ServiceMemberRef] | None = Field(None, min_length=1)


class ServiceGroupListInput(ListQuery):
    """Filters for ``getAllServiceGroups``."""
