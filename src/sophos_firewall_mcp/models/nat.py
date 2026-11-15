"""Pydantic models for the Sophos Firewall NAT-rule domain (IPv4 and IPv6).

The Sophos API (``firewall_config_openapi.yaml``) defines NAT rules as **one rule base per IP
family** with no SNAT/DNAT discriminator: a rule always carries its match fields
(``originalServicesOrGroups``, ``inboundInterfaces``, ``outboundInterfaces``,
``originalSourceNetworks``, ``originalDestinationNetworks``) and *may* carry translation
fields (``translatedSource``, ``translatedDestination``, ``translatedService``,
``overrideSnatForOutboundInterfaces``). This module models exactly those fields and never
invents a variant enum.

Family differences, taken from the parsed contract:

* IPv4 source networks select ``macAddresses``, ``ipv4Addresses``, ``ipv4Groups``,
  ``fqdnAddresses``, ``fqdnGroups``, ``countries`` and ``countryGroups``; IPv6 selects
  ``macAddresses``, ``ipv6Addresses`` and ``ipv6Groups``.
* IPv4 ``translatedSource`` is ``masq`` or ``ipv4Address``; IPv6 is ``masq`` or
  ``ipv6Address``.
* IPv4 ``translatedDestination`` is ``ipv4Address`` or ``fqdnAddress``; IPv6 is an object
  with a required ``ipv6Address``.
* The per-interface source-NAT override entry follows the same family: IPv4 uses
  ``ipv4Address``, IPv6 uses ``ipv6Address``.

Request bodies are closed (``extra="forbid"``) and use snake_case field names with the
contract's camelCase wire names as serialization aliases. Update bodies are partial: the
adapter serializes them with ``exclude_unset=True`` so omitted properties keep their stored
value (JSON Merge Patch, RFC 7396), while an explicit ``null`` removes a property.

The ``*Wire`` models parse appliance payloads (``extra="ignore"``, forward-compatible) and
are never returned to a model; the ``project_*`` functions turn them into the bounded DTOs
the tools publish. Bulk delete (``bulkDeleteNatRulesIpv4`` / ``bulkDeleteNatRulesIpv6``) is
deliberately absent: it is classified in ``docs/API-COVERAGE.md`` and never registered.

Naming (phase 5): the **inputs** are snake_case because the model writes them, and the
**outputs** keep the Sophos wire names (camelCase) because they are projections of the
appliance payload. The two conventions meet only in the ``project_*`` functions, which map
one onto the other explicitly. Object references are projected to the shared
:class:`~sophos_firewall_mcp.models.common.ObjectRef` shape (``{"name": …}``), the shape the
firewall-rule projections already use. Two members are derived rather than read:
``kind`` and ``position``.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal, Mapping

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    model_validator,
)

from sophos_firewall_mcp.models.common import ListPage, ObjectRef, validate_object_name
from sophos_firewall_mcp.models.objects import serialize_epoch_sentinel

__all__ = [
    "HealthCheckProtocol",
    "InterfaceName",
    "InterfaceRef",
    "LoadBalancingMethod",
    "NatRuleCreateIpv4Input",
    "NatRuleCreateIpv6Input",
    "NatRuleDeleteInput",
    "NatRuleDeleteOutput",
    "NatRuleGetInput",
    "NatRuleHealthCheckInput",
    "NatRuleHealthCheckOutput",
    "NatRuleHealthCheckRuleInput",
    "NatRuleIdOrName",
    "NatRuleInterfacesInput",
    "NatRuleInterfacesOutput",
    "NatRuleIpv4NetworksInput",
    "NatRuleIpv4SnatOverrideInput",
    "NatRuleIpv4TranslatedDestinationInput",
    "NatRuleIpv4TranslatedSourceInput",
    "NatRuleIpv6NetworksInput",
    "NatRuleIpv6SnatOverrideInput",
    "NatRuleIpv6TranslatedDestinationInput",
    "NatRuleIpv6TranslatedSourceInput",
    "NatRuleKind",
    "NatRuleListInput",
    "NatRuleMoveInput",
    "NatRuleMoveOutput",
    "NatRuleName",
    "NatRuleNameRef",
    "NatRuleNetworksOutput",
    "NatRuleOutput",
    "NatRulePosition",
    "NatRuleServicesInput",
    "NatRuleServicesOutput",
    "NatRuleSnatOverrideOutput",
    "NatRuleTranslationOutput",
    "NatRuleUpdateIpv4Input",
    "NatRuleUpdateIpv6Input",
    "NatRuleWire",
    "ObjectRefInput",
    "ObjectRefName",
    "ServiceName",
    "ServiceRef",
    "project_nat_rule",
    "project_nat_rule_page",
    "validate_object_name_or_id",
]

#: Where a NAT rule is inserted, relative to the rule base or a reference rule.
NatRulePosition = Literal["top", "bottom", "after", "before"]

#: The API's ``loadBalancingMethod`` vocabulary (input is closed to it; the output keeps
#: a plain ``str`` so a future firmware value does not fail a read).
LoadBalancingMethod = Literal["roundRobin", "firstAlive", "random", "stickyIp", "oneToOne"]

#: The API's health-check probe protocols (input is closed; output stays a plain ``str``).
HealthCheckProtocol = Literal["tcp", "icmp"]

#: UUID shape of the ``sfos-object-name-or-id`` format (the YAML ``format`` carries no
#: assertion, so the model enforces it).
_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Sequences the shared REST client refuses in a path. ``quote(..., safe="")`` encodes
#: ``?``, ``#``, ``/`` and ``\\`` but leaves ``.`` untouched, so a name containing ``..``
#: cannot be addressed through the transport and is rejected here with a clear message
#: instead of surfacing as an unexpected client ``ValueError``.
_UNSAFE_PATH_SEQUENCES = ("..", "\\", "?", "#", "://", "%2e")


def validate_object_name_or_id(value: str) -> str:
    """Validate the documented ``sfos-object-name-or-id`` path format.

    A UUID is accepted as-is; anything else must be a valid ``sfos-object-name`` and must be
    addressable through the shared REST client (no ``..`` and no other path-significant
    sequence).

    Raises:
        ValueError: The value is neither a UUID nor an addressable object name.
    """
    if not isinstance(value, str):
        raise ValueError("identifier must be a string")
    if _UUID_PATTERN.match(value):
        return value
    validate_object_name(value)
    lowered = value.lower()
    for sequence in _UNSAFE_PATH_SEQUENCES:
        if sequence in lowered:
            raise ValueError(
                f"object name must not contain {sequence!r}: it is not addressable as a "
                "path segment; use the object's UUID instead"
            )
    return value


#: ``str`` annotated with the documented ``sfos-object-name-or-id`` validation.
NatRuleIdOrName = Annotated[str, AfterValidator(validate_object_name_or_id)]

#: NAT-rule name: ``sfos-object-name``, at most 60 characters (create/move bodies).
NatRuleName = Annotated[
    str, Field(min_length=1, max_length=60), AfterValidator(validate_object_name)
]

#: Interface name: ``sfos-object-name``, at most 58 characters.
InterfaceName = Annotated[
    str, Field(min_length=1, max_length=58), AfterValidator(validate_object_name)
]

#: Service name: ``sfos-object-name``, at most 50 characters.
ServiceName = Annotated[
    str, Field(min_length=1, max_length=50), AfterValidator(validate_object_name)
]

#: Address/group/country reference name: ``sfos-object-name``, at most 60 characters.
ObjectRefName = Annotated[
    str, Field(min_length=1, max_length=60), AfterValidator(validate_object_name)
]


# -- Inputs: references and match selections -------------------------------------------


class NatRuleNameRef(BaseModel):
    """``{name}`` reference to another NAT rule (``referenceItem``/``linkedFirewallRule``)."""

    model_config = ConfigDict(extra="forbid")

    name: NatRuleName = Field(description="Name of the referenced NAT rule.")


class InterfaceRef(BaseModel):
    """``{name}`` reference to an interface."""

    model_config = ConfigDict(extra="forbid")

    name: InterfaceName = Field(description="Name of the interface.")


class ServiceRef(BaseModel):
    """``{name}`` reference to a service object."""

    model_config = ConfigDict(extra="forbid")

    name: ServiceName = Field(description="Name of the service object.")


class ObjectRefInput(BaseModel):
    """``{name}`` reference to an address, group or country object."""

    model_config = ConfigDict(extra="forbid")

    name: ObjectRefName = Field(description="Name of the referenced object.")


class NatRuleServicesInput(BaseModel):
    """``originalServicesOrGroups``: match any service, or a non-empty selection.

    The API models this as ``oneOf [{any: true}, {services?, serviceGroups?}]`` with
    ``minProperties: 1`` on the selected variant. Exactly one variant is sent, and the
    selected variant must select at least one object.
    """

    model_config = ConfigDict(extra="forbid")

    any: Literal[True] | None = Field(
        default=None, description="Match any service. Mutually exclusive with the selections."
    )
    services: list[ServiceRef] | None = Field(default=None, description="Selected service objects.")
    service_groups: list[ObjectRefInput] | None = Field(
        default=None,
        serialization_alias="serviceGroups",
        description="Selected service-group objects.",
    )

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "NatRuleServicesInput":
        selected = self.services or self.service_groups
        if self.any is True:
            if selected:
                raise ValueError(
                    "any=true and services/service_groups are mutually exclusive; provide one"
                )
            return self
        if not selected:
            raise ValueError("provide either any=true or at least one of services/service_groups")
        return self


class NatRuleInterfacesInput(BaseModel):
    """``inboundInterfaces``/``outboundInterfaces``: match any interface, or a selection.

    The API models this as ``oneOf [{any: true}, {interfaces: [...]}]``. Exactly one
    variant is sent, and the selected variant must name at least one interface.
    """

    model_config = ConfigDict(extra="forbid")

    any: Literal[True] | None = Field(
        default=None, description="Match any interface. Mutually exclusive with interfaces."
    )
    interfaces: list[InterfaceRef] | None = Field(default=None, description="Selected interfaces.")

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "NatRuleInterfacesInput":
        if self.any is True:
            if self.interfaces:
                raise ValueError("any=true and interfaces are mutually exclusive; provide one")
            return self
        if not self.interfaces:
            raise ValueError("provide either any=true or at least one interface")
        return self


class NatRuleIpv4NetworksInput(BaseModel):
    """IPv4 ``originalSourceNetworks``/``originalDestinationNetworks`` selection.

    The API models this as ``oneOf [{any: true}, {macAddresses?, ipv4Addresses?,
    ipv4Groups?, fqdnAddresses?, fqdnGroups?, countries?, countryGroups?}]`` with
    ``minProperties: 1`` on the selected variant.
    """

    model_config = ConfigDict(extra="forbid")

    any: Literal[True] | None = Field(
        default=None, description="Match any network. Mutually exclusive with the selections."
    )
    mac_addresses: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="macAddresses", description="Selected MAC hosts."
    )
    ipv4_addresses: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="ipv4Addresses", description="Selected IPv4 hosts."
    )
    ipv4_groups: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="ipv4Groups", description="Selected IPv4 groups."
    )
    fqdn_addresses: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="fqdnAddresses", description="Selected FQDN hosts."
    )
    fqdn_groups: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="fqdnGroups", description="Selected FQDN groups."
    )
    countries: list[ObjectRefInput] | None = Field(default=None, description="Selected countries.")
    country_groups: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="countryGroups", description="Selected country groups."
    )

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "NatRuleIpv4NetworksInput":
        selected = (
            self.mac_addresses
            or self.ipv4_addresses
            or self.ipv4_groups
            or self.fqdn_addresses
            or self.fqdn_groups
            or self.countries
            or self.country_groups
        )
        if self.any is True:
            if selected:
                raise ValueError(
                    "any=true and the network selections are mutually exclusive; provide one"
                )
            return self
        if not selected:
            raise ValueError("provide either any=true or at least one IPv4 network selection")
        return self


class NatRuleIpv6NetworksInput(BaseModel):
    """IPv6 ``originalSourceNetworks``/``originalDestinationNetworks`` selection.

    The API models this as ``oneOf [{any: true}, {macAddresses?, ipv6Addresses?,
    ipv6Groups?}]`` with ``minProperties: 1`` on the selected variant.
    """

    model_config = ConfigDict(extra="forbid")

    any: Literal[True] | None = Field(
        default=None, description="Match any network. Mutually exclusive with the selections."
    )
    mac_addresses: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="macAddresses", description="Selected MAC hosts."
    )
    ipv6_addresses: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="ipv6Addresses", description="Selected IPv6 hosts."
    )
    ipv6_groups: list[ObjectRefInput] | None = Field(
        default=None, serialization_alias="ipv6Groups", description="Selected IPv6 groups."
    )

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "NatRuleIpv6NetworksInput":
        selected = self.mac_addresses or self.ipv6_addresses or self.ipv6_groups
        if self.any is True:
            if selected:
                raise ValueError(
                    "any=true and the network selections are mutually exclusive; provide one"
                )
            return self
        if not selected:
            raise ValueError("provide either any=true or at least one IPv6 network selection")
        return self


class NatRuleIpv4TranslatedSourceInput(BaseModel):
    """IPv4 ``translatedSource``: masquerade or an IPv4 address object."""

    model_config = ConfigDict(extra="forbid")

    masq: Literal[True] | None = Field(
        default=None, description="Masquerade through the outbound interface IP."
    )
    ipv4_address: ObjectRefInput | None = Field(
        default=None,
        serialization_alias="ipv4Address",
        description="IPv4 address object to translate the source to.",
    )

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "NatRuleIpv4TranslatedSourceInput":
        if (self.masq is True) == (self.ipv4_address is not None):
            raise ValueError("provide exactly one of masq=true or ipv4_address")
        return self


class NatRuleIpv6TranslatedSourceInput(BaseModel):
    """IPv6 ``translatedSource``: masquerade or an IPv6 address object."""

    model_config = ConfigDict(extra="forbid")

    masq: Literal[True] | None = Field(
        default=None, description="Masquerade through the outbound interface IP."
    )
    ipv6_address: ObjectRefInput | None = Field(
        default=None,
        serialization_alias="ipv6Address",
        description="IPv6 address object to translate the source to.",
    )

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "NatRuleIpv6TranslatedSourceInput":
        if (self.masq is True) == (self.ipv6_address is not None):
            raise ValueError("provide exactly one of masq=true or ipv6_address")
        return self


class NatRuleIpv4TranslatedDestinationInput(BaseModel):
    """IPv4 ``translatedDestination``: an IPv4 address or FQDN address object."""

    model_config = ConfigDict(extra="forbid")

    ipv4_address: ObjectRefInput | None = Field(
        default=None,
        serialization_alias="ipv4Address",
        description="IPv4 address object to translate the destination to.",
    )
    fqdn_address: ObjectRefInput | None = Field(
        default=None,
        serialization_alias="fqdnAddress",
        description="FQDN address object to translate the destination to.",
    )

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "NatRuleIpv4TranslatedDestinationInput":
        if (self.ipv4_address is not None) == (self.fqdn_address is not None):
            raise ValueError("provide exactly one of ipv4_address or fqdn_address")
        return self


class NatRuleIpv6TranslatedDestinationInput(BaseModel):
    """IPv6 ``translatedDestination``: an object with a required ``ipv6Address``."""

    model_config = ConfigDict(extra="forbid")

    ipv6_address: ObjectRefInput = Field(
        serialization_alias="ipv6Address",
        description="IPv6 address object to translate the destination to.",
    )


class NatRuleHealthCheckRuleInput(BaseModel):
    """Probe settings of a NAT-rule health check."""

    model_config = ConfigDict(extra="forbid")

    protocol: HealthCheckProtocol = Field(description="Probe protocol.")
    port: int | None = Field(default=None, ge=1, le=65535, description="TCP port for probe checks.")
    interval: int = Field(ge=5, le=65535, description="Probe interval in seconds.")
    timeout: int = Field(ge=1, le=10, description="Probe timeout in seconds.")
    retry: int | None = Field(default=None, ge=1, le=10, description="Probe retry attempts.")


class NatRuleHealthCheckInput(BaseModel):
    """``healthCheck``: the API wraps the probe settings in a ``rule`` object."""

    model_config = ConfigDict(extra="forbid")

    rule: NatRuleHealthCheckRuleInput = Field(description="Health-check probe settings.")


class NatRuleIpv4SnatOverrideInput(BaseModel):
    """One IPv4 per-interface source-NAT override entry."""

    model_config = ConfigDict(extra="forbid")

    outbound_interface: InterfaceRef = Field(
        serialization_alias="outboundInterface",
        description="Outbound interface the override applies to.",
    )
    translated_source: NatRuleIpv4TranslatedSourceInput = Field(
        serialization_alias="translatedSource",
        description="Source translation for this outbound interface.",
    )


class NatRuleIpv6SnatOverrideInput(BaseModel):
    """One IPv6 per-interface source-NAT override entry."""

    model_config = ConfigDict(extra="forbid")

    outbound_interface: InterfaceRef = Field(
        serialization_alias="outboundInterface",
        description="Outbound interface the override applies to.",
    )
    translated_source: NatRuleIpv6TranslatedSourceInput = Field(
        serialization_alias="translatedSource",
        description="Source translation for this outbound interface.",
    )


# -- Inputs: list, get, delete ---------------------------------------------------------


class NatRuleListInput(BaseModel):
    """Query contract of ``getAllNatRulesIpv4``/``getAllNatRulesIpv6``.

    One page per call. ``nameContains`` and ``nameNotEquals`` are documented as mutually
    exclusive, so at most one may be set.

    ``page_size`` defaults to 10: a NAT rule is a large object (the tested appliance's
    28-rule base is ~44 KB of JSON), so a default call must stay small and the caller raises
    the page size explicitly when it wants a bigger page.
    """

    model_config = ConfigDict(extra="forbid")

    page: int = Field(
        default=1,
        ge=1,
        description="1-based page number; 0 is rejected before the request is sent.",
    )
    page_size: int = Field(
        default=10,
        ge=1,
        le=100,
        description=(
            "Page size, 1-100. Defaults to 10 so a default call stays small; a NAT rule is "
            "a large object, so raise it deliberately. The appliance rejects values above 100."
        ),
    )
    page_total: bool = Field(
        default=False,
        serialization_alias="pageTotal",
        description=(
            "Also request pages.total (the number of pages) and pages.items (the number "
            "of items) in the response metadata."
        ),
    )
    name_contains: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        serialization_alias="nameContains",
        description="Only return rules whose name contains this value.",
    )
    name_not_equals: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        serialization_alias="nameNotEquals",
        description="Exclude the rule with exactly this name.",
    )

    @model_validator(mode="after")
    def _at_most_one_name_filter(self) -> "NatRuleListInput":
        if self.name_contains is not None and self.name_not_equals is not None:
            raise ValueError(
                "name_contains and name_not_equals are mutually exclusive; provide at most one"
            )
        return self


class NatRuleGetInput(BaseModel):
    """Input of ``getNatRuleIpv4ByIdOrName``/``getNatRuleIpv6ByIdOrName``."""

    model_config = ConfigDict(extra="forbid")

    id_or_name: NatRuleIdOrName = Field(description="Name or UUID of the NAT rule.")


class NatRuleDeleteInput(BaseModel):
    """Input of ``deleteNatRuleIpv4ByIdOrName``/``deleteNatRuleIpv6ByIdOrName``."""

    model_config = ConfigDict(extra="forbid")

    id_or_name: NatRuleIdOrName = Field(description="Name or UUID of the NAT rule.")


# -- Inputs: create --------------------------------------------------------------------


def _require_anchor(
    position: NatRulePosition | None, reference_item: NatRuleNameRef | None
) -> None:
    """Reject ``after``/``before`` without an anchor; ``top``/``bottom`` need none."""
    if position in ("after", "before") and reference_item is None:
        raise ValueError(
            "position 'after' or 'before' requires referenceItem; use 'top' or 'bottom' "
            "to position without an anchor"
        )


class _NatRuleCreateBase(BaseModel):
    """Fields shared by the IPv4 and IPv6 create bodies.

    The API requires ``name``, ``originalServicesOrGroups``, ``inboundInterfaces``,
    ``outboundInterfaces`` and (in the family-specific half) the two original-network
    selections. ``enabled`` defaults to ``true`` in the API; the tool always sends the
    resolved value so the created state is explicit.
    """

    model_config = ConfigDict(extra="forbid")

    name: NatRuleName = Field(description="Name of the NAT rule.")
    description: str | None = Field(
        default=None, max_length=255, description="Free-text description."
    )
    enabled: bool = Field(
        default=True, description="Turn the NAT rule on or off (contract default: true)."
    )
    position: NatRulePosition | None = Field(
        default=None, description="Where to insert the rule in the rule base."
    )
    reference_item: NatRuleNameRef | None = Field(
        default=None,
        serialization_alias="referenceItem",
        description="Anchor rule for the after/before positions.",
    )
    linked_firewall_rule: NatRuleNameRef | None = Field(
        default=None,
        serialization_alias="linkedFirewallRule",
        description="Firewall rule to link this NAT rule to.",
    )
    original_services_or_groups: NatRuleServicesInput = Field(
        serialization_alias="originalServicesOrGroups", description="Match services."
    )
    translated_service: ServiceRef | None = Field(
        default=None,
        serialization_alias="translatedService",
        description="Service object to translate to.",
    )
    inbound_interfaces: NatRuleInterfacesInput = Field(
        serialization_alias="inboundInterfaces", description="Match inbound interfaces."
    )
    outbound_interfaces: NatRuleInterfacesInput = Field(
        serialization_alias="outboundInterfaces", description="Match outbound interfaces."
    )
    load_balancing_method: LoadBalancingMethod | None = Field(
        default=None,
        serialization_alias="loadBalancingMethod",
        description="Load-balancing method of the NAT rule.",
    )
    health_check: NatRuleHealthCheckInput | None = Field(
        default=None, serialization_alias="healthCheck", description="Health-check settings."
    )

    @model_validator(mode="after")
    def _check_position(self) -> "_NatRuleCreateBase":
        """Reject an anchored position without its anchor before any request is sent."""
        _require_anchor(self.position, self.reference_item)
        return self


class NatRuleCreateIpv4Input(_NatRuleCreateBase):
    """Body of ``createNatRuleIpv4``."""

    original_source_networks: NatRuleIpv4NetworksInput = Field(
        serialization_alias="originalSourceNetworks", description="Match source networks."
    )
    original_destination_networks: NatRuleIpv4NetworksInput = Field(
        serialization_alias="originalDestinationNetworks",
        description="Match destination networks.",
    )
    translated_source: NatRuleIpv4TranslatedSourceInput | None = Field(
        default=None,
        serialization_alias="translatedSource",
        description="Source NAT translation.",
    )
    translated_destination: NatRuleIpv4TranslatedDestinationInput | None = Field(
        default=None,
        serialization_alias="translatedDestination",
        description="Destination NAT translation.",
    )
    override_snat_for_outbound_interfaces: list[NatRuleIpv4SnatOverrideInput] | None = Field(
        default=None,
        serialization_alias="overrideSnatForOutboundInterfaces",
        description="Per-outbound-interface source-NAT overrides.",
    )


class NatRuleCreateIpv6Input(_NatRuleCreateBase):
    """Body of ``createNatRuleIpv6``."""

    original_source_networks: NatRuleIpv6NetworksInput = Field(
        serialization_alias="originalSourceNetworks", description="Match source networks."
    )
    original_destination_networks: NatRuleIpv6NetworksInput = Field(
        serialization_alias="originalDestinationNetworks",
        description="Match destination networks.",
    )
    translated_source: NatRuleIpv6TranslatedSourceInput | None = Field(
        default=None,
        serialization_alias="translatedSource",
        description="Source NAT translation.",
    )
    translated_destination: NatRuleIpv6TranslatedDestinationInput | None = Field(
        default=None,
        serialization_alias="translatedDestination",
        description="Destination NAT translation.",
    )
    override_snat_for_outbound_interfaces: list[NatRuleIpv6SnatOverrideInput] | None = Field(
        default=None,
        serialization_alias="overrideSnatForOutboundInterfaces",
        description="Per-outbound-interface source-NAT overrides.",
    )


# -- Inputs: update (PATCH, JSON Merge Patch) ------------------------------------------


class _NatRuleUpdateBase(BaseModel):
    """Fields shared by the IPv4 and IPv6 update bodies.

    Only the fields the caller sets are sent: omitted fields keep their stored value and an
    explicit ``null`` removes a property (RFC 7396). ``name`` and ``enabled`` cannot be
    removed because every NAT rule has them.
    """

    model_config = ConfigDict(extra="forbid")

    id_or_name: NatRuleIdOrName = Field(description="Name or UUID of the NAT rule to update.")
    name: NatRuleName | None = Field(default=None, description="New name of the NAT rule.")
    description: str | None = Field(
        default=None, max_length=255, description="Free-text description."
    )
    enabled: bool | None = Field(default=None, description="Turn the NAT rule on or off.")
    original_services_or_groups: NatRuleServicesInput | None = Field(
        default=None, serialization_alias="originalServicesOrGroups", description="Match services."
    )
    translated_service: ServiceRef | None = Field(
        default=None,
        serialization_alias="translatedService",
        description="Service object to translate to.",
    )
    inbound_interfaces: NatRuleInterfacesInput | None = Field(
        default=None,
        serialization_alias="inboundInterfaces",
        description="Match inbound interfaces.",
    )
    outbound_interfaces: NatRuleInterfacesInput | None = Field(
        default=None,
        serialization_alias="outboundInterfaces",
        description="Match outbound interfaces.",
    )
    load_balancing_method: LoadBalancingMethod | None = Field(
        default=None,
        serialization_alias="loadBalancingMethod",
        description="Load-balancing method of the NAT rule.",
    )
    health_check: NatRuleHealthCheckInput | None = Field(
        default=None, serialization_alias="healthCheck", description="Health-check settings."
    )

    @model_validator(mode="after")
    def _at_least_one_update(self) -> "_NatRuleUpdateBase":
        if not (self.model_fields_set - {"id_or_name"}):
            raise ValueError("provide at least one field to update")
        for field in ("name", "enabled"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(
                    f"{field} cannot be null: every NAT rule keeps a name and an enabled state"
                )
        return self


class NatRuleUpdateIpv4Input(_NatRuleUpdateBase):
    """Body of ``updateNatRuleIpv4ByIdOrName`` (PATCH, JSON Merge Patch)."""

    original_source_networks: NatRuleIpv4NetworksInput | None = Field(
        default=None,
        serialization_alias="originalSourceNetworks",
        description="Match source networks.",
    )
    original_destination_networks: NatRuleIpv4NetworksInput | None = Field(
        default=None,
        serialization_alias="originalDestinationNetworks",
        description="Match destination networks.",
    )
    translated_source: NatRuleIpv4TranslatedSourceInput | None = Field(
        default=None,
        serialization_alias="translatedSource",
        description="Source NAT translation.",
    )
    translated_destination: NatRuleIpv4TranslatedDestinationInput | None = Field(
        default=None,
        serialization_alias="translatedDestination",
        description="Destination NAT translation.",
    )
    override_snat_for_outbound_interfaces: list[NatRuleIpv4SnatOverrideInput] | None = Field(
        default=None,
        serialization_alias="overrideSnatForOutboundInterfaces",
        description="Per-outbound-interface source-NAT overrides.",
    )


class NatRuleUpdateIpv6Input(_NatRuleUpdateBase):
    """Body of ``updateNatRuleIpv6ByIdOrName`` (PATCH, JSON Merge Patch)."""

    original_source_networks: NatRuleIpv6NetworksInput | None = Field(
        default=None,
        serialization_alias="originalSourceNetworks",
        description="Match source networks.",
    )
    original_destination_networks: NatRuleIpv6NetworksInput | None = Field(
        default=None,
        serialization_alias="originalDestinationNetworks",
        description="Match destination networks.",
    )
    translated_source: NatRuleIpv6TranslatedSourceInput | None = Field(
        default=None,
        serialization_alias="translatedSource",
        description="Source NAT translation.",
    )
    translated_destination: NatRuleIpv6TranslatedDestinationInput | None = Field(
        default=None,
        serialization_alias="translatedDestination",
        description="Destination NAT translation.",
    )
    override_snat_for_outbound_interfaces: list[NatRuleIpv6SnatOverrideInput] | None = Field(
        default=None,
        serialization_alias="overrideSnatForOutboundInterfaces",
        description="Per-outbound-interface source-NAT overrides.",
    )


# -- Inputs: move ----------------------------------------------------------------------


class NatRuleMoveInput(BaseModel):
    """Body of ``moveNatRuleIpv4``/``moveNatRuleIpv6``.

    The API documentation says the rule "must be identified by name", so ``name`` is
    required here even though the schema lists only ``position`` as required. ``after`` and
    ``before`` are only meaningful with a ``reference_item``.
    """

    model_config = ConfigDict(extra="forbid")

    name: NatRuleName = Field(description="Name of the NAT rule to move.")
    position: NatRulePosition = Field(description="Where to move the rule.")
    reference_item: NatRuleNameRef | None = Field(
        default=None,
        serialization_alias="referenceItem",
        description="Anchor rule for the after/before positions.",
    )

    @model_validator(mode="after")
    def _check_position(self) -> "NatRuleMoveInput":
        """Reject an anchored position without its anchor before any request is sent."""
        _require_anchor(self.position, self.reference_item)
        return self


# -- Outputs: bounded projections ------------------------------------------------------
#
# The field names below are the appliance's wire names (camelCase), like every other output
# projection in this server: the model reads them, so it reads what the API returns.
# Object references keep the shared ``{"name": …}`` shape.

#: Derived SNAT/DNAT discriminator of a NAT rule.
#:
#: The API declares no discriminator, so it is derived from which translation the
#: appliance populated: ``snat`` when only ``translatedSource`` carries a value, ``dnat``
#: when only ``translatedDestination`` does, and ``unknown`` when neither does -- or when
#: both do, because the API has no combined variant and the discriminator is never
#: guessed.
NatRuleKind = Literal["snat", "dnat", "unknown"]


class NatRuleServicesOutput(BaseModel):
    """Projected ``originalServicesOrGroups``: the variant marker plus referenced objects."""

    any: bool | None = Field(default=None, description="True when the rule matches any service.")
    services: list[ObjectRef] = Field(default_factory=list, description="Selected service objects.")
    serviceGroups: list[ObjectRef] = Field(
        default_factory=list, description="Selected service-group objects."
    )


class NatRuleInterfacesOutput(BaseModel):
    """Projected interface selection: the variant marker plus interface references."""

    any: bool | None = Field(default=None, description="True when the rule matches any interface.")
    interfaces: list[ObjectRef] = Field(
        default_factory=list, description="Selected interface objects."
    )


class NatRuleNetworksOutput(BaseModel):
    """Projected network selection: the variant marker plus referenced objects.

    One model covers both families: IPv4 rules populate the IPv4/FQDN/country members and
    IPv6 rules populate the IPv6 members.
    """

    any: bool | None = Field(default=None, description="True when the rule matches any network.")
    macAddresses: list[ObjectRef] = Field(default_factory=list)
    ipv4Addresses: list[ObjectRef] = Field(default_factory=list)
    ipv4Groups: list[ObjectRef] = Field(default_factory=list)
    fqdnAddresses: list[ObjectRef] = Field(default_factory=list)
    fqdnGroups: list[ObjectRef] = Field(default_factory=list)
    countries: list[ObjectRef] = Field(default_factory=list)
    countryGroups: list[ObjectRef] = Field(default_factory=list)
    ipv6Addresses: list[ObjectRef] = Field(default_factory=list)
    ipv6Groups: list[ObjectRef] = Field(default_factory=list)


class NatRuleTranslationOutput(BaseModel):
    """Projected source or destination translation.

    Exactly one member is set when the appliance returns a translation: ``masq`` for
    masquerading, or the referenced address object in the family member the API used
    (``ipv4Address``, ``fqdnAddress`` or ``ipv6Address``).
    """

    masq: bool | None = Field(default=None, description="True when the source is masqueraded.")
    ipv4Address: ObjectRef | None = None
    fqdnAddress: ObjectRef | None = None
    ipv6Address: ObjectRef | None = None


class NatRuleHealthCheckOutput(BaseModel):
    """Projected health-check probe settings."""

    protocol: str = Field(description="Probe protocol declared by the API: tcp or icmp.")
    port: int | None = None
    interval: int
    timeout: int
    retry: int | None = None


class NatRuleSnatOverrideOutput(BaseModel):
    """Projected per-outbound-interface source-NAT override."""

    outboundInterface: ObjectRef
    translatedSource: NatRuleTranslationOutput | None = None


class NatRuleOutput(BaseModel):
    """One NAT rule, projected from the appliance payload.

    This is the explicit, bounded projection the tools publish: the field names are the
    appliance's wire names, object references keep the ``{"name": …}`` shape, and no raw
    Sophos payload is returned. ``kind`` is derived from the populated translation and
    ``position`` is derived by the list tools. The epoch "never" sentinel is
    published as ``null`` (L6); see
    :func:`~sophos_firewall_mcp.models.objects.serialize_epoch_sentinel`.
    """

    @field_serializer(
        "createdAt", "updatedAt", "created_at", "updated_at", check_fields=False, when_used="json"
    )
    def _epoch_sentinel_is_absent(self, value: datetime | None) -> datetime | None:
        """Publish the appliance's epoch "never" sentinel as ``None`` (L6)."""
        return serialize_epoch_sentinel(value)

    id: str = Field(description="UUID of the NAT rule.")
    name: str
    description: str | None = None
    enabled: bool
    kind: NatRuleKind = Field(
        description="Derived SNAT/DNAT discriminator: 'snat' when only translatedSource is "
        "populated, 'dnat' when only translatedDestination is, 'unknown' when neither or "
        "both are."
    )
    position: int | None = Field(
        default=None,
        ge=1,
        description="1-based evaluation position in the rule base. The list tools derive it "
        "from the page offset and the item index; get/create/update return null because "
        "those operations do not expose it.",
    )
    linkedFirewallRule: ObjectRef | None = Field(
        default=None,
        description="Firewall rule linked to this NAT rule, when the appliance returns one.",
    )
    originalServicesOrGroups: NatRuleServicesOutput | None = None
    translatedService: ObjectRef | None = None
    inboundInterfaces: NatRuleInterfacesOutput | None = None
    outboundInterfaces: NatRuleInterfacesOutput | None = None
    loadBalancingMethod: str | None = Field(
        default=None,
        description="Load-balancing method; the API declares roundRobin, firstAlive, "
        "random, stickyIp or oneToOne.",
    )
    healthCheck: NatRuleHealthCheckOutput | None = None
    originalSourceNetworks: NatRuleNetworksOutput | None = None
    originalDestinationNetworks: NatRuleNetworksOutput | None = None
    translatedSource: NatRuleTranslationOutput | None = None
    translatedDestination: NatRuleTranslationOutput | None = None
    overrideSnatForOutboundInterfaces: list[NatRuleSnatOverrideOutput] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class NatRuleDeleteOutput(BaseModel):
    """Result of a single NAT-rule delete.

    The shared client's ``delete`` primitive discards the response body, so ``deleted`` is
    ``True`` because the appliance answered with a success status; the targeted identifier is
    echoed so the caller can correlate the result.
    """

    deleted: bool
    idOrName: str = Field(description="Identifier the delete was issued for.")


class NatRuleMoveOutput(BaseModel):
    """Result of a NAT-rule move: the appliance returns an empty success body.

    The applied request is echoed instead of inventing a response shape. ``referenceItem``
    keeps the ``{"name": …}`` shape the request used.
    """

    name: str
    position: NatRulePosition
    referenceItem: ObjectRef | None = None


# -- Wire models: parse the appliance payload, never returned --------------------------


class _WireRef(BaseModel):
    """``{name}`` reference as returned by the appliance."""

    model_config = ConfigDict(extra="ignore")

    name: str


class _WireServices(BaseModel):
    """``originalServicesOrGroups`` oneOf, parsed leniently."""

    model_config = ConfigDict(extra="ignore")

    any: bool | None = None
    services: list[_WireRef] = Field(default_factory=list)
    serviceGroups: list[_WireRef] = Field(default_factory=list)  # noqa: N815


class _WireInterfaces(BaseModel):
    """``inboundInterfaces``/``outboundInterfaces`` oneOf, parsed leniently."""

    model_config = ConfigDict(extra="ignore")

    any: bool | None = None
    interfaces: list[_WireRef] = Field(default_factory=list)


class _WireNetworks(BaseModel):
    """IPv4/IPv6 network-selection oneOf, parsed leniently for both families."""

    model_config = ConfigDict(extra="ignore")

    any: bool | None = None
    macAddresses: list[_WireRef] = Field(default_factory=list)  # noqa: N815
    ipv4Addresses: list[_WireRef] = Field(default_factory=list)  # noqa: N815
    ipv4Groups: list[_WireRef] = Field(default_factory=list)  # noqa: N815
    fqdnAddresses: list[_WireRef] = Field(default_factory=list)  # noqa: N815
    fqdnGroups: list[_WireRef] = Field(default_factory=list)  # noqa: N815
    countries: list[_WireRef] = Field(default_factory=list)
    countryGroups: list[_WireRef] = Field(default_factory=list)  # noqa: N815
    ipv6Addresses: list[_WireRef] = Field(default_factory=list)  # noqa: N815
    ipv6Groups: list[_WireRef] = Field(default_factory=list)  # noqa: N815


class _WireTranslation(BaseModel):
    """``translatedSource``/``translatedDestination`` oneOf, parsed leniently."""

    model_config = ConfigDict(extra="ignore")

    masq: bool | None = None
    ipv4Address: _WireRef | None = None  # noqa: N815
    fqdnAddress: _WireRef | None = None  # noqa: N815
    ipv6Address: _WireRef | None = None  # noqa: N815


class _WireHealthCheckRule(BaseModel):
    """Probe settings of a health check."""

    model_config = ConfigDict(extra="ignore")

    protocol: str
    port: int | None = None
    interval: int
    timeout: int
    retry: int | None = None


class _WireHealthCheck(BaseModel):
    """``healthCheck`` object."""

    model_config = ConfigDict(extra="ignore")

    rule: _WireHealthCheckRule


class _WireSnatOverride(BaseModel):
    """One per-outbound-interface source-NAT override entry."""

    model_config = ConfigDict(extra="ignore")

    outboundInterface: _WireRef  # noqa: N815
    translatedSource: _WireTranslation | None = None  # noqa: N815


class NatRuleWire(BaseModel):
    """NAT-rule payload of the get/create/update/list operations.

    Only the fields the output projection needs are declared; unknown members are ignored
    rather than echoed.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    description: str | None = None
    enabled: bool
    linkedFirewallRule: _WireRef | None = None  # noqa: N815
    originalServicesOrGroups: _WireServices | None = None  # noqa: N815
    translatedService: _WireRef | None = None  # noqa: N815
    inboundInterfaces: _WireInterfaces | None = None  # noqa: N815
    outboundInterfaces: _WireInterfaces | None = None  # noqa: N815
    loadBalancingMethod: str | None = None  # noqa: N815
    healthCheck: _WireHealthCheck | None = None  # noqa: N815
    originalSourceNetworks: _WireNetworks | None = None  # noqa: N815
    originalDestinationNetworks: _WireNetworks | None = None  # noqa: N815
    translatedSource: _WireTranslation | None = None  # noqa: N815
    translatedDestination: _WireTranslation | None = None  # noqa: N815
    overrideSnatForOutboundInterfaces: list[_WireSnatOverride] = Field(  # noqa: N815
        default_factory=list
    )
    createdAt: datetime | None = None  # noqa: N815
    updatedAt: datetime | None = None  # noqa: N815


# -- Projections -----------------------------------------------------------------------


def _ref(reference: _WireRef | None) -> ObjectRef | None:
    """Project one ``{name}`` reference, or ``None`` when the appliance omitted it."""
    if reference is None:
        return None
    return ObjectRef(name=reference.name)


def _refs(references: list[_WireRef]) -> list[ObjectRef]:
    """Project a list of ``{name}`` references to the shared shape, preserving order."""
    return [ObjectRef(name=reference.name) for reference in references]


def _project_services(wire: _WireServices | None) -> NatRuleServicesOutput | None:
    """Project a service selection, or ``None`` when the appliance omitted it."""
    if wire is None:
        return None
    return NatRuleServicesOutput(
        any=wire.any,
        services=_refs(wire.services),
        serviceGroups=_refs(wire.serviceGroups),
    )


def _project_interfaces(wire: _WireInterfaces | None) -> NatRuleInterfacesOutput | None:
    """Project an interface selection, or ``None`` when the appliance omitted it."""
    if wire is None:
        return None
    return NatRuleInterfacesOutput(any=wire.any, interfaces=_refs(wire.interfaces))


def _project_networks(wire: _WireNetworks | None) -> NatRuleNetworksOutput | None:
    """Project a network selection, or ``None`` when the appliance omitted it."""
    if wire is None:
        return None
    return NatRuleNetworksOutput(
        any=wire.any,
        macAddresses=_refs(wire.macAddresses),
        ipv4Addresses=_refs(wire.ipv4Addresses),
        ipv4Groups=_refs(wire.ipv4Groups),
        fqdnAddresses=_refs(wire.fqdnAddresses),
        fqdnGroups=_refs(wire.fqdnGroups),
        countries=_refs(wire.countries),
        countryGroups=_refs(wire.countryGroups),
        ipv6Addresses=_refs(wire.ipv6Addresses),
        ipv6Groups=_refs(wire.ipv6Groups),
    )


def _project_translation(wire: _WireTranslation | None) -> NatRuleTranslationOutput | None:
    """Project a translation, or ``None`` when the appliance omitted it."""
    if wire is None:
        return None
    return NatRuleTranslationOutput(
        masq=wire.masq,
        ipv4Address=_ref(wire.ipv4Address),
        fqdnAddress=_ref(wire.fqdnAddress),
        ipv6Address=_ref(wire.ipv6Address),
    )


def _project_health_check(wire: _WireHealthCheck | None) -> NatRuleHealthCheckOutput | None:
    """Project health-check settings, or ``None`` when the appliance omitted them."""
    if wire is None:
        return None
    rule = wire.rule
    return NatRuleHealthCheckOutput(
        protocol=rule.protocol,
        port=rule.port,
        interval=rule.interval,
        timeout=rule.timeout,
        retry=rule.retry,
    )


def _project_snat_override(wire: _WireSnatOverride) -> NatRuleSnatOverrideOutput:
    """Project one per-interface source-NAT override entry."""
    return NatRuleSnatOverrideOutput(
        outboundInterface=ObjectRef(name=wire.outboundInterface.name),
        translatedSource=_project_translation(wire.translatedSource),
    )


def _translation_is_populated(translation: NatRuleTranslationOutput | None) -> bool:
    """Whether a projected translation actually carries a value.

    The API declares ``translatedSource``/``translatedDestination`` as a ``oneOf`` of
    ``masq`` and an address reference, so a present-but-empty object is not a translation:
    it is treated as absent rather than guessed into a ``kind``.
    """
    if translation is None:
        return False
    return (
        translation.masq is True
        or translation.ipv4Address is not None
        or translation.fqdnAddress is not None
        or translation.ipv6Address is not None
    )


def _derive_kind(
    translated_source: NatRuleTranslationOutput | None,
    translated_destination: NatRuleTranslationOutput | None,
) -> NatRuleKind:
    """Derive the SNAT/DNAT discriminator from the populated translation.

    ``snat`` when only the source translation carries a value, ``dnat`` when only the
    destination one does, and ``unknown`` when neither does -- or when both do, because the
    contract has no combined variant and the discriminator is never guessed.
    """
    has_source = _translation_is_populated(translated_source)
    has_destination = _translation_is_populated(translated_destination)
    if has_source == has_destination:
        return "unknown"
    return "snat" if has_source else "dnat"


def _project_nat_rule_wire(wire: NatRuleWire, *, position: int | None = None) -> NatRuleOutput:
    """Project one parsed NAT-rule payload into the bounded MCP output model."""
    translated_source = _project_translation(wire.translatedSource)
    translated_destination = _project_translation(wire.translatedDestination)
    return NatRuleOutput(
        id=wire.id,
        name=wire.name,
        description=wire.description,
        enabled=wire.enabled,
        kind=_derive_kind(translated_source, translated_destination),
        position=position,
        linkedFirewallRule=_ref(wire.linkedFirewallRule),
        originalServicesOrGroups=_project_services(wire.originalServicesOrGroups),
        translatedService=_ref(wire.translatedService),
        inboundInterfaces=_project_interfaces(wire.inboundInterfaces),
        outboundInterfaces=_project_interfaces(wire.outboundInterfaces),
        loadBalancingMethod=wire.loadBalancingMethod,
        healthCheck=_project_health_check(wire.healthCheck),
        originalSourceNetworks=_project_networks(wire.originalSourceNetworks),
        originalDestinationNetworks=_project_networks(wire.originalDestinationNetworks),
        translatedSource=translated_source,
        translatedDestination=translated_destination,
        overrideSnatForOutboundInterfaces=[
            _project_snat_override(override) for override in wire.overrideSnatForOutboundInterfaces
        ],
        createdAt=wire.createdAt,
        updatedAt=wire.updatedAt,
    )


def project_nat_rule(payload: Mapping[str, Any]) -> NatRuleOutput:
    """Project one NAT-rule payload into the bounded MCP output model.

    ``position`` is ``None``: the get/create/update operations do not return the rule's
    evaluation position and the API exposes no way to obtain it for a single rule. Only
    :func:`project_nat_rule_page` can derive it, from the page offset and the item index.
    """
    return _project_nat_rule_wire(NatRuleWire.model_validate(payload))


def project_nat_rule_page(
    payload: Mapping[str, Any], *, page: int, page_size: int
) -> ListPage[NatRuleOutput]:
    """Project one NAT-rule list page, deriving each rule's evaluation ``position``.

    The appliance returns the rules in evaluation order and echoes the requested page, so the
    1-based position is ``(page - 1) * page_size + index + 1``. It is derived from the request
    rather than read from ``pages`` because ``pageTotal`` is optional and the metadata is
    usually absent.
    """
    wire = ListPage[NatRuleWire].model_validate(payload)
    offset = (page - 1) * page_size
    return ListPage[NatRuleOutput](
        items=[
            _project_nat_rule_wire(item, position=offset + index + 1)
            for index, item in enumerate(wire.items)
        ],
        pages=wire.pages,
    )
