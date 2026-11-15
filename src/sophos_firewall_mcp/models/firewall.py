"""Pydantic models for the firewall-rule domain.

Two model families live here, and the split is deliberate:

* **MCP-facing request models** (:class:`_ClosedModel`) describe exactly what a caller
  may send. They are closed (``extra="forbid"``), carry the API's field names and
  constraints, and are the only models the tool handlers accept.
* **Appliance payload projections** (:class:`_WireModel`) describe what the adapter is
  willing to echo back. They are open to unknown members (``extra="ignore"``) so a
  server-side addition does not break a read, and they are explicit, bounded
  projections -- never the raw Sophos payload.

The models mirror the audited contract in ``firewall_config_openapi.yaml``: the IPv4
create body is a ``oneOf`` discriminated by ``ruleType`` and this domain models only the
``firewall`` variant (WAF is out of v1 scope); the IPv6 schemas have no discriminator and
no WAF variant. IPv4 and IPv6 therefore have separate request models wherever the
contract differs.

Contract decisions encoded here:

* ``enabled`` is required by the create schema with a default of ``true``. The MCP create
  input defaults it to ``false`` and the adapter always sends it, so a rule can never be
  enabled by relying on the schema default.
* ``position`` is required on create and identifies the insertion point; ``after`` and
  ``before`` need a ``referenceItem`` anchor.
* The API returns no evaluation ``position`` on a rule object. The output
  projection carries one anyway: the list tools derive it from the page offset and the
  item's index in the returned page, and a single-object read or write reports ``null``
  instead of inventing a value.
* ``move`` identifies the rule by **name** only (the operation says "must be identified by
  name"), unlike the ``idOrName`` path parameters of get/update/delete.
* PATCH bodies are partial: the update models default every field to ``None`` and the
  adapter serializes them with ``exclude_unset=True``. An explicitly supplied ``None``
  for an optional member is a JSON Merge Patch removal; ``None`` for a member that cannot
  be removed (``enabled``, ``action``, the match criteria) is rejected before I/O.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    model_validator,
)

from sophos_firewall_mcp.models.common import (
    ListPage,
    ObjectName,
    ObjectNameOrId,
    ObjectRef,
    OutputModel,
    validate_object_name,
    validate_object_name_or_id,
)
from sophos_firewall_mcp.models.objects import serialize_epoch_sentinel

__all__ = [
    "AnySelection",
    "CloneFirewallRuleInput",
    "CreateFirewallRuleIpv4Input",
    "CreateFirewallRuleIpv6Input",
    "DeleteFirewallRuleInput",
    "DeleteFirewallRuleOutput",
    "DscpMarking",
    "EmailScanning",
    "ExclusionZones",
    "ExclusionsIpv4",
    "ExclusionsIpv6",
    "FirewallAction",
    "FirewallRuleIpv4Output",
    "FirewallRuleIpv6Output",
    "GetFirewallRuleInput",
    "HeartbeatEndpoint",
    "Ipv4NetworkMatchOutput",
    "Ipv4Networks",
    "Ipv6NetworkMatchOutput",
    "Ipv6Networks",
    "ListFirewallRulesInput",
    "ListFirewallRulesIpv4Output",
    "ListFirewallRulesIpv6Output",
    "MoveFirewallRuleInput",
    "MoveFirewallRuleOutput",
    "ObjectNameOrId",
    "ObjectReference",
    "Qos",
    "RuleName",
    "RulePosition",
    "SecurityFeaturesIpv4",
    "SecurityFeaturesIpv6",
    "SelectedUsers",
    "ServiceMatchOutput",
    "Services",
    "SetFirewallRuleEnabledInput",
    "SynchronizedSecurityHeartbeat",
    "UpdateFirewallRuleIpv4Input",
    "UpdateFirewallRuleIpv6Input",
    "UserAuthentication",
    "ZoneMatch",
    "ZoneMatchOutput",
    "ZoneName",
    "ZoneReference",
    "ZoneSelection",
    "validate_object_name_or_id",
]

#: ``maxLength`` of a rule/object name in the audited contract.
MAX_RULE_NAME_LENGTH = 60

#: ``maxLength`` of a rule description in the audited contract.
MAX_DESCRIPTION_LENGTH = 255

#: ``maxItems`` of every selection array in the audited contract.
MAX_SELECTION_ITEMS = 1024

#: ``maxLength`` of the ``nameContains``/``nameNotEquals`` query filters.
MAX_NAME_FILTER_LENGTH = 255

#: The API's zone-name ``pattern`` (note: ``0`` is not a valid first character).
ZONE_NAME_PATTERN = r"^[a-zA-Z1-9][a-zA-Z0-9_]*$"

#: A rule name: the documented ``sfos-object-name`` format, at most 60 characters.
RuleName = Annotated[ObjectName, Field(min_length=1, max_length=MAX_RULE_NAME_LENGTH)]

#: A zone reference: rule-name format plus the API's zone ``pattern``.
ZoneName = Annotated[
    str,
    Field(min_length=1, max_length=MAX_RULE_NAME_LENGTH, pattern=ZONE_NAME_PATTERN),
    AfterValidator(validate_object_name),
]

#: A nested object reference name (address, service, schedule, policy, ...).
ReferenceName = Annotated[ObjectName, Field(min_length=1, max_length=MAX_RULE_NAME_LENGTH)]

#: A rule description.
Description = Annotated[str, Field(max_length=MAX_DESCRIPTION_LENGTH)]

#: The four documented insertion points.
RulePosition = Literal["after", "before", "bottom", "top"]

#: The documented firewall actions.
FirewallAction = Literal["accept", "drop", "reject"]

#: The API's full 64-value DSCP marking enum (``qos.dscpMarking``).
DscpMarking = Literal[
    "0-Best Effort",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8-Class 1(CS1)",
    "9",
    "10-Class 1,Gold(AF11)",
    "11",
    "12-Class1,Silver(AF12)",
    "13",
    "14-Class 1,Bronze(AF13)",
    "15",
    "16-Class 2(CS2)",
    "17",
    "18-Class 2,Gold(AF21)",
    "19",
    "20-Class 2,Silver(AF22)",
    "21",
    "22-Class 2,Bronze(AF23)",
    "23",
    "24-Class 3(CS3)",
    "25",
    "26-Class 3,Gold(AF31)",
    "27",
    "28-Class 3,Silver(AF32)",
    "29",
    "30-Class 3,Bronze(AF33)",
    "31",
    "32-Class 4(CS4)",
    "33",
    "34-Class 4,Gold(AF41)",
    "35",
    "36-Class 4,Silver(AF42)",
    "37",
    "38-Class 4,Bronze(AF43)",
    "39",
    "40-Class 5(CS5)",
    "41",
    "42",
    "43",
    "44",
    "45",
    "46-Expedited Forwarding(EF)",
    "47",
    "48-Control(CS6)",
    "49",
    "50",
    "51",
    "52",
    "53",
    "54",
    "55",
    "56-Control(CS7)",
    "57",
    "58",
    "59",
    "60",
    "61",
    "62",
    "63",
]


class _ClosedModel(BaseModel):
    """Base for MCP-facing request models: the API is closed.

    The published MCP input names are snake_case (0.5.0). Every field that the Sophos
    contract spells in camelCase keeps that spelling as its *serialization* alias, so
    ``model_dump(by_alias=True)`` still produces the exact wire body the API requires
    while the published JSON schema shows the snake_case name. ``populate_by_name`` lets a
    caller use either spelling on input.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class _WireModel(OutputModel):
    """Base for appliance payload projections: unknown members are ignored, never echoed.

    The epoch "never" sentinel is published as ``null`` (L6); see
    :func:`~sophos_firewall_mcp.models.objects.serialize_epoch_sentinel`.
    """

    model_config = ConfigDict(extra="ignore")

    @field_serializer(
        "createdAt", "updatedAt", "created_at", "updated_at", check_fields=False, when_used="json"
    )
    def _epoch_sentinel_is_absent(self, value: datetime | None) -> datetime | None:
        """Publish the appliance's epoch "never" sentinel as ``None`` (L6)."""
        return serialize_epoch_sentinel(value)


def _require_anchor(position: RulePosition, reference_item: ObjectReference | None) -> None:
    """Reject ``after``/``before`` without an anchor; ``top``/``bottom`` need none."""
    if position in ("after", "before") and reference_item is None:
        raise ValueError(
            "position 'after' or 'before' requires reference_item; use 'top' or 'bottom' "
            "to move without an anchor"
        )


# -- Nested request structures ---------------------------------------------------------


class ObjectReference(_ClosedModel):
    """A nested reference to an existing Sophos object, for example ``{"name": "LAN"}``."""

    name: ReferenceName


class ZoneReference(_ClosedModel):
    """A nested reference to an existing zone."""

    name: ZoneName


class AnySelection(_ClosedModel):
    """The ``{"any": true}`` variant of a match selection."""

    any: Literal[True]


class ZoneSelection(_ClosedModel):
    """An explicit, non-empty list of zones."""

    zones: list[ZoneReference] = Field(min_length=1)


class Ipv4Networks(_ClosedModel):
    """The selected-network members of an IPv4 match (no ``any`` variant)."""

    countries: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)
    country_groups: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("country_groups", "countryGroups"),
        serialization_alias="countryGroups",
    )
    fqdn_addresses: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("fqdn_addresses", "fqdnAddresses"),
        serialization_alias="fqdnAddresses",
    )
    fqdn_groups: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("fqdn_groups", "fqdnGroups"),
        serialization_alias="fqdnGroups",
    )
    ipv4_addresses: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("ipv4_addresses", "ipv4Addresses"),
        serialization_alias="ipv4Addresses",
    )
    ipv4_groups: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("ipv4_groups", "ipv4Groups"),
        serialization_alias="ipv4Groups",
    )
    mac_addresses: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("mac_addresses", "macAddresses"),
        serialization_alias="macAddresses",
    )

    @model_validator(mode="after")
    def _require_at_least_one_member(self) -> Self:
        if not any(getattr(self, field) for field in type(self).model_fields):
            raise ValueError("at least one IPv4 network member must be selected")
        return self


class Ipv6Networks(_ClosedModel):
    """The selected-network members of an IPv6 match (no ``any`` variant)."""

    ipv6_addresses: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("ipv6_addresses", "ipv6Addresses"),
        serialization_alias="ipv6Addresses",
    )
    ipv6_groups: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("ipv6_groups", "ipv6Groups"),
        serialization_alias="ipv6Groups",
    )
    mac_addresses: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("mac_addresses", "macAddresses"),
        serialization_alias="macAddresses",
    )

    @model_validator(mode="after")
    def _require_at_least_one_member(self) -> Self:
        if not any(getattr(self, field) for field in type(self).model_fields):
            raise ValueError("at least one IPv6 network member must be selected")
        return self


class Services(_ClosedModel):
    """The selected service members of a match (no ``any`` variant)."""

    services: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)
    service_groups: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("service_groups", "serviceGroups"),
        serialization_alias="serviceGroups",
    )

    @model_validator(mode="after")
    def _require_at_least_one_member(self) -> Self:
        if not any(getattr(self, field) for field in type(self).model_fields):
            raise ValueError("at least one service member must be selected")
        return self


#: A zone match: ``{"any": true}`` or a non-empty zone list.
ZoneMatch = AnySelection | ZoneSelection

#: An IPv4 network match: ``{"any": true}`` or selected IPv4 members.
Ipv4NetworkMatch = AnySelection | Ipv4Networks

#: An IPv6 network match: ``{"any": true}`` or selected IPv6 members.
Ipv6NetworkMatch = AnySelection | Ipv6Networks

#: A service match: ``{"any": true}`` or selected services.
ServiceMatch = AnySelection | Services


class SelectedUsers(_ClosedModel):
    """An explicit user/user-group selection for ``user_authentication.users_or_groups``."""

    users: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)
    user_groups: list[ObjectReference] | None = Field(
        default=None,
        max_length=MAX_SELECTION_ITEMS,
        validation_alias=AliasChoices("user_groups", "userGroups"),
        serialization_alias="userGroups",
    )


class UserAuthentication(_ClosedModel):
    """The rule's user-authentication settings."""

    users_or_groups: AnySelection | SelectedUsers | None = Field(
        default=None,
        validation_alias=AliasChoices("users_or_groups", "usersOrGroups"),
        serialization_alias="usersOrGroups",
    )
    exclude_users_from_accounting: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "exclude_users_from_accounting", "excludeUsersFromAccounting"
        ),
        serialization_alias="excludeUsersFromAccounting",
    )
    web_authentication_for_unknown_users: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "web_authentication_for_unknown_users", "webAuthenticationForUnknownUsers"
        ),
        serialization_alias="webAuthenticationForUnknownUsers",
    )


class ExclusionZones(_ClosedModel):
    """The zone members of an exclusion."""

    zones: list[ZoneReference] | None = None


class ExclusionsIpv4(_ClosedModel):
    """IPv4 exclusions: traffic that matches the rule but is excluded from it."""

    source_zones: ExclusionZones | None = Field(
        default=None,
        validation_alias=AliasChoices("source_zones", "sourceZones"),
        serialization_alias="sourceZones",
    )
    destination_zones: ExclusionZones | None = Field(
        default=None,
        validation_alias=AliasChoices("destination_zones", "destinationZones"),
        serialization_alias="destinationZones",
    )
    source_networks: Ipv4Networks | None = Field(
        default=None,
        validation_alias=AliasChoices("source_networks", "sourceNetworks"),
        serialization_alias="sourceNetworks",
    )
    destination_networks: Ipv4Networks | None = Field(
        default=None,
        validation_alias=AliasChoices("destination_networks", "destinationNetworks"),
        serialization_alias="destinationNetworks",
    )
    services_or_groups: Services | None = Field(
        default=None,
        validation_alias=AliasChoices("services_or_groups", "servicesOrGroups"),
        serialization_alias="servicesOrGroups",
    )


class ExclusionsIpv6(_ClosedModel):
    """IPv6 exclusions: traffic that matches the rule but is excluded from it."""

    source_zones: ExclusionZones | None = Field(
        default=None,
        validation_alias=AliasChoices("source_zones", "sourceZones"),
        serialization_alias="sourceZones",
    )
    destination_zones: ExclusionZones | None = Field(
        default=None,
        validation_alias=AliasChoices("destination_zones", "destinationZones"),
        serialization_alias="destinationZones",
    )
    source_networks: Ipv6Networks | None = Field(
        default=None,
        validation_alias=AliasChoices("source_networks", "sourceNetworks"),
        serialization_alias="sourceNetworks",
    )
    destination_networks: Ipv6Networks | None = Field(
        default=None,
        validation_alias=AliasChoices("destination_networks", "destinationNetworks"),
        serialization_alias="destinationNetworks",
    )
    services_or_groups: Services | None = Field(
        default=None,
        validation_alias=AliasChoices("services_or_groups", "servicesOrGroups"),
        serialization_alias="servicesOrGroups",
    )


class HeartbeatEndpoint(_ClosedModel):
    """One side of a synchronized-security heartbeat configuration."""

    block_clients_with_no_heartbeat: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "block_clients_with_no_heartbeat", "blockClientsWithNoHeartbeat"
        ),
        serialization_alias="blockClientsWithNoHeartbeat",
    )
    minimum_level: Literal["green", "noRestriction", "yellow"] | None = Field(
        default=None,
        validation_alias=AliasChoices("minimum_level", "minimumLevel"),
        serialization_alias="minimumLevel",
    )


class SynchronizedSecurityHeartbeat(_ClosedModel):
    """The rule's Security Heartbeat settings."""

    source: HeartbeatEndpoint | None = None
    destination: HeartbeatEndpoint | None = None


class SecurityFeaturesIpv4(_ClosedModel):
    """The IPv4 rule's security-feature settings (includes ``scan_ftp``)."""

    application_based_qos_policy: bool = Field(
        default=False,
        validation_alias=AliasChoices("application_based_qos_policy", "applicationBasedQosPolicy"),
        serialization_alias="applicationBasedQosPolicy",
    )
    application_policy: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("application_policy", "applicationPolicy"),
        serialization_alias="applicationPolicy",
    )
    block_quic_protocol: bool = Field(
        default=False,
        validation_alias=AliasChoices("block_quic_protocol", "blockQuicProtocol"),
        serialization_alias="blockQuicProtocol",
    )
    decrypt_https_web_proxy_mode: bool = Field(
        default=False,
        validation_alias=AliasChoices("decrypt_https_web_proxy_mode", "decryptHTTPSWebProxyMode"),
        serialization_alias="decryptHTTPSWebProxyMode",
    )
    ips_policy: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("ips_policy", "ipsPolicy"),
        serialization_alias="ipsPolicy",
    )
    scan_ftp: bool = Field(
        default=False,
        validation_alias=AliasChoices("scan_ftp", "scanFtp"),
        serialization_alias="scanFtp",
    )
    scan_http_and_decrypted_https: bool = Field(
        default=False,
        validation_alias=AliasChoices("scan_http_and_decrypted_https", "scanHttpAndDecryptedHttps"),
        serialization_alias="scanHttpAndDecryptedHttps",
    )
    scan_with_ndr_active_threat_intelligence: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "scan_with_ndr_active_threat_intelligence", "scanWithNdrActiveThreatIntelligence"
        ),
        serialization_alias="scanWithNdrActiveThreatIntelligence",
    )
    web_category_based_qos_policy: bool = Field(
        default=False,
        validation_alias=AliasChoices("web_category_based_qos_policy", "webCategoryBasedQosPolicy"),
        serialization_alias="webCategoryBasedQosPolicy",
    )
    web_policy: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("web_policy", "webPolicy"),
        serialization_alias="webPolicy",
    )
    web_proxy: bool = Field(
        default=False,
        validation_alias=AliasChoices("web_proxy", "webProxy"),
        serialization_alias="webProxy",
    )
    zero_day_protection: bool = Field(
        default=False,
        validation_alias=AliasChoices("zero_day_protection", "zeroDayProtection"),
        serialization_alias="zeroDayProtection",
    )


class SecurityFeaturesIpv6(_ClosedModel):
    """The IPv6 rule's security-feature settings (the IPv6 schema has no ``scan_ftp``)."""

    application_based_qos_policy: bool = Field(
        default=False,
        validation_alias=AliasChoices("application_based_qos_policy", "applicationBasedQosPolicy"),
        serialization_alias="applicationBasedQosPolicy",
    )
    application_policy: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("application_policy", "applicationPolicy"),
        serialization_alias="applicationPolicy",
    )
    block_quic_protocol: bool = Field(
        default=False,
        validation_alias=AliasChoices("block_quic_protocol", "blockQuicProtocol"),
        serialization_alias="blockQuicProtocol",
    )
    decrypt_https_web_proxy_mode: bool = Field(
        default=False,
        validation_alias=AliasChoices("decrypt_https_web_proxy_mode", "decryptHTTPSWebProxyMode"),
        serialization_alias="decryptHTTPSWebProxyMode",
    )
    ips_policy: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("ips_policy", "ipsPolicy"),
        serialization_alias="ipsPolicy",
    )
    scan_http_and_decrypted_https: bool = Field(
        default=False,
        validation_alias=AliasChoices("scan_http_and_decrypted_https", "scanHttpAndDecryptedHttps"),
        serialization_alias="scanHttpAndDecryptedHttps",
    )
    scan_with_ndr_active_threat_intelligence: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "scan_with_ndr_active_threat_intelligence", "scanWithNdrActiveThreatIntelligence"
        ),
        serialization_alias="scanWithNdrActiveThreatIntelligence",
    )
    web_category_based_qos_policy: bool = Field(
        default=False,
        validation_alias=AliasChoices("web_category_based_qos_policy", "webCategoryBasedQosPolicy"),
        serialization_alias="webCategoryBasedQosPolicy",
    )
    web_policy: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("web_policy", "webPolicy"),
        serialization_alias="webPolicy",
    )
    web_proxy: bool = Field(
        default=False,
        validation_alias=AliasChoices("web_proxy", "webProxy"),
        serialization_alias="webProxy",
    )
    zero_day_protection: bool = Field(
        default=False,
        validation_alias=AliasChoices("zero_day_protection", "zeroDayProtection"),
        serialization_alias="zeroDayProtection",
    )


class EmailScanning(_ClosedModel):
    """The rule's email-protocol scanning settings."""

    imap: bool = False
    imaps: bool = False
    pop3: bool = False
    pop3s: bool = False
    smtp: bool = False
    smtps: bool = False


class Qos(_ClosedModel):
    """The rule's traffic-shaping and DSCP settings."""

    traffic_shaping_policy: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("traffic_shaping_policy", "trafficShapingPolicy"),
        serialization_alias="trafficShapingPolicy",
    )
    dscp_marking: DscpMarking | None = Field(
        default=None,
        validation_alias=AliasChoices("dscp_marking", "dscpMarking"),
        serialization_alias="dscpMarking",
    )


# -- Create requests -------------------------------------------------------------------


class CreateFirewallRuleIpv4Input(_ClosedModel):
    """Create an IPv4 firewall rule (``createFirewallRuleIpv4``).

    ``enabled`` defaults to ``false`` so a created rule is never enabled by relying on the
    schema's ``true`` default; the adapter always sends the explicit value. ``position`` is
    required: the appliance needs the insertion point, and ``after``/``before`` require a
    ``reference_item`` anchor. ``rule_type`` accepts only ``firewall`` (WAF is out of scope).
    """

    name: RuleName
    description: Description | None = None
    rule_type: Literal["firewall"] = Field(
        default="firewall",
        validation_alias=AliasChoices("rule_type", "ruleType"),
        serialization_alias="ruleType",
    )
    enabled: bool = False
    action: FirewallAction = "accept"
    source_zones: ZoneMatch = Field(
        validation_alias=AliasChoices("source_zones", "sourceZones"),
        serialization_alias="sourceZones",
    )
    destination_zones: ZoneMatch = Field(
        validation_alias=AliasChoices("destination_zones", "destinationZones"),
        serialization_alias="destinationZones",
    )
    source_networks: Ipv4NetworkMatch = Field(
        validation_alias=AliasChoices("source_networks", "sourceNetworks"),
        serialization_alias="sourceNetworks",
    )
    destination_networks: Ipv4NetworkMatch = Field(
        validation_alias=AliasChoices("destination_networks", "destinationNetworks"),
        serialization_alias="destinationNetworks",
    )
    services_or_groups: ServiceMatch = Field(
        validation_alias=AliasChoices("services_or_groups", "servicesOrGroups"),
        serialization_alias="servicesOrGroups",
    )
    user_authentication: UserAuthentication | None = Field(
        default=None,
        validation_alias=AliasChoices("user_authentication", "userAuthentication"),
        serialization_alias="userAuthentication",
    )
    exclusions: ExclusionsIpv4 | None = None
    synchronized_security_heartbeat: SynchronizedSecurityHeartbeat | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "synchronized_security_heartbeat", "synchronizedSecurityHeartbeat"
        ),
        serialization_alias="synchronizedSecurityHeartbeat",
    )
    security_features: SecurityFeaturesIpv4 | None = Field(
        default=None,
        validation_alias=AliasChoices("security_features", "securityFeatures"),
        serialization_alias="securityFeatures",
    )
    email_scanning: EmailScanning | None = Field(
        default=None,
        validation_alias=AliasChoices("email_scanning", "emailScanning"),
        serialization_alias="emailScanning",
    )
    qos: Qos | None = None
    log_traffic: bool = Field(
        default=False,
        validation_alias=AliasChoices("log_traffic", "logTraffic"),
        serialization_alias="logTraffic",
    )
    schedule: ObjectReference | None = None
    position: RulePosition
    reference_item: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("reference_item", "referenceItem"),
        serialization_alias="referenceItem",
    )

    @model_validator(mode="after")
    def _check_position(self) -> Self:
        _require_anchor(self.position, self.reference_item)
        return self


class CreateFirewallRuleIpv6Input(_ClosedModel):
    """Create an IPv6 firewall rule (``createFirewallRuleIpv6``).

    The IPv6 schema has no ``ruleType`` discriminator and no WAF variant; the field is
    still sent as ``firewall`` because the API declares it required.
    """

    name: RuleName
    description: Description | None = None
    rule_type: Literal["firewall"] = Field(
        default="firewall",
        validation_alias=AliasChoices("rule_type", "ruleType"),
        serialization_alias="ruleType",
    )
    enabled: bool = False
    action: FirewallAction = "accept"
    source_zones: ZoneMatch = Field(
        validation_alias=AliasChoices("source_zones", "sourceZones"),
        serialization_alias="sourceZones",
    )
    destination_zones: ZoneMatch = Field(
        validation_alias=AliasChoices("destination_zones", "destinationZones"),
        serialization_alias="destinationZones",
    )
    source_networks: Ipv6NetworkMatch = Field(
        validation_alias=AliasChoices("source_networks", "sourceNetworks"),
        serialization_alias="sourceNetworks",
    )
    destination_networks: Ipv6NetworkMatch = Field(
        validation_alias=AliasChoices("destination_networks", "destinationNetworks"),
        serialization_alias="destinationNetworks",
    )
    services_or_groups: ServiceMatch = Field(
        validation_alias=AliasChoices("services_or_groups", "servicesOrGroups"),
        serialization_alias="servicesOrGroups",
    )
    user_authentication: UserAuthentication | None = Field(
        default=None,
        validation_alias=AliasChoices("user_authentication", "userAuthentication"),
        serialization_alias="userAuthentication",
    )
    exclusions: ExclusionsIpv6 | None = None
    security_features: SecurityFeaturesIpv6 | None = Field(
        default=None,
        validation_alias=AliasChoices("security_features", "securityFeatures"),
        serialization_alias="securityFeatures",
    )
    email_scanning: EmailScanning | None = Field(
        default=None,
        validation_alias=AliasChoices("email_scanning", "emailScanning"),
        serialization_alias="emailScanning",
    )
    qos: Qos | None = None
    log_traffic: bool = Field(
        default=False,
        validation_alias=AliasChoices("log_traffic", "logTraffic"),
        serialization_alias="logTraffic",
    )
    schedule: ObjectReference | None = None
    position: RulePosition
    reference_item: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("reference_item", "referenceItem"),
        serialization_alias="referenceItem",
    )

    @model_validator(mode="after")
    def _check_position(self) -> Self:
        _require_anchor(self.position, self.reference_item)
        return self


# -- Update (PATCH) requests -----------------------------------------------------------

#: Update members where an explicit ``null`` is a JSON Merge Patch removal. Every other
#: member is a scalar or a required match criterion and cannot be nulled.
_REMOVABLE_UPDATE_FIELDS = frozenset(
    {
        "description",
        "schedule",
        "user_authentication",
        "exclusions",
        "synchronized_security_heartbeat",
        "security_features",
        "email_scanning",
        "qos",
    }
)


class _UpdateFirewallRuleBase(_ClosedModel):
    """Members shared by the IPv4 and IPv6 JSON Merge Patch bodies.

    Every member is optional and the adapter serializes with ``exclude_unset=True``, so an
    omitted member keeps its persisted value. ``id_or_name`` identifies the target and is
    never part of the body.
    """

    id_or_name: ObjectNameOrId = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
    )
    name: RuleName | None = None
    description: Description | None = None
    enabled: bool | None = None
    action: FirewallAction | None = None
    source_zones: ZoneMatch | None = Field(
        default=None,
        validation_alias=AliasChoices("source_zones", "sourceZones"),
        serialization_alias="sourceZones",
    )
    destination_zones: ZoneMatch | None = Field(
        default=None,
        validation_alias=AliasChoices("destination_zones", "destinationZones"),
        serialization_alias="destinationZones",
    )
    services_or_groups: ServiceMatch | None = Field(
        default=None,
        validation_alias=AliasChoices("services_or_groups", "servicesOrGroups"),
        serialization_alias="servicesOrGroups",
    )
    user_authentication: UserAuthentication | None = Field(
        default=None,
        validation_alias=AliasChoices("user_authentication", "userAuthentication"),
        serialization_alias="userAuthentication",
    )
    email_scanning: EmailScanning | None = Field(
        default=None,
        validation_alias=AliasChoices("email_scanning", "emailScanning"),
        serialization_alias="emailScanning",
    )
    qos: Qos | None = None
    log_traffic: bool | None = Field(
        default=None,
        validation_alias=AliasChoices("log_traffic", "logTraffic"),
        serialization_alias="logTraffic",
    )
    schedule: ObjectReference | None = None

    @model_validator(mode="after")
    def _reject_null_for_non_removable_members(self) -> Self:
        for field in type(self).model_fields:
            if field in _REMOVABLE_UPDATE_FIELDS:
                continue
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(
                    f"{field} cannot be null in a merge patch; omit it to keep the current value"
                )
        return self


class UpdateFirewallRuleIpv4Input(_UpdateFirewallRuleBase):
    """Partially update an IPv4 firewall rule (``updateFirewallRuleIpv4``)."""

    source_networks: Ipv4NetworkMatch | None = Field(
        default=None,
        validation_alias=AliasChoices("source_networks", "sourceNetworks"),
        serialization_alias="sourceNetworks",
    )
    destination_networks: Ipv4NetworkMatch | None = Field(
        default=None,
        validation_alias=AliasChoices("destination_networks", "destinationNetworks"),
        serialization_alias="destinationNetworks",
    )
    exclusions: ExclusionsIpv4 | None = None
    synchronized_security_heartbeat: SynchronizedSecurityHeartbeat | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "synchronized_security_heartbeat", "synchronizedSecurityHeartbeat"
        ),
        serialization_alias="synchronizedSecurityHeartbeat",
    )
    security_features: SecurityFeaturesIpv4 | None = Field(
        default=None,
        validation_alias=AliasChoices("security_features", "securityFeatures"),
        serialization_alias="securityFeatures",
    )


class UpdateFirewallRuleIpv6Input(_UpdateFirewallRuleBase):
    """Partially update an IPv6 firewall rule (``updateFirewallRuleIpv6``)."""

    source_networks: Ipv6NetworkMatch | None = Field(
        default=None,
        validation_alias=AliasChoices("source_networks", "sourceNetworks"),
        serialization_alias="sourceNetworks",
    )
    destination_networks: Ipv6NetworkMatch | None = Field(
        default=None,
        validation_alias=AliasChoices("destination_networks", "destinationNetworks"),
        serialization_alias="destinationNetworks",
    )
    exclusions: ExclusionsIpv6 | None = None
    security_features: SecurityFeaturesIpv6 | None = Field(
        default=None,
        validation_alias=AliasChoices("security_features", "securityFeatures"),
        serialization_alias="securityFeatures",
    )


# -- Other operation requests ----------------------------------------------------------


class ListFirewallRulesInput(_ClosedModel):
    """One page of a firewall-rule collection (``getAllFirewallRulesIpv4/Ipv6``).

    ``name_contains`` and ``name_not_equals`` are mutually exclusive in the API, so at
    most one may be supplied. Pagination is one explicit page per call; the adapter never
    walks the collection automatically.

    ``page_size`` defaults to 10: a firewall rule is a large object (the tested
    appliance's 48-rule base is ~70 KB of JSON), so a default call must stay small and the
    caller raises the page size explicitly when it wants a bigger page.
    """

    page: int = Field(
        default=1,
        ge=1,
        description="1-based page number; 0 is rejected before the request is sent.",
    )
    page_size: int = Field(
        default=10,
        ge=1,
        le=100,
        validation_alias=AliasChoices("page_size", "pageSize"),
        serialization_alias="pageSize",
        description=(
            "Page size, 1-100. Defaults to 10 so a default call stays small; a firewall "
            "rule is a large object, so raise it deliberately."
        ),
    )
    page_total: bool = Field(
        default=False,
        validation_alias=AliasChoices("page_total", "pageTotal"),
        serialization_alias="pageTotal",
        description=(
            "Also request pages.total (the number of pages) and pages.items (the number "
            "of items) in the response metadata."
        ),
    )
    name_contains: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_NAME_FILTER_LENGTH,
        validation_alias=AliasChoices("name_contains", "nameContains"),
        serialization_alias="nameContains",
    )
    name_not_equals: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_NAME_FILTER_LENGTH,
        validation_alias=AliasChoices("name_not_equals", "nameNotEquals"),
        serialization_alias="nameNotEquals",
    )

    @model_validator(mode="after")
    def _check_name_filters(self) -> Self:
        if self.name_contains is not None and self.name_not_equals is not None:
            raise ValueError(
                "name_contains and name_not_equals are mutually exclusive; set at most one"
            )
        return self


class GetFirewallRuleInput(_ClosedModel):
    """Read one firewall rule by id or name (``getFirewallRuleIpv4/Ipv6``)."""

    id_or_name: ObjectNameOrId = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
    )


class DeleteFirewallRuleInput(_ClosedModel):
    """Delete one firewall rule by id or name (``deleteFirewallRuleIpv4/Ipv6``)."""

    id_or_name: ObjectNameOrId = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
    )


class MoveFirewallRuleInput(_ClosedModel):
    """Move one firewall rule (``moveFirewallRuleIpv4/Ipv6``).

    The operation requires the rule to be identified by **name**; ``id_or_name`` is not
    accepted here. ``after``/``before`` require a ``reference_item`` anchor.
    """

    name: RuleName
    position: RulePosition
    reference_item: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("reference_item", "referenceItem"),
        serialization_alias="referenceItem",
    )

    @model_validator(mode="after")
    def _check_position(self) -> Self:
        _require_anchor(self.position, self.reference_item)
        return self


class SetFirewallRuleEnabledInput(_ClosedModel):
    """Enable or disable one firewall rule by PATCHing ``enabled``.

    ``enabled`` is required: the caller must choose the target state, so a missing value
    can never silently disable a rule.
    """

    id_or_name: ObjectNameOrId = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
    )
    enabled: bool


class CloneFirewallRuleInput(_ClosedModel):
    """Clone one firewall rule into a new rule (get + create).

    The source is read with the matching get operation and re-created with the matching
    create operation. The clone is never auto-enabled: ``enabled`` defaults to ``false``.
    """

    source: ObjectNameOrId
    name: RuleName
    position: RulePosition
    reference_item: ObjectReference | None = Field(
        default=None,
        validation_alias=AliasChoices("reference_item", "referenceItem"),
        serialization_alias="referenceItem",
    )
    enabled: bool = False

    @model_validator(mode="after")
    def _check_position(self) -> Self:
        _require_anchor(self.position, self.reference_item)
        return self


# -- Output projections ----------------------------------------------------------------


class ZoneMatchOutput(_WireModel):
    """A zone match flattened to ``any`` plus the selected zone references."""

    any: bool = False
    zones: list[ObjectRef] = Field(default_factory=list)


class Ipv4NetworkMatchOutput(_WireModel):
    """An IPv4 network match flattened to ``any`` plus the selected references."""

    any: bool = False
    countries: list[ObjectRef] = Field(default_factory=list)
    countryGroups: list[ObjectRef] = Field(default_factory=list)
    fqdnAddresses: list[ObjectRef] = Field(default_factory=list)
    fqdnGroups: list[ObjectRef] = Field(default_factory=list)
    ipv4Addresses: list[ObjectRef] = Field(default_factory=list)
    ipv4Groups: list[ObjectRef] = Field(default_factory=list)
    macAddresses: list[ObjectRef] = Field(default_factory=list)


class Ipv6NetworkMatchOutput(_WireModel):
    """An IPv6 network match flattened to ``any`` plus the selected references."""

    any: bool = False
    ipv6Addresses: list[ObjectRef] = Field(default_factory=list)
    ipv6Groups: list[ObjectRef] = Field(default_factory=list)
    macAddresses: list[ObjectRef] = Field(default_factory=list)


class ServiceMatchOutput(_WireModel):
    """A service match flattened to ``any`` plus the selected references."""

    any: bool = False
    services: list[ObjectRef] = Field(default_factory=list)
    serviceGroups: list[ObjectRef] = Field(default_factory=list)


class FirewallRuleOutputBase(_WireModel):
    """The bounded projection every firewall-rule tool returns.

    It carries the stable ``id`` (when returned), the name, the IP family, the applied
    ``enabled`` state, the action and logging flags, the schedule and the match criteria.
    ``enabled`` is ``None`` only when the appliance omitted the field it declares
    required; the normal path always returns the applied state.

    ``position`` is the rule's 1-based evaluation position in the rule base. The
    contract does not return it on a single-object read or write, so ``get``, ``create``,
    ``update``, ``set_enabled`` and ``clone`` report ``null``; only the list tools can
    derive it, from the page offset and the item's index in the returned page. It is
    therefore never invented for a single object: ``null`` means "not derivable here",
    not "first rule".
    """

    id: str | None = None
    name: str
    ruleType: Literal["firewall"] = "firewall"
    position: int | None = Field(
        default=None,
        ge=1,
        description=(
            "1-based evaluation position in the rule base. The list tools derive it from "
            "the page offset and the item's index in the returned page; a single-object "
            "read or write returns null because the API does not return it."
        ),
    )
    enabled: bool | None = None
    description: str | None = None
    action: FirewallAction | None = None
    logTraffic: bool | None = None
    schedule: ObjectRef | None = None
    sourceZones: ZoneMatchOutput | None = None
    destinationZones: ZoneMatchOutput | None = None
    servicesOrGroups: ServiceMatchOutput | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class FirewallRuleIpv4Output(FirewallRuleOutputBase):
    """An IPv4 firewall rule projected for MCP output."""

    ipFamily: Literal["ipv4"] = "ipv4"
    sourceNetworks: Ipv4NetworkMatchOutput | None = None
    destinationNetworks: Ipv4NetworkMatchOutput | None = None


class FirewallRuleIpv6Output(FirewallRuleOutputBase):
    """An IPv6 firewall rule projected for MCP output."""

    ipFamily: Literal["ipv6"] = "ipv6"
    sourceNetworks: Ipv6NetworkMatchOutput | None = None
    destinationNetworks: Ipv6NetworkMatchOutput | None = None


class ListFirewallRulesIpv4Output(ListPage[FirewallRuleIpv4Output]):
    """One page of IPv4 firewall rules plus the number of WAF rules that were skipped.

    WAF rules are out of v1 scope. They are never projected into the output, but the count
    is reported so the caller can tell that the appliance holds rules this tool does not
    return.
    """

    wafRulesSkipped: int = Field(default=0, ge=0)


class ListFirewallRulesIpv6Output(ListPage[FirewallRuleIpv6Output]):
    """One page of IPv6 firewall rules (the IPv6 API has no WAF variant)."""


class DeleteFirewallRuleOutput(_WireModel):
    """The result of deleting one firewall rule."""

    deleted: bool
    idOrName: str


class MoveFirewallRuleOutput(_WireModel):
    """The result of moving one firewall rule."""

    moved: bool = True
    name: str
    position: RulePosition
    referenceItem: ObjectRef | None = None
