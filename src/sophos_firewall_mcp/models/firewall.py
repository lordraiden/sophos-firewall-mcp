"""Pydantic models for the firewall-rule domain (issue #27).

Two model families live here, and the split is deliberate:

* **MCP-facing request models** (:class:`_ClosedModel`) describe exactly what a caller
  may send. They are closed (``extra="forbid"``), carry the contract's field names and
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
* ``move`` identifies the rule by **name** only (the operation says "must be identified by
  name"), unlike the ``idOrName`` path parameters of get/update/delete.
* PATCH bodies are partial: the update models default every field to ``None`` and the
  adapter serializes them with ``exclude_unset=True``. An explicitly supplied ``None``
  for an optional member is a JSON Merge Patch removal; ``None`` for a member that cannot
  be removed (``enabled``, ``action``, the match criteria) is rejected before I/O.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from sophos_firewall_mcp.models.common import (
    ListPage,
    ObjectName,
    ObjectRef,
    validate_object_name,
)

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

#: The contract's zone-name ``pattern`` (note: ``0`` is not a valid first character).
ZONE_NAME_PATTERN = r"^[a-zA-Z1-9][a-zA-Z0-9_]*$"

#: ``format: uuid`` as used by the ``idOrName`` path parameters and rule ids.
_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Characters that would make a name unsafe as a single URL path segment. The REST client
#: already refuses ``..``; rejecting these here turns a transport-level ``ValueError`` into
#: a clear model validation error before any I/O.
_PATH_UNSAFE_TOKENS = ("/", "\\", "..")

#: A rule name: the documented ``sfos-object-name`` format, at most 60 characters.
RuleName = Annotated[ObjectName, Field(min_length=1, max_length=MAX_RULE_NAME_LENGTH)]

#: A zone reference: rule-name format plus the contract's zone ``pattern``.
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

#: The contract's full 64-value DSCP marking enum (``qos.dscpMarking``).
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


def validate_object_name_or_id(value: str) -> str:
    """Validate an ``idOrName`` path identifier: a UUID or a documented object name.

    ``sfos-object-name-or-id`` accepts either form. A UUID is returned unchanged; any
    other value must pass :func:`~sophos_firewall_mcp.models.common.validate_object_name`
    and must also be safe as one URL path segment (no ``/``, ``\\`` or ``..``).

    Raises:
        ValueError: The value is neither a UUID nor a usable object name.
    """
    if not isinstance(value, str):
        raise ValueError("idOrName must be a string")
    if _UUID_PATTERN.fullmatch(value):
        return value
    name = validate_object_name(value)
    if any(token in name for token in _PATH_UNSAFE_TOKENS):
        raise ValueError("object name must not contain '/', '\\' or '..'")
    return name


#: A UUID or a documented object name, as accepted by the ``idOrName`` path parameters.
ObjectNameOrId = Annotated[str, AfterValidator(validate_object_name_or_id)]


class _ClosedModel(BaseModel):
    """Base for MCP-facing request models: the contract is closed."""

    model_config = ConfigDict(extra="forbid")


class _WireModel(BaseModel):
    """Base for appliance payload projections: unknown members are ignored, never echoed."""

    model_config = ConfigDict(extra="ignore")


def _require_anchor(position: RulePosition, reference_item: ObjectReference | None) -> None:
    """Reject ``after``/``before`` without an anchor; ``top``/``bottom`` need none."""
    if position in ("after", "before") and reference_item is None:
        raise ValueError(
            "position 'after' or 'before' requires referenceItem; use 'top' or 'bottom' "
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
    countryGroups: list[ObjectReference] | None = Field(
        default=None, max_length=MAX_SELECTION_ITEMS
    )
    fqdnAddresses: list[ObjectReference] | None = Field(
        default=None, max_length=MAX_SELECTION_ITEMS
    )
    fqdnGroups: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)
    ipv4Addresses: list[ObjectReference] | None = Field(
        default=None, max_length=MAX_SELECTION_ITEMS
    )
    ipv4Groups: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)
    macAddresses: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)

    @model_validator(mode="after")
    def _require_at_least_one_member(self) -> Self:
        if not any(getattr(self, field) for field in type(self).model_fields):
            raise ValueError("at least one IPv4 network member must be selected")
        return self


class Ipv6Networks(_ClosedModel):
    """The selected-network members of an IPv6 match (no ``any`` variant)."""

    ipv6Addresses: list[ObjectReference] | None = Field(
        default=None, max_length=MAX_SELECTION_ITEMS
    )
    ipv6Groups: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)
    macAddresses: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)

    @model_validator(mode="after")
    def _require_at_least_one_member(self) -> Self:
        if not any(getattr(self, field) for field in type(self).model_fields):
            raise ValueError("at least one IPv6 network member must be selected")
        return self


class Services(_ClosedModel):
    """The selected service members of a match (no ``any`` variant)."""

    services: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)
    serviceGroups: list[ObjectReference] | None = Field(
        default=None, max_length=MAX_SELECTION_ITEMS
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
    """An explicit user/user-group selection for ``userAuthentication.usersOrGroups``."""

    users: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)
    userGroups: list[ObjectReference] | None = Field(default=None, max_length=MAX_SELECTION_ITEMS)


class UserAuthentication(_ClosedModel):
    """The rule's user-authentication settings."""

    usersOrGroups: AnySelection | SelectedUsers | None = None
    excludeUsersFromAccounting: bool = False
    webAuthenticationForUnknownUsers: bool = False


class ExclusionZones(_ClosedModel):
    """The zone members of an exclusion."""

    zones: list[ZoneReference] | None = None


class ExclusionsIpv4(_ClosedModel):
    """IPv4 exclusions: traffic that matches the rule but is excluded from it."""

    sourceZones: ExclusionZones | None = None
    destinationZones: ExclusionZones | None = None
    sourceNetworks: Ipv4Networks | None = None
    destinationNetworks: Ipv4Networks | None = None
    servicesOrGroups: Services | None = None


class ExclusionsIpv6(_ClosedModel):
    """IPv6 exclusions: traffic that matches the rule but is excluded from it."""

    sourceZones: ExclusionZones | None = None
    destinationZones: ExclusionZones | None = None
    sourceNetworks: Ipv6Networks | None = None
    destinationNetworks: Ipv6Networks | None = None
    servicesOrGroups: Services | None = None


class HeartbeatEndpoint(_ClosedModel):
    """One side of a synchronized-security heartbeat configuration."""

    blockClientsWithNoHeartbeat: bool = False
    minimumLevel: Literal["green", "noRestriction", "yellow"] | None = None


class SynchronizedSecurityHeartbeat(_ClosedModel):
    """The rule's Security Heartbeat settings."""

    source: HeartbeatEndpoint | None = None
    destination: HeartbeatEndpoint | None = None


class SecurityFeaturesIpv4(_ClosedModel):
    """The IPv4 rule's security-feature settings (includes ``scanFtp``)."""

    applicationBasedQosPolicy: bool = False
    applicationPolicy: ObjectReference | None = None
    blockQuicProtocol: bool = False
    decryptHTTPSWebProxyMode: bool = False
    ipsPolicy: ObjectReference | None = None
    scanFtp: bool = False
    scanHttpAndDecryptedHttps: bool = False
    scanWithNdrActiveThreatIntelligence: bool = False
    webCategoryBasedQosPolicy: bool = False
    webPolicy: ObjectReference | None = None
    webProxy: bool = False
    zeroDayProtection: bool = False


class SecurityFeaturesIpv6(_ClosedModel):
    """The IPv6 rule's security-feature settings (the IPv6 schema has no ``scanFtp``)."""

    applicationBasedQosPolicy: bool = False
    applicationPolicy: ObjectReference | None = None
    blockQuicProtocol: bool = False
    decryptHTTPSWebProxyMode: bool = False
    ipsPolicy: ObjectReference | None = None
    scanHttpAndDecryptedHttps: bool = False
    scanWithNdrActiveThreatIntelligence: bool = False
    webCategoryBasedQosPolicy: bool = False
    webPolicy: ObjectReference | None = None
    webProxy: bool = False
    zeroDayProtection: bool = False


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

    trafficShapingPolicy: ObjectReference | None = None
    dscpMarking: DscpMarking | None = None


# -- Create requests -------------------------------------------------------------------


class CreateFirewallRuleIpv4Input(_ClosedModel):
    """Create an IPv4 firewall rule (``createFirewallRuleIpv4``).

    ``enabled`` defaults to ``false`` so a created rule is never enabled by relying on the
    schema's ``true`` default; the adapter always sends the explicit value. ``position`` is
    required: the appliance needs the insertion point, and ``after``/``before`` require a
    ``referenceItem`` anchor. ``ruleType`` accepts only ``firewall`` (WAF is out of scope).
    """

    name: RuleName
    description: Description | None = None
    ruleType: Literal["firewall"] = "firewall"
    enabled: bool = False
    action: FirewallAction = "accept"
    sourceZones: ZoneMatch
    destinationZones: ZoneMatch
    sourceNetworks: Ipv4NetworkMatch
    destinationNetworks: Ipv4NetworkMatch
    servicesOrGroups: ServiceMatch
    userAuthentication: UserAuthentication | None = None
    exclusions: ExclusionsIpv4 | None = None
    synchronizedSecurityHeartbeat: SynchronizedSecurityHeartbeat | None = None
    securityFeatures: SecurityFeaturesIpv4 | None = None
    emailScanning: EmailScanning | None = None
    qos: Qos | None = None
    logTraffic: bool = False
    schedule: ObjectReference | None = None
    position: RulePosition
    referenceItem: ObjectReference | None = None

    @model_validator(mode="after")
    def _check_position(self) -> Self:
        _require_anchor(self.position, self.referenceItem)
        return self


class CreateFirewallRuleIpv6Input(_ClosedModel):
    """Create an IPv6 firewall rule (``createFirewallRuleIpv6``).

    The IPv6 schema has no ``ruleType`` discriminator and no WAF variant; the field is
    still sent as ``firewall`` because the contract declares it required.
    """

    name: RuleName
    description: Description | None = None
    ruleType: Literal["firewall"] = "firewall"
    enabled: bool = False
    action: FirewallAction = "accept"
    sourceZones: ZoneMatch
    destinationZones: ZoneMatch
    sourceNetworks: Ipv6NetworkMatch
    destinationNetworks: Ipv6NetworkMatch
    servicesOrGroups: ServiceMatch
    userAuthentication: UserAuthentication | None = None
    exclusions: ExclusionsIpv6 | None = None
    securityFeatures: SecurityFeaturesIpv6 | None = None
    emailScanning: EmailScanning | None = None
    qos: Qos | None = None
    logTraffic: bool = False
    schedule: ObjectReference | None = None
    position: RulePosition
    referenceItem: ObjectReference | None = None

    @model_validator(mode="after")
    def _check_position(self) -> Self:
        _require_anchor(self.position, self.referenceItem)
        return self


# -- Update (PATCH) requests -----------------------------------------------------------

#: Update members where an explicit ``null`` is a JSON Merge Patch removal. Every other
#: member is a scalar or a required match criterion and cannot be nulled.
_REMOVABLE_UPDATE_FIELDS = frozenset(
    {
        "description",
        "schedule",
        "userAuthentication",
        "exclusions",
        "synchronizedSecurityHeartbeat",
        "securityFeatures",
        "emailScanning",
        "qos",
    }
)


class _UpdateFirewallRuleBase(_ClosedModel):
    """Members shared by the IPv4 and IPv6 JSON Merge Patch bodies.

    Every member is optional and the adapter serializes with ``exclude_unset=True``, so an
    omitted member keeps its persisted value. ``idOrName`` identifies the target and is
    never part of the body.
    """

    idOrName: ObjectNameOrId
    name: RuleName | None = None
    description: Description | None = None
    enabled: bool | None = None
    action: FirewallAction | None = None
    sourceZones: ZoneMatch | None = None
    destinationZones: ZoneMatch | None = None
    servicesOrGroups: ServiceMatch | None = None
    userAuthentication: UserAuthentication | None = None
    emailScanning: EmailScanning | None = None
    qos: Qos | None = None
    logTraffic: bool | None = None
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

    sourceNetworks: Ipv4NetworkMatch | None = None
    destinationNetworks: Ipv4NetworkMatch | None = None
    exclusions: ExclusionsIpv4 | None = None
    synchronizedSecurityHeartbeat: SynchronizedSecurityHeartbeat | None = None
    securityFeatures: SecurityFeaturesIpv4 | None = None


class UpdateFirewallRuleIpv6Input(_UpdateFirewallRuleBase):
    """Partially update an IPv6 firewall rule (``updateFirewallRuleIpv6``)."""

    sourceNetworks: Ipv6NetworkMatch | None = None
    destinationNetworks: Ipv6NetworkMatch | None = None
    exclusions: ExclusionsIpv6 | None = None
    securityFeatures: SecurityFeaturesIpv6 | None = None


# -- Other operation requests ----------------------------------------------------------


class ListFirewallRulesInput(_ClosedModel):
    """One page of a firewall-rule collection (``getAllFirewallRulesIpv4/Ipv6``).

    ``nameContains`` and ``nameNotEquals`` are mutually exclusive in the contract, so at
    most one may be supplied. Pagination is one explicit page per call; the adapter never
    walks the collection automatically.
    """

    page: int = Field(default=1, ge=1)
    pageSize: int = Field(default=50, ge=1, le=100)
    pageTotal: bool = False
    nameContains: str | None = Field(default=None, min_length=1, max_length=MAX_NAME_FILTER_LENGTH)
    nameNotEquals: str | None = Field(default=None, min_length=1, max_length=MAX_NAME_FILTER_LENGTH)

    @model_validator(mode="after")
    def _check_name_filters(self) -> Self:
        if self.nameContains is not None and self.nameNotEquals is not None:
            raise ValueError(
                "nameContains and nameNotEquals are mutually exclusive; set at most one"
            )
        return self


class GetFirewallRuleInput(_ClosedModel):
    """Read one firewall rule by id or name (``getFirewallRuleIpv4/Ipv6``)."""

    idOrName: ObjectNameOrId


class DeleteFirewallRuleInput(_ClosedModel):
    """Delete one firewall rule by id or name (``deleteFirewallRuleIpv4/Ipv6``)."""

    idOrName: ObjectNameOrId


class MoveFirewallRuleInput(_ClosedModel):
    """Move one firewall rule (``moveFirewallRuleIpv4/Ipv6``).

    The operation requires the rule to be identified by **name**; ``idOrName`` is not
    accepted here. ``after``/``before`` require a ``referenceItem`` anchor.
    """

    name: RuleName
    position: RulePosition
    referenceItem: ObjectReference | None = None

    @model_validator(mode="after")
    def _check_position(self) -> Self:
        _require_anchor(self.position, self.referenceItem)
        return self


class SetFirewallRuleEnabledInput(_ClosedModel):
    """Enable or disable one firewall rule by PATCHing ``enabled``.

    ``enabled`` is required: the caller must choose the target state, so a missing value
    can never silently disable a rule.
    """

    idOrName: ObjectNameOrId
    enabled: bool


class CloneFirewallRuleInput(_ClosedModel):
    """Clone one firewall rule into a new rule (get + create).

    The source is read with the matching get operation and re-created with the matching
    create operation. The clone is never auto-enabled: ``enabled`` defaults to ``false``.
    """

    source: ObjectNameOrId
    name: RuleName
    position: RulePosition
    referenceItem: ObjectReference | None = None
    enabled: bool = False

    @model_validator(mode="after")
    def _check_position(self) -> Self:
        _require_anchor(self.position, self.referenceItem)
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
    """

    id: str | None = None
    name: str
    ruleType: Literal["firewall"] = "firewall"
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
    """One page of IPv6 firewall rules (the IPv6 contract has no WAF variant)."""


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
