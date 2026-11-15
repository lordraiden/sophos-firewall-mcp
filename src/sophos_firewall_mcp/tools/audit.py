"""Audit, connectivity-explanation and object-usage tools (issue #35).

Three **composite, read-only** tools that add no Sophos operation. They call the audited
list/get operations through the domain adapters of issues #27-#31 and reason over the
projected results:

====================================  ==============================================
Tool                                  Underlying audited reads (through adapters)
====================================  ==============================================
``audit_firewall_rules``              ``getAllFirewallRulesIpv4/Ipv6``,
                                      ``getAllNatRulesIpv4/Ipv6``,
                                      ``getAllIpAddresses``, ``getAllIpv6Addresses``,
                                      ``getAllFqdns``, ``getAllIpv4AddressGroups``,
                                      ``getAllIpv6AddressGroups``, ``getAllFqdnGroups``,
                                      ``getAllServices``, ``getAllServiceGroups``,
                                      ``getAllZones`` (for the WAN-zone classification)
``explain_connectivity``              ``listNetworkInterfaces``, ``getAllZones``,
                                      ``getAllFirewallRulesIpv4/Ipv6``,
                                      ``getAllNatRulesIpv4/Ipv6``, ``getGatewaysIpv4/Ipv6``,
                                      ``getUnicastRoutesIPv4/Ipv6``
``find_object_usage``                 ``getAllFirewallRulesIpv4/Ipv6``,
                                      ``getAllNatRulesIpv4/Ipv6`` and the address-group,
                                      FQDN-group and service-group lists
====================================  ==============================================

The tools never build a URL, a header or an HTTP client and never call
``SophosRestClient`` directly: every read goes through the adapter that owns the
operation, so the path, the pagination metadata and the error mapping stay in one place.
The network adapter owns its path constants but does not export them, so this module
imports them instead of keeping a second copy of the paths.

What the analysis can and cannot claim
--------------------------------------
The domain projections are the only evidence these tools have, and the audit reports the
gaps instead of guessing:

* A **rule** projection carries zones, networks, services, action, ``enabled``, logging and
  schedule. It does not carry user authentication or exclusions, so a ``shadowed`` finding
  is a candidate for review, not a proof; the limitation is stated in the output notes.
* **Address- and service-object membership is not resolved** by ``explain_connectivity``:
  a rule whose network or service criteria reference objects is reported as
  ``not-verifiable`` for that criterion instead of being assumed to match or not match.
* An **FQDN endpoint** cannot be resolved without DNS, and the contract has no name
  resolution operation, so such a flow is reported as ``not-verifiable``.
* **Routing** is evaluated over the configured static unicast routes and gateways; the
  contract exposes no live routing table, so dynamic routing is not evaluated.
* ``explain_connectivity`` is **configuration analysis**, not a packet test: the contract
  has no ping, traceroute, packet capture or flow-simulation endpoint. The output says so
  (``method="config-analysis"``).

Bounded work
------------
A tool call never auto-paginates the caller's request, but the analysis needs a bounded
internal walk. Each collection is read for at most ``MAX_ITEMS_PER_COLLECTION`` items and
``MAX_PAGES_PER_COLLECTION`` pages, with a global page cap, and the walk stops on the
appliance's ``pages.total`` metadata or on a short page. Every result carries a
:class:`~sophos_firewall_mcp.models.audit.ScanReport`; ``truncated`` is true only when a
limit was actually hit.

Errors are mapped by the domain adapters through
:func:`~sophos_firewall_mcp.tools.tool_error`; this module adds no transport handling and
never catches ``BaseException`` or ``CancelledError``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, ValidationError

from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.models.audit import (
    ALL_CHECKS,
    MAX_RULES_REPORTED,
    MAX_TEXT,
    AddressFamily,
    AuditCheck,
    AuditFinding,
    AuditFirewallRulesInput,
    AuditFirewallRulesOutput,
    ConnectivityEndpoint,
    ConnectivityService,
    EndpointSummary,
    ExplainConnectivityInput,
    ExplainConnectivityOutput,
    FindingEvidence,
    FindObjectUsageInput,
    FindObjectUsageOutput,
    InterfaceMatch,
    IpFamily,
    NatEvaluation,
    ObjectReference,
    ObjectType,
    RoutingDecision,
    RuleEvaluation,
    ScanReport,
    ServiceSummary,
    Severity,
    UnverifiableCheck,
    ZoneMatch,
)
from sophos_firewall_mcp.models.common import ListPage, ObjectRef
from sophos_firewall_mcp.models.firewall import (
    FirewallRuleIpv4Output,
    FirewallRuleIpv6Output,
    Ipv4NetworkMatchOutput,
    Ipv6NetworkMatchOutput,
    ListFirewallRulesInput,
    ServiceMatchOutput,
    ZoneMatchOutput,
)
from sophos_firewall_mcp.models.nat import (
    NatRuleInterfacesOutput,
    NatRuleListInput,
    NatRuleNetworksOutput,
    NatRuleOutput,
    NatRuleServicesOutput,
    NatRuleTranslationOutput,
)
from sophos_firewall_mcp.models.network import (
    FilteredPageInput,
    GatewayIpv4,
    GatewayIpv6,
    NetworkInterface,
    UnicastRouteIpv4,
    UnicastRouteIpv6,
    Zone,
)
from sophos_firewall_mcp.models.objects import (
    FqdnAddress,
    FqdnAddressGroup,
    FqdnAddressGroupListInput,
    FqdnAddressListInput,
    Ipv4Address,
    Ipv4AddressGroup,
    Ipv4AddressGroupListInput,
    Ipv4AddressListInput,
    Ipv6Address,
    Ipv6AddressGroup,
    Ipv6AddressGroupListInput,
    Ipv6AddressListInput,
    Service,
    ServiceGroup,
    ServiceGroupListInput,
    ServiceListInput,
)
from sophos_firewall_mcp.tools import DomainAdapter, ToolKind, register_tool
from sophos_firewall_mcp.tools.firewall_rules import FirewallRuleAdapter
from sophos_firewall_mcp.tools.hosts_objects import ObjectsAdapter
from sophos_firewall_mcp.tools.nat_rules import IPV4_RULES_PATH, IPV6_RULES_PATH, NatAdapter
from sophos_firewall_mcp.tools.network import (
    GATEWAYS_IPV4_PATH,
    GATEWAYS_IPV6_PATH,
    INTERFACES_PATH,
    UNICAST_ROUTES_IPV4_PATH,
    UNICAST_ROUTES_IPV6_PATH,
    ZONES_PATH,
    NetworkAdapter,
)
from sophos_firewall_mcp.tools.services_objects import ServicesAdapter

__all__ = ["AuditAdapter", "register_audit_tools"]

#: Page size requested by the bounded internal walk (the appliance's maximum).
PAGE_SIZE = 100

#: Maximum items read from one collection by the bounded internal walk.
MAX_ITEMS_PER_COLLECTION = 500

#: Maximum pages read from one collection (``MAX_ITEMS_PER_COLLECTION / PAGE_SIZE``).
MAX_PAGES_PER_COLLECTION = MAX_ITEMS_PER_COLLECTION // PAGE_SIZE

#: Global page cap across every collection of one tool call.
MAX_PAGES_TOTAL = 80

#: The projected network members of a firewall rule, in both IP families.
_NETWORK_FIELDS = (
    "countries",
    "countryGroups",
    "fqdnAddresses",
    "fqdnGroups",
    "ipv4Addresses",
    "ipv4Groups",
    "macAddresses",
    "ipv6Addresses",
    "ipv6Groups",
)

#: The projected network members of a NAT rule (flattened to plain names).
_NAT_NETWORK_FIELDS = (
    "mac_addresses",
    "ipv4_addresses",
    "ipv4_groups",
    "fqdn_addresses",
    "fqdn_groups",
    "countries",
    "country_groups",
    "ipv6_addresses",
    "ipv6_groups",
)

#: A projected firewall rule of either IP family.
RuleOutput = FirewallRuleIpv4Output | FirewallRuleIpv6Output

#: The verdicts the rule evaluation can reach internally (``truncated`` is mapped later).
_OutcomeVerdict = str

#: The checks that report a firewall rule; ``rule_name_contains`` narrows the report to them.
_RULE_SCOPED_CHECKS = frozenset(
    {"any-any", "disabled", "shadowed", "no-logging", "unrestricted-service"}
)

#: Severity order used to sort findings before the output bound is applied.
_SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2, "info": 3}

PageT = TypeVar("PageT", bound=BaseModel)
ItemT = TypeVar("ItemT")


# -- Bounded walk and collectors -------------------------------------------------------


@dataclass
class _Budget:
    """The bounded-walk budget of one tool call."""

    max_items_per_collection: int = MAX_ITEMS_PER_COLLECTION
    max_pages_per_collection: int = MAX_PAGES_PER_COLLECTION
    max_pages_total: int = MAX_PAGES_TOTAL
    pages_read: int = 0
    items_scanned: int = 0
    collections: list[str] = field(default_factory=list)
    truncated_collections: list[str] = field(default_factory=list)
    truncated: bool = False

    def report(self) -> ScanReport:
        """Project the budget into the bounded, explicit scan report."""
        return ScanReport(
            collections=list(self.collections),
            items_scanned=self.items_scanned,
            pages_read=self.pages_read,
            item_limit_per_collection=self.max_items_per_collection,
            truncated=self.truncated,
            truncated_collections=list(self.truncated_collections),
        )


class _Findings:
    """Collect findings and apply the output bound after sorting them by severity.

    Findings are collected unbounded (the scan itself is bounded) and sorted by severity
    before ``max_findings`` is applied, so truncation drops the least important findings
    instead of whichever check happened to run last.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._items: list[AuditFinding] = []
        self.truncated = False

    def add(self, finding: AuditFinding) -> None:
        self._items.append(finding)

    def finalize(self) -> list[AuditFinding]:
        """Sort by severity, then canonical check order, and apply the output bound."""
        check_order = {check: index for index, check in enumerate(ALL_CHECKS)}
        ordered = sorted(
            enumerate(self._items),
            key=lambda item: (
                _SEVERITY_ORDER.get(item[1].severity, len(_SEVERITY_ORDER)),
                check_order.get(item[1].check, len(ALL_CHECKS)),
                item[0],
            ),
        )
        selected = [finding for _, finding in ordered[: self._limit]]
        self.truncated = len(self._items) > self._limit
        return selected


@dataclass
class _UnverifiableEntry:
    """One aggregated ``not_verifiable`` reason."""

    subjects: list[str] = field(default_factory=list)
    count: int = 0


class _Unverifiable:
    """Aggregate the reasons a check could not be completed, instead of guessing."""

    def __init__(self) -> None:
        self._entries: dict[tuple[AuditCheck, str], _UnverifiableEntry] = {}

    def add(self, check: AuditCheck, reason: str, subject: str | None = None) -> None:
        entry = self._entries.setdefault((check, reason), _UnverifiableEntry())
        entry.count += 1
        if subject is not None and len(entry.subjects) < 10 and subject not in entry.subjects:
            entry.subjects.append(subject)

    def models(self) -> list[UnverifiableCheck]:
        order = {check: index for index, check in enumerate(ALL_CHECKS)}
        ordered = sorted(self._entries.items(), key=lambda item: order.get(item[0][0], 99))
        return [
            UnverifiableCheck(
                check=check,
                reason=reason,
                subjects=list(entry.subjects),
                subject_count=entry.count,
            )
            for (check, reason), entry in ordered
        ]


@dataclass(frozen=True)
class _ObjectEntry:
    """One address or service object found by the inventory scan."""

    name: str
    id: str | None
    object_type: ObjectType
    family: AddressFamily | None
    built_in: bool = False


@dataclass(frozen=True)
class _GroupEntry:
    """One address or service group with the names of its members."""

    name: str
    id: str | None
    kind: str
    family: AddressFamily | None
    members: list[str]


@dataclass
class _ResolvedEndpoint:
    """One flow endpoint resolved against the local interfaces and zones."""

    ip: str | None = None
    zone: str | None = None
    fqdn: str | None = None
    zones: set[str] = field(default_factory=set)
    interfaces: list[str] = field(default_factory=list)
    interface_hits: list[tuple[str, str | None, str]] = field(default_factory=list)
    local: bool | None = None
    family: IpFamily | None = None
    unresolved: bool = False


@dataclass
class _IndeterminateRule:
    """One rule that matches every resolvable criterion but cannot be decided."""

    rule: RuleOutput
    position: int
    unresolved_fields: list[str]


@dataclass
class _RuleOutcome:
    """The result of evaluating one family's rule base against a flow."""

    matched: list[RuleEvaluation] = field(default_factory=list)
    decisive: RuleEvaluation | None = None
    verdict: _OutcomeVerdict = "no-matching-rule"
    examined: int = 0
    indeterminate: list[_IndeterminateRule] = field(default_factory=list)
    truncated: bool = False


# -- Pure matching helpers -------------------------------------------------------------


def _ref_names(match: object, field_name: str) -> set[str]:
    """The names of one ``list[{name}]`` member of a projected match, defensively."""
    value = getattr(match, field_name, None)
    if not isinstance(value, list):
        return set()
    names: set[str] = set()
    for reference in value:
        if isinstance(reference, ObjectRef):
            names.add(reference.name)
    return names


def _string_names(value: object) -> set[str]:
    """The strings of one ``list[str]`` member, defensively."""
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str)}


def _is_built_in(name: str, *timestamps: datetime | None) -> bool:
    """Whether an object is built-in or auto-generated and therefore not removable.

    The appliance prefixes its built-in objects with ``##`` (``##ALL_RW``) and its
    auto-generated interface objects with ``#`` (``#Port2``); it also stamps built-in objects
    with the Unix epoch as a "never" sentinel. An operator cannot remove any of them, so
    reporting them as removable is noise.

    This is a heuristic, not a contract field: the REST projection exposes no ``builtIn``
    flag. It was confirmed against the live appliance (``10.10.10.1``) on 2026-11-15 with a
    read-only ``service_list`` call (``SOPHOS_READ_ONLY_MODE=true``, 93 services on one
    page): every service carried ``createdAt == updatedAt == 1970-01-01T00:00:00Z``,
    including the built-in ``AH``, ``AOL``, ``BGP``, ``DHCP``, ``DNS``, ``FTP``, ``HTTP``,
    ``HTTPS``, ``ICMP``, ``IMAP``, ``LDAP``, ``NTP``, ``POP3``, ``PPTP``, ``SMTP``, ``SNMP``,
    ``SSH``, ``TELNET`` and ``TFTP`` entries, so the epoch rule does exclude them. The same
    run also showed the limit of the heuristic: the appliance does not populate service
    timestamps at all, so operator-created services (``DOCKHAND_MCP``,
    ``HomeAssistant (8123)``, …) carry the epoch too and are excluded as well. The exclusion
    is therefore a noise filter, not a proof that an object is built-in; the ``unused-object``
    note states this explicitly and reports how many objects it skipped.
    """
    if name.startswith("#"):
        return True
    return any(
        timestamp is not None and timestamp.replace(tzinfo=None) == datetime(1970, 1, 1)
        for timestamp in timestamps
    )


def _translation_names(translation: NatRuleTranslationOutput | None) -> set[str]:
    """The address-object names a NAT translation references."""
    if translation is None:
        return set()
    names = {
        translation.ipv4_address,
        translation.fqdn_address,
        translation.ipv6_address,
    }
    return {name for name in names if name is not None}


def _zones_cover(earlier: ZoneMatchOutput, later: ZoneMatchOutput) -> bool:
    """Whether *earlier* matches every zone *later* matches."""
    if earlier.any:
        return True
    if later.any:
        return False
    earlier_names = {zone.name.casefold() for zone in earlier.zones}
    later_names = {zone.name.casefold() for zone in later.zones}
    return later_names <= earlier_names


def _networks_cover(
    earlier: Ipv4NetworkMatchOutput | Ipv6NetworkMatchOutput,
    later: Ipv4NetworkMatchOutput | Ipv6NetworkMatchOutput,
) -> bool:
    """Whether *earlier* references every network object *later* references.

    A broader object with a different name cannot be proven to cover a narrower one, so
    the comparison is a set superset over the projected names. That can miss a shadowing
    (a conservative false negative) but never invents one.
    """
    if earlier.any:
        return True
    if later.any:
        return False
    return all(_ref_names(later, name) <= _ref_names(earlier, name) for name in _NETWORK_FIELDS)


def _services_cover(earlier: ServiceMatchOutput, later: ServiceMatchOutput) -> bool:
    """Whether *earlier* matches every service *later* matches."""
    if earlier.any:
        return True
    if later.any:
        return False
    return _ref_names(later, "services") <= _ref_names(earlier, "services") and _ref_names(
        later, "serviceGroups"
    ) <= _ref_names(earlier, "serviceGroups")


def _schedule_covers(earlier: ObjectRef | None, later: ObjectRef | None) -> bool:
    """Whether *earlier*'s schedule covers every moment *later* applies."""
    if earlier is None:
        return True
    if later is None:
        return False
    return earlier.name.casefold() == later.name.casefold()


def _zones_equal(earlier: ZoneMatchOutput | None, later: ZoneMatchOutput | None) -> bool:
    if earlier is None or later is None:
        return earlier is None and later is None
    if earlier.any or later.any:
        return earlier.any == later.any
    return {zone.name.casefold() for zone in earlier.zones} == {
        zone.name.casefold() for zone in later.zones
    }


def _networks_equal(
    earlier: Ipv4NetworkMatchOutput | Ipv6NetworkMatchOutput | None,
    later: Ipv4NetworkMatchOutput | Ipv6NetworkMatchOutput | None,
) -> bool:
    if earlier is None or later is None:
        return earlier is None and later is None
    if earlier.any or later.any:
        return earlier.any == later.any
    return all(_ref_names(earlier, name) == _ref_names(later, name) for name in _NETWORK_FIELDS)


def _services_equal(earlier: ServiceMatchOutput | None, later: ServiceMatchOutput | None) -> bool:
    if earlier is None or later is None:
        return earlier is None and later is None
    if earlier.any or later.any:
        return earlier.any == later.any
    return _ref_names(earlier, "services") == _ref_names(later, "services") and _ref_names(
        earlier, "serviceGroups"
    ) == _ref_names(later, "serviceGroups")


def _schedule_equal(earlier: ObjectRef | None, later: ObjectRef | None) -> bool:
    if earlier is None or later is None:
        return earlier is None and later is None
    return earlier.name.casefold() == later.name.casefold()


def _covers(earlier: RuleOutput, later: RuleOutput) -> bool | None:
    """Whether *earlier* fully covers *later*; ``None`` when the projection cannot tell."""
    if (
        earlier.sourceZones is None
        or earlier.destinationZones is None
        or earlier.servicesOrGroups is None
        or earlier.sourceNetworks is None
        or earlier.destinationNetworks is None
    ):
        return None
    if (
        later.sourceZones is None
        or later.destinationZones is None
        or later.servicesOrGroups is None
        or later.sourceNetworks is None
        or later.destinationNetworks is None
    ):
        return None
    if not _schedule_covers(earlier.schedule, later.schedule):
        return False
    return (
        _zones_cover(earlier.sourceZones, later.sourceZones)
        and _zones_cover(earlier.destinationZones, later.destinationZones)
        and _networks_cover(earlier.sourceNetworks, later.sourceNetworks)
        and _networks_cover(earlier.destinationNetworks, later.destinationNetworks)
        and _services_cover(earlier.servicesOrGroups, later.servicesOrGroups)
    )


def _duplicate(earlier: RuleOutput, later: RuleOutput) -> bool:
    """Whether two rules have identical criteria and action (a duplicate, not just shadowed)."""
    if earlier.action != later.action:
        return False
    return (
        _schedule_equal(earlier.schedule, later.schedule)
        and _zones_equal(earlier.sourceZones, later.sourceZones)
        and _zones_equal(earlier.destinationZones, later.destinationZones)
        and _networks_equal(earlier.sourceNetworks, later.sourceNetworks)
        and _networks_equal(earlier.destinationNetworks, later.destinationNetworks)
        and _services_equal(earlier.servicesOrGroups, later.servicesOrGroups)
    )


def _zone_match(rule_zones: ZoneMatchOutput | None, endpoint_zones: set[str]) -> bool | None:
    """Whether a rule's zone criterion matches; ``None`` when the endpoint zone is unknown."""
    if rule_zones is None:
        return None
    if rule_zones.any:
        return True
    if not endpoint_zones:
        return None
    rule_names = {zone.name.casefold() for zone in rule_zones.zones}
    return bool(rule_names & endpoint_zones)


def _network_match(
    rule_networks: Ipv4NetworkMatchOutput | Ipv6NetworkMatchOutput | None,
) -> bool | None:
    """Whether a rule's network criterion matches; ``None`` for unresolvable objects."""
    if rule_networks is None:
        return None
    if rule_networks.any:
        return True
    # The projection carries object names, not their contents: membership is not resolved.
    return None


def _service_match(
    rule_services: ServiceMatchOutput | None, service: ConnectivityService
) -> bool | None:
    """Whether a rule's service criterion matches; ``None`` when it cannot be decided."""
    if rule_services is None:
        return None
    if rule_services.any:
        return True
    if service.name is not None:
        names = {reference.name.casefold() for reference in rule_services.services}
        if service.name.casefold() in names:
            return True
        if not rule_services.serviceGroups:
            return False
    # A protocol/port cannot be mapped to service objects without their definitions.
    return None


def _nat_interfaces_match(
    match: NatRuleInterfacesOutput | None, endpoint_interfaces: list[str]
) -> bool | None:
    """Whether a NAT interface criterion matches; ``None`` when the flow interface is unknown."""
    if match is None:
        return None
    if match.any:
        return True
    if not endpoint_interfaces:
        return None
    known = {name.casefold() for name in endpoint_interfaces}
    return bool({name.casefold() for name in match.interfaces} & known)


def _nat_networks_match(match: NatRuleNetworksOutput | None) -> bool | None:
    """Whether a NAT network criterion matches; ``None`` for unresolvable objects."""
    if match is None:
        return None
    if match.any:
        return True
    return None


def _nat_services_match(
    match: NatRuleServicesOutput | None, service: ConnectivityService
) -> bool | None:
    """Whether a NAT service criterion matches; ``None`` when it cannot be decided."""
    if match is None:
        return None
    if match.any:
        return True
    if service.name is not None:
        names = {name.casefold() for name in match.services}
        if service.name.casefold() in names:
            return True
        if not match.service_groups:
            return False
    return None


def _destination_includes_wan(
    match: ZoneMatchOutput, zone_types: dict[str, str | None]
) -> bool | None:
    """Whether a rule's destination zones include a WAN zone; ``None`` when unknown."""
    if match.any:
        return True
    if not match.zones:
        return None
    unknown = False
    for reference in match.zones:
        zone_type = zone_types.get(reference.name.casefold())
        if zone_type is None:
            unknown = True
        elif zone_type == "wan":
            return True
    return None if unknown else False


def _source_includes_non_wan(
    match: ZoneMatchOutput, zone_types: dict[str, str | None]
) -> bool | None:
    """Whether a rule's source zones include a non-WAN zone; ``None`` when unknown."""
    if match.any:
        return True
    if not match.zones:
        return None
    unknown = False
    for reference in match.zones:
        zone_type = zone_types.get(reference.name.casefold())
        if zone_type is None:
            unknown = True
        elif zone_type != "wan":
            return True
    return None if unknown else False


def _interface_contains(
    interface: NetworkInterface, address: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> str | None:
    """The interface address whose subnet contains *address*, or ``None``."""
    if isinstance(address, ipaddress.IPv4Address):
        if interface.ipv4 is None:
            return None
        candidates: list[tuple[str | None, int | None]] = [
            (interface.ipv4.ipv4Address, interface.ipv4.cidr)
        ]
        candidates.extend(
            (secondary.ipv4Address, secondary.cidr)
            for secondary in interface.ipv4.secondaryAddresses
        )
    else:
        if interface.ipv6 is None:
            return None
        candidates = [(interface.ipv6.ipv6Address, interface.ipv6.prefixLength)]
        candidates.extend(
            (secondary.ipv6Address, secondary.prefixLength)
            for secondary in interface.ipv6.secondaryAddresses
        )
    for candidate, prefix in candidates:
        if candidate is None or prefix is None:
            continue
        try:
            network = ipaddress.ip_network(f"{candidate}/{prefix}", strict=False)
        except ValueError:
            continue
        if address in network:
            return candidate
    return None


def _route_network(
    route: UnicastRouteIpv4 | UnicastRouteIpv6, family: IpFamily
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The destination network of one static unicast route, or ``None`` when malformed."""
    if family == "ipv4":
        if not isinstance(route, UnicastRouteIpv4):
            return None
        if route.destinationAddressIpv4 is None or route.cidr is None:
            return None
        try:
            return ipaddress.ip_network(
                f"{route.destinationAddressIpv4}/{route.cidr}", strict=False
            )
        except ValueError:
            return None
    if not isinstance(route, UnicastRouteIpv6):
        return None
    if route.destinationAddressIpv6 is None or route.prefixLength is None:
        return None
    try:
        return ipaddress.ip_network(
            f"{route.destinationAddressIpv6}/{route.prefixLength}", strict=False
        )
    except ValueError:
        return None


def _gateway_name(gateways: list[GatewayIpv4 | GatewayIpv6], gateway_ip: str | None) -> str | None:
    """The configured gateway name for an address, when one matches."""
    if gateway_ip is None:
        return None
    for gateway in gateways:
        if (
            getattr(gateway, "ipv4Address", None) == gateway_ip
            or getattr(gateway, "ipv6Address", None) == gateway_ip
        ):
            return gateway.name
    return None


def _canonical_zone_name(canonical_zones: dict[str, Zone], key: str) -> str:
    """The configured zone name for a casefolded key, or the key itself."""
    zone = canonical_zones.get(key)
    if zone is not None and zone.name is not None:
        return zone.name
    return key


def _zone_of_interface(interfaces: list[NetworkInterface], name: str | None) -> str | None:
    """The zone name of a named interface, when known."""
    if name is None:
        return None
    for interface in interfaces:
        if interface.name == name and interface.zone is not None:
            return interface.zone.name
    return None


def _validated_page(payload: Any, model: type[PageT], label: str) -> PageT:
    """Validate one raw network page into its bounded model, with a sanitized error."""
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ())) or "body"
        raise ToolError(
            f"the appliance returned a {label} page that does not match the contract "
            f"({location})"
        ) from exc


class AuditAdapter(DomainAdapter):
    """Compose the domain adapters into the three read-only audit tools.

    The adapter owns no HTTP call of its own: every read goes through the adapter that owns
    the operation, and every projection is a bounded model from
    :mod:`sophos_firewall_mcp.models.audit`.
    """

    # -- Bounded internal walk ---------------------------------------------------------

    async def _walk(
        self,
        label: str,
        budget: _Budget,
        fetch: Callable[[int], Awaitable[ListPage[ItemT]]],
    ) -> list[ItemT]:
        """Read one collection page by page, within the budget, and report the truncation."""
        collected: list[ItemT] = []
        page = 1
        cut = False
        while True:
            if budget.pages_read >= budget.max_pages_total:
                cut = True
                break
            if len(collected) >= budget.max_items_per_collection:
                cut = True
                break
            result = await fetch(page)
            budget.pages_read += 1
            items = list(result.items)
            collected.extend(items)
            budget.items_scanned += len(items)
            total = result.pages.total if result.pages is not None else None
            if total is not None and len(collected) >= total:
                break
            if total is None and len(items) < PAGE_SIZE:
                break
            if len(collected) >= budget.max_items_per_collection:
                cut = True
                break
            if page >= budget.max_pages_per_collection:
                cut = True
                break
            page += 1
        if label not in budget.collections:
            budget.collections.append(label)
        if cut:
            budget.truncated = True
            if label not in budget.truncated_collections:
                budget.truncated_collections.append(label)
        return collected

    # -- Reads through the owning adapters ---------------------------------------------

    async def _rules(self, family: IpFamily, budget: _Budget) -> list[RuleOutput]:
        """Read one family's firewall rule base in evaluation order."""
        adapter = FirewallRuleAdapter(self.context)
        collected: list[RuleOutput] = []
        if family == "ipv4":

            async def fetch_ipv4(page: int) -> ListPage[FirewallRuleIpv4Output]:
                return await adapter.list_ipv4(
                    ListFirewallRulesInput(page=page, page_size=PAGE_SIZE, page_total=True)
                )

            rules_ipv4: list[FirewallRuleIpv4Output] = await self._walk(
                "firewall-rules-ipv4", budget, fetch_ipv4
            )
            collected.extend(rules_ipv4)
        else:

            async def fetch_ipv6(page: int) -> ListPage[FirewallRuleIpv6Output]:
                return await adapter.list_ipv6(
                    ListFirewallRulesInput(page=page, page_size=PAGE_SIZE, page_total=True)
                )

            rules_ipv6: list[FirewallRuleIpv6Output] = await self._walk(
                "firewall-rules-ipv6", budget, fetch_ipv6
            )
            collected.extend(rules_ipv6)
        return collected

    async def _nat_rules(self, family: IpFamily, budget: _Budget) -> list[NatRuleOutput]:
        """Read one family's NAT rule base in evaluation order."""
        adapter = NatAdapter(self.context)
        path = IPV4_RULES_PATH if family == "ipv4" else IPV6_RULES_PATH

        async def fetch(page: int) -> ListPage[NatRuleOutput]:
            return await adapter.list_rules(
                path, NatRuleListInput(page=page, page_size=PAGE_SIZE, page_total=True)
            )

        return await self._walk(f"nat-rules-{family}", budget, fetch)

    async def _zones(self, budget: _Budget) -> list[Zone]:
        """Read the configured zones (``getAllZones``)."""
        adapter = NetworkAdapter(self.context)

        async def fetch(page: int) -> ListPage[Zone]:
            payload = await adapter.page(
                ZONES_PATH, FilteredPageInput(page=page, page_size=PAGE_SIZE, page_total=True)
            )
            return _validated_page(payload, ListPage[Zone], "zones")

        return await self._walk("zones", budget, fetch)

    async def _interfaces(self, budget: _Budget) -> list[NetworkInterface]:
        """Read the configured interfaces (``listNetworkInterfaces``)."""
        adapter = NetworkAdapter(self.context)

        async def fetch(page: int) -> ListPage[NetworkInterface]:
            payload = await adapter.page(
                INTERFACES_PATH, FilteredPageInput(page=page, page_size=PAGE_SIZE, page_total=True)
            )
            return _validated_page(payload, ListPage[NetworkInterface], "interfaces")

        return await self._walk("interfaces", budget, fetch)

    async def _gateways(self, family: IpFamily, budget: _Budget) -> list[GatewayIpv4 | GatewayIpv6]:
        """Read one family's configured gateways (``getGatewaysIpv4/Ipv6``)."""
        adapter = NetworkAdapter(self.context)
        path = GATEWAYS_IPV4_PATH if family == "ipv4" else GATEWAYS_IPV6_PATH
        collected: list[GatewayIpv4 | GatewayIpv6] = []
        if family == "ipv4":

            async def fetch_ipv4(page: int) -> ListPage[GatewayIpv4]:
                payload = await adapter.page(
                    path, FilteredPageInput(page=page, page_size=PAGE_SIZE, page_total=True)
                )
                return _validated_page(payload, ListPage[GatewayIpv4], "IPv4 gateways")

            gateways_ipv4: list[GatewayIpv4] = await self._walk("gateways-ipv4", budget, fetch_ipv4)
            collected.extend(gateways_ipv4)
        else:

            async def fetch_ipv6(page: int) -> ListPage[GatewayIpv6]:
                payload = await adapter.page(
                    path, FilteredPageInput(page=page, page_size=PAGE_SIZE, page_total=True)
                )
                return _validated_page(payload, ListPage[GatewayIpv6], "IPv6 gateways")

            gateways_ipv6: list[GatewayIpv6] = await self._walk("gateways-ipv6", budget, fetch_ipv6)
            collected.extend(gateways_ipv6)
        return collected

    async def _routes(
        self, family: IpFamily, budget: _Budget
    ) -> list[UnicastRouteIpv4 | UnicastRouteIpv6]:
        """Read one family's static unicast routes (``getUnicastRoutesIPv4/Ipv6``)."""
        adapter = NetworkAdapter(self.context)
        path = UNICAST_ROUTES_IPV4_PATH if family == "ipv4" else UNICAST_ROUTES_IPV6_PATH
        collected: list[UnicastRouteIpv4 | UnicastRouteIpv6] = []
        if family == "ipv4":

            async def fetch_ipv4(page: int) -> ListPage[UnicastRouteIpv4]:
                payload = await adapter.page(
                    path, FilteredPageInput(page=page, page_size=PAGE_SIZE, page_total=True)
                )
                return _validated_page(payload, ListPage[UnicastRouteIpv4], "IPv4 routes")

            routes_ipv4: list[UnicastRouteIpv4] = await self._walk(
                "routes-ipv4", budget, fetch_ipv4
            )
            collected.extend(routes_ipv4)
        else:

            async def fetch_ipv6(page: int) -> ListPage[UnicastRouteIpv6]:
                payload = await adapter.page(
                    path, FilteredPageInput(page=page, page_size=PAGE_SIZE, page_total=True)
                )
                return _validated_page(payload, ListPage[UnicastRouteIpv6], "IPv6 routes")

            routes_ipv6: list[UnicastRouteIpv6] = await self._walk(
                "routes-ipv6", budget, fetch_ipv6
            )
            collected.extend(routes_ipv6)
        return collected

    async def _addresses(
        self, families: tuple[AddressFamily, ...], budget: _Budget
    ) -> list[_ObjectEntry]:
        """Read the address objects of the requested families."""
        adapter = ObjectsAdapter(self.context)
        entries: list[_ObjectEntry] = []
        if "ipv4" in families:

            async def fetch_ipv4(page: int) -> ListPage[Ipv4Address]:
                return await adapter.list_ipv4_addresses(
                    Ipv4AddressListInput(
                        page=page,
                        page_size=PAGE_SIZE,
                        page_total=True,
                        name_contains=None,
                        name_not_equals=None,
                    )
                )

            for address_ipv4 in await self._walk("addresses-ipv4", budget, fetch_ipv4):
                entries.append(
                    _ObjectEntry(
                        address_ipv4.name,
                        address_ipv4.id,
                        "address",
                        "ipv4",
                        _is_built_in(
                            address_ipv4.name,
                            address_ipv4.created_at,
                            address_ipv4.updated_at,
                        ),
                    )
                )
        if "ipv6" in families:

            async def fetch_ipv6(page: int) -> ListPage[Ipv6Address]:
                return await adapter.list_ipv6_addresses(
                    Ipv6AddressListInput(
                        page=page,
                        page_size=PAGE_SIZE,
                        page_total=True,
                        name_contains=None,
                        name_not_equals=None,
                    )
                )

            for address_ipv6 in await self._walk("addresses-ipv6", budget, fetch_ipv6):
                entries.append(
                    _ObjectEntry(
                        address_ipv6.name,
                        address_ipv6.id,
                        "address",
                        "ipv6",
                        _is_built_in(
                            address_ipv6.name,
                            address_ipv6.created_at,
                            address_ipv6.updated_at,
                        ),
                    )
                )
        if "fqdn" in families:

            async def fetch_fqdn(page: int) -> ListPage[FqdnAddress]:
                return await adapter.list_fqdn_addresses(
                    FqdnAddressListInput(
                        page=page,
                        page_size=PAGE_SIZE,
                        page_total=True,
                        name_contains=None,
                        name_not_equals=None,
                    )
                )

            for fqdn in await self._walk("addresses-fqdn", budget, fetch_fqdn):
                if fqdn.name is not None:
                    entries.append(
                        _ObjectEntry(
                            fqdn.name,
                            fqdn.id,
                            "address",
                            "fqdn",
                            _is_built_in(fqdn.name, fqdn.created_at, fqdn.updated_at),
                        )
                    )
        return entries

    async def _address_groups(
        self, families: tuple[AddressFamily, ...], budget: _Budget
    ) -> list[_GroupEntry]:
        """Read the address groups of the requested families."""
        adapter = ObjectsAdapter(self.context)
        entries: list[_GroupEntry] = []
        if "ipv4" in families:

            async def fetch_ipv4(page: int) -> ListPage[Ipv4AddressGroup]:
                return await adapter.list_ipv4_address_groups(
                    Ipv4AddressGroupListInput(
                        page=page,
                        page_size=PAGE_SIZE,
                        page_total=True,
                        name_contains=None,
                        name_not_equals=None,
                    )
                )

            for group_ipv4 in await self._walk("address-groups-ipv4", budget, fetch_ipv4):
                if group_ipv4.name is not None:
                    entries.append(
                        _GroupEntry(
                            group_ipv4.name,
                            group_ipv4.id,
                            "address-group",
                            "ipv4",
                            [member.name for member in group_ipv4.ipv4_addresses],
                        )
                    )
        if "ipv6" in families:

            async def fetch_ipv6(page: int) -> ListPage[Ipv6AddressGroup]:
                return await adapter.list_ipv6_address_groups(
                    Ipv6AddressGroupListInput(
                        page=page,
                        page_size=PAGE_SIZE,
                        page_total=True,
                        name_contains=None,
                        name_not_equals=None,
                    )
                )

            for group_ipv6 in await self._walk("address-groups-ipv6", budget, fetch_ipv6):
                if group_ipv6.name is not None:
                    entries.append(
                        _GroupEntry(
                            group_ipv6.name,
                            group_ipv6.id,
                            "address-group",
                            "ipv6",
                            [member.name for member in group_ipv6.ipv6_addresses],
                        )
                    )
        if "fqdn" in families:

            async def fetch_fqdn(page: int) -> ListPage[FqdnAddressGroup]:
                return await adapter.list_fqdn_address_groups(
                    FqdnAddressGroupListInput(
                        page=page,
                        page_size=PAGE_SIZE,
                        page_total=True,
                        name_contains=None,
                        name_not_equals=None,
                    )
                )

            for group_fqdn in await self._walk("address-groups-fqdn", budget, fetch_fqdn):
                if group_fqdn.name is not None:
                    entries.append(
                        _GroupEntry(
                            group_fqdn.name,
                            group_fqdn.id,
                            "address-group",
                            "fqdn",
                            [member.name for member in group_fqdn.fqdns],
                        )
                    )
        return entries

    async def _services(self, budget: _Budget) -> list[_ObjectEntry]:
        """Read the network services (``getAllServices``)."""
        adapter = ServicesAdapter(self.context)

        async def fetch(page: int) -> ListPage[Service]:
            return await adapter.list_services(
                ServiceListInput(
                    page=page,
                    page_size=PAGE_SIZE,
                    page_total=True,
                    name_contains=None,
                    name_not_equals=None,
                )
            )

        return [
            _ObjectEntry(
                service.name,
                service.id,
                "service",
                None,
                _is_built_in(service.name, service.created_at, service.updated_at),
            )
            for service in await self._walk("services", budget, fetch)
        ]

    async def _service_groups(self, budget: _Budget) -> list[_GroupEntry]:
        """Read the service groups (``getAllServiceGroups``)."""
        adapter = ServicesAdapter(self.context)

        async def fetch(page: int) -> ListPage[ServiceGroup]:
            return await adapter.list_service_groups(
                ServiceGroupListInput(
                    page=page,
                    page_size=PAGE_SIZE,
                    page_total=True,
                    name_contains=None,
                    name_not_equals=None,
                )
            )

        return [
            _GroupEntry(
                group.name,
                group.id,
                "service-group",
                None,
                [member.name for member in group.services],
            )
            for group in await self._walk("service-groups", budget, fetch)
        ]

    # -- audit_firewall_rules ----------------------------------------------------------

    async def audit_firewall_rules(
        self, request: AuditFirewallRulesInput
    ) -> AuditFirewallRulesOutput:
        """Run the requested checks over the rule base and return bounded findings."""
        checks: tuple[AuditCheck, ...] = (
            tuple(request.checks) if request.checks is not None else ALL_CHECKS
        )
        notes: list[str] = []
        if request.rule_name_contains is not None:
            # A rule-name filter selects rule-scoped findings; the object- and NAT-scoped
            # checks are not narrowed by it, so running them would bury the answer.
            skipped = [check for check in checks if check not in _RULE_SCOPED_CHECKS]
            checks = tuple(check for check in checks if check in _RULE_SCOPED_CHECKS)
            if skipped:
                notes.append(
                    "rule_name_contains selects rule-scoped findings, so the non-rule-scoped "
                    f"checks ({', '.join(skipped)}) were skipped; omit rule_name_contains to "
                    "run them."
                )
        requested = set(checks)
        families: tuple[IpFamily, ...] = (
            (request.ip_family,) if request.ip_family is not None else ("ipv4", "ipv6")
        )
        budget = _Budget()
        findings = _Findings(request.max_findings)
        unverifiable = _Unverifiable()

        rules: dict[IpFamily, list[RuleOutput]] = {}
        for family in families:
            rules[family] = await self._rules(family, budget)
        rules_examined = sum(len(rules[family]) for family in families)

        # The unused-object check must see the references of both families: services and
        # FQDN objects are family-neutral, so a rule of the other family can reference an
        # object that the requested family's rule base never mentions. Reporting an in-use
        # object as removable is worse than reporting nothing.
        reference_families: tuple[IpFamily, ...] = families
        if "unused-object" in requested and request.ip_family is not None:
            reference_families = ("ipv4", "ipv6")
            for family in reference_families:
                if family not in rules:
                    rules[family] = await self._rules(family, budget)

        nat_by_family: dict[IpFamily, list[NatRuleOutput]] = {}
        if requested & {"unused-object", "nat-without-rule"}:
            nat_families = reference_families if "unused-object" in requested else families
            for family in nat_families:
                nat_by_family[family] = await self._nat_rules(family, budget)
        nat_rules_examined = sum(
            len(nat_by_family[family]) for family in families if family in nat_by_family
        )

        zones: list[Zone] = []
        if "unrestricted-service" in requested:
            zones = await self._zones(budget)

        objects: list[_ObjectEntry] = []
        groups: list[_GroupEntry] = []
        if "unused-object" in requested:
            # Only the object families the requested rule base can reference are inventoried:
            # an IPv4 rule can reference IPv4 and FQDN objects, an IPv6 rule IPv6 objects.
            inventory_families = _inventory_families(request.ip_family)
            objects = await self._addresses(inventory_families, budget)
            objects.extend(await self._services(budget))
            groups = await self._address_groups(inventory_families, budget)
            groups.extend(await self._service_groups(budget))

        selected = _rule_selector(request.rule_name_contains)

        if "any-any" in requested:
            _check_any_any(rules, families, selected, findings, unverifiable)
        if "disabled" in requested:
            _check_disabled(rules, families, selected, findings, unverifiable)
        if "shadowed" in requested:
            _check_shadowed(rules, families, selected, findings, unverifiable)
            notes.append(
                "Shadowing compares the projected criteria (zones, networks, services, action "
                "and schedule). User-authentication and exclusion members are not part of the "
                "firewall-rule projection, so a shadowing finding is a candidate for review, "
                "not a proof."
            )
        if "no-logging" in requested:
            _check_no_logging(rules, families, selected, findings, unverifiable)
        if "unused-object" in requested:
            _check_unused_object(
                rules,
                reference_families,
                nat_by_family,
                groups,
                objects,
                budget,
                findings,
                unverifiable,
            )
            if any(
                label.startswith(("addresses-", "address-groups-", "services", "service-groups"))
                for label in budget.truncated_collections
            ):
                notes.append(
                    "The object inventory was truncated: objects beyond the scanned portion "
                    "were not examined, so this result is not a complete unused-object audit."
                )
        if "nat-without-rule" in requested:
            _check_nat_without_rule(nat_by_family, rules, families, budget, findings, unverifiable)
        if "unrestricted-service" in requested:
            _check_unrestricted_service(
                rules, families, zones, budget, selected, findings, unverifiable
            )

        if request.rule_name_contains is not None:
            notes.append(
                "rule_name_contains selects which rule-scoped findings are reported; the rule "
                "base was still read in full so shadowing is evaluated in real order."
            )
        if "unused-object" in requested:
            notes.append(
                "unused-object counts a reference from any scanned rule, NAT rule or group; a "
                "group membership is a reference even when the group itself is unused."
            )
            notes.append(
                "unused-object excludes built-in and auto-generated objects by heuristic: a "
                "name starting with '#', or the appliance's epoch timestamp "
                "(1970-01-01T00:00:00Z) used as a 'never' sentinel. The REST projection "
                "exposes no built-in flag, and the appliance stamps every service with the "
                "epoch, so a user-created service is excluded too; "
                f"{sum(1 for entry in objects if entry.built_in)} object(s) were excluded this "
                "way and are not findings."
            )
            if request.ip_family is not None:
                notes.append(
                    "unused-object scans the references of both IP families regardless of "
                    "ip_family, so an object referenced only by the other family is not "
                    "reported as unused; the object inventory stays limited to the requested "
                    "family."
                )
        if requested & {"any-any", "disabled", "shadowed", "no-logging", "unrestricted-service"}:
            notes.append(
                "WAF rules are out of v1 scope and are not part of the firewall-rule projection."
            )

        return AuditFirewallRulesOutput(
            findings=findings.finalize(),
            findings_truncated=findings.truncated,
            checks_run=list(checks),
            not_verifiable=unverifiable.models(),
            rules_examined=rules_examined,
            nat_rules_examined=nat_rules_examined,
            scan=budget.report(),
            notes=notes,
        )

    # -- explain_connectivity ----------------------------------------------------------

    async def explain_connectivity(
        self, request: ExplainConnectivityInput
    ) -> ExplainConnectivityOutput:
        """Explain, from configuration, which interface, rule, NAT entry and route apply."""
        budget = _Budget()
        missing: list[str] = []
        notes: list[str] = [
            "Configuration analysis only: the REST contract exposes no ping, traceroute, "
            "packet capture or live flow simulation, so this is not a packet test.",
            "Rules whose network or service criteria reference objects are reported as not "
            "verifiable: address- and service-object membership is not resolved by this tool.",
            "Routing is evaluated over the configured static unicast routes and gateways; the "
            "contract exposes no live routing table, so dynamic routing is not evaluated.",
        ]
        families = _resolve_families(request)
        interfaces = await self._interfaces(budget)
        zones = await self._zones(budget)

        source = _resolve_endpoint(request.source, interfaces)
        destination = _resolve_endpoint(request.destination, interfaces)
        service_summary = ServiceSummary(
            name=request.service.name,
            protocol=request.service.protocol,
            port=request.service.port,
        )

        if source.unresolved or destination.unresolved:
            missing.append(
                "an FQDN endpoint cannot be resolved to an address without DNS, and the REST "
                "contract exposes no name-resolution operation"
            )
            return _explain_output(
                families=families,
                source=source,
                destination=destination,
                service=service_summary,
                zones=zones,
                interfaces=interfaces,
                routing=RoutingDecision(
                    decision="not-verified",
                    destination=destination.fqdn or source.fqdn,
                    note="the destination is not an IP address, so no route can be selected",
                ),
                verdict="not-verifiable",
                verdict_reason="an FQDN endpoint cannot be resolved to an address",
                matched=[],
                decisive=None,
                nat=[],
                missing=missing,
                notes=notes,
                rules_examined=0,
                truncated=budget.truncated,
                budget=budget,
            )

        if not families:
            missing.append(
                "the source and destination IP addresses belong to different IP families"
            )
            return _explain_output(
                families=("ipv4",),
                source=source,
                destination=destination,
                service=service_summary,
                zones=zones,
                interfaces=interfaces,
                routing=RoutingDecision(decision="not-verified"),
                verdict="not-verifiable",
                verdict_reason="the source and destination IP families do not match",
                matched=[],
                decisive=None,
                nat=[],
                missing=missing,
                notes=notes,
                rules_examined=0,
                truncated=budget.truncated,
                budget=budget,
            )

        routing = RoutingDecision(decision="not-verified", destination=destination.ip)
        gateways: dict[IpFamily, list[GatewayIpv4 | GatewayIpv6]] = {}
        routes: dict[IpFamily, list[UnicastRouteIpv4 | UnicastRouteIpv6]] = {}
        if destination.ip is not None:
            if destination.local:
                routing = RoutingDecision(decision="local", destination=destination.ip)
            else:
                family = destination.family or "ipv4"
                gateways[family] = await self._gateways(family, budget)
                routes[family] = await self._routes(family, budget)
                routing_truncated = any(
                    label in budget.truncated_collections
                    for label in (f"gateways-{family}", f"routes-{family}")
                )
                routing = _routing_for(
                    destination,
                    gateways[family],
                    routes[family],
                    truncated=routing_truncated,
                    item_limit=budget.max_items_per_collection,
                )
                route_zone = _zone_of_interface(interfaces, routing.interface)
                if route_zone is not None:
                    destination.zones.add(route_zone.casefold())
                if routing.decision == "no-route":
                    missing.append(
                        "no configured static unicast route matches the destination and no WAN "
                        "gateway is configured; dynamic routing is not evaluated"
                    )
                elif routing.truncated:
                    missing.append(
                        "the gateway and static-route scan was truncated after "
                        f"{budget.max_items_per_collection} items, so the routing decision is "
                        "not verified: a route beyond the scanned portion may change it"
                    )

        if not source.zones and source.ip is not None and not source.local:
            missing.append(
                "the source IP does not belong to a local interface, so the ingress zone is "
                "unknown"
            )
        if destination.ip is not None and not destination.zones:
            missing.append(
                "the destination zone could not be resolved from the interfaces or the route"
            )

        rules: dict[IpFamily, list[RuleOutput]] = {}
        nat: dict[IpFamily, list[NatRuleOutput]] = {}
        for family in families:
            rules[family] = await self._rules(family, budget)
            nat[family] = await self._nat_rules(family, budget)

        # When both endpoints are zones the family is ambiguous, but an empty rule base is
        # not: default to the family that actually has rules instead of refusing to answer.
        scanned_both_families = len(families) == 2
        if len(families) == 2:
            populated = tuple(family for family in families if rules[family])
            empty = tuple(family for family in families if not rules[family])
            if len(populated) == 1 and empty:
                families = populated
                notes.append(
                    f"the {empty[0]} rule base is empty, so the {populated[0]} rule base was used"
                )

        outcomes = {
            family: _evaluate_rules(
                rules[family],
                family,
                request,
                source,
                destination,
                request.max_rules_examined,
            )
            for family in families
        }
        matched: list[RuleEvaluation] = []
        decisive: RuleEvaluation | None = None
        verdict: str
        if len(families) == 1:
            outcome = outcomes[families[0]]
            matched = outcome.matched
            decisive = outcome.decisive
            verdict = outcome.verdict
            if verdict == "truncated":
                verdict = "not-verifiable"
            evidence = _indeterminate_evidence(outcome)
            if evidence is not None:
                missing.append(evidence)
            if outcome.truncated:
                missing.append(
                    f"the rule base scan was truncated after {outcome.examined} rules; a "
                    "matching rule may exist beyond the examined prefix"
                )
        else:
            verdicts = {family: outcomes[family].verdict for family in families}
            unique = set(verdicts.values())
            if len(unique) == 1 and unique <= {"allowed", "denied", "no-matching-rule"}:
                verdict = unique.pop()
                for family in families:
                    matched.extend(outcomes[family].matched)
                    if decisive is None and outcomes[family].decisive is not None:
                        decisive = outcomes[family].decisive
            else:
                verdict = "not-verifiable"
                missing.append(
                    "the IP family is ambiguous (both endpoints are zones), and the IPv4 and "
                    "IPv6 rule bases do not agree; set ip_family to analyse one of them"
                )
            for family in families:
                evidence = _indeterminate_evidence(outcomes[family], family)
                if evidence is not None:
                    missing.append(evidence)
                if outcomes[family].truncated:
                    missing.append(
                        f"the {family} rule base scan was truncated after "
                        f"{outcomes[family].examined} rules"
                    )

        rule_names = {rule.name for family in families for rule in rules[family]}
        rules_truncated = any(
            label.startswith("firewall-rules") for label in budget.truncated_collections
        )
        nat_evaluations = _evaluate_nat(
            nat,
            families,
            request,
            source,
            destination,
            rule_names,
            rules_truncated,
            scanned_both_families,
        )

        if verdict == "allowed":
            reason = (
                f"firewall rule '{decisive.name}' at position {decisive.position} accepts the "
                "flow"
                if decisive is not None
                else "an enabled firewall rule accepts the flow"
            )
        elif verdict == "denied":
            reason = (
                f"firewall rule '{decisive.name}' at position {decisive.position} has action "
                f"'{decisive.action}'"
                if decisive is not None
                else "an enabled firewall rule denies the flow"
            )
        elif verdict == "no-matching-rule":
            reason = "no enabled firewall rule matches the described flow"
        else:
            reason = missing[-1] if missing else "the configuration is insufficient for a verdict"

        return _explain_output(
            families=families,
            source=source,
            destination=destination,
            service=service_summary,
            zones=zones,
            interfaces=interfaces,
            routing=routing,
            verdict=verdict,
            verdict_reason=reason,
            matched=matched,
            decisive=decisive,
            nat=nat_evaluations,
            missing=missing,
            notes=notes,
            rules_examined=sum(outcome.examined for outcome in outcomes.values()),
            truncated=budget.truncated or any(outcome.truncated for outcome in outcomes.values()),
            budget=budget,
        )

    # -- find_object_usage -------------------------------------------------------------

    async def find_object_usage(self, request: FindObjectUsageInput) -> FindObjectUsageOutput:
        """Find every reference to one object across rules, NAT rules and groups."""
        budget = _Budget()
        notes: list[str] = []
        families = _address_families(request.ip_family)

        if request.object_type in ("address", "address-group"):
            group_entries = await self._address_groups(families, budget)
            if request.object_type == "address":
                entries = await self._addresses(families, budget)
            else:
                entries = [
                    _ObjectEntry(group.name, group.id, "address-group", group.family)
                    for group in group_entries
                ]
        else:
            group_entries = await self._service_groups(budget)
            if request.object_type == "service":
                entries = await self._services(budget)
            else:
                entries = [
                    _ObjectEntry(group.name, group.id, "service-group", group.family)
                    for group in group_entries
                ]

        matches = [
            entry
            for entry in entries
            if entry.name == request.identifier
            or (entry.id is not None and entry.id == request.identifier)
        ]
        resolved_name = matches[0].name if matches else None
        resolved_id = matches[0].id if matches else None
        if len(matches) > 1:
            notes.append(
                "multiple objects match the identifier; references are reported for the name "
                f"'{resolved_name}'"
            )
        if not matches:
            if budget.truncated:
                notes.append(
                    "the object was not found in the scanned portion, and the scan was truncated"
                )
            else:
                notes.append(
                    "the object was not found in the scanned collections; references are still "
                    "searched by the given identifier"
                )

        target = resolved_name if resolved_name is not None else request.identifier
        rules: dict[IpFamily, list[RuleOutput]] = {}
        nat: dict[IpFamily, list[NatRuleOutput]] = {}
        for family in ("ipv4", "ipv6"):
            rules[family] = await self._rules(family, budget)
            nat[family] = await self._nat_rules(family, budget)

        references, total = _collect_references(
            target, rules, nat, group_entries, request.max_references
        )
        if total > len(references):
            notes.append(f"{total} references were found; the first {len(references)} are returned")
        if budget.truncated:
            notes.append(
                "a scan was truncated, so references beyond the scanned portion were not "
                "examined"
            )
        notes.append(
            "The REST contract has no usage endpoint: references are derived from the audited "
            "list operations."
        )

        return FindObjectUsageOutput(
            object_type=request.object_type,
            identifier=request.identifier,
            resolved_name=resolved_name,
            resolved_id=resolved_id,
            found=bool(matches),
            references=references,
            reference_count=total,
            truncated=total > len(references) or budget.truncated,
            scan=budget.report(),
            notes=notes,
        )


# -- Check implementations -------------------------------------------------------------


def _rule_selector(fragment: str | None) -> Callable[[RuleOutput], bool]:
    """Build the rule-name filter used to select reported rule-scoped findings."""
    if fragment is None:
        return lambda rule: True
    needle = fragment.casefold()
    return lambda rule: needle in rule.name.casefold()


def _check_any_any(
    rules: dict[IpFamily, list[RuleOutput]],
    families: tuple[IpFamily, ...],
    selected: Callable[[RuleOutput], bool],
    findings: _Findings,
    unverifiable: _Unverifiable,
) -> None:
    """Report enabled accept rules that match any source/destination or any service."""
    for family in families:
        for position, rule in enumerate(rules[family], start=1):
            if not selected(rule):
                continue
            if rule.enabled is None:
                unverifiable.add(
                    "any-any", "the rule projection does not report its enabled state", rule.name
                )
                continue
            if not rule.enabled or rule.action != "accept":
                continue
            if (
                rule.sourceZones is None
                or rule.destinationZones is None
                or rule.servicesOrGroups is None
            ):
                unverifiable.add(
                    "any-any",
                    "the rule projection does not carry every match criterion",
                    rule.name,
                )
                continue
            fields: list[str] = []
            if rule.sourceZones.any and rule.destinationZones.any:
                fields.extend(("sourceZones.any", "destinationZones.any"))
            if rule.servicesOrGroups.any:
                fields.append("servicesOrGroups.any")
            if not fields:
                continue
            if len(fields) == 3:
                summary = f"Rule '{rule.name}' accepts any source, any destination and any service"
                severity: Severity = "high"
            elif len(fields) == 2:
                summary = f"Rule '{rule.name}' accepts any source and any destination"
                severity = "high"
            else:
                summary = f"Rule '{rule.name}' accepts any service"
                severity = "medium"
            findings.add(
                AuditFinding(
                    check="any-any",
                    severity=severity,
                    summary=summary,
                    evidence=FindingEvidence(
                        rule_name=rule.name,
                        rule_id=rule.id,
                        position=position,
                        ip_family=family,
                        fields=fields,
                        detail=(
                            "The enabled accept rule matches every value of the cited criteria, "
                            "so it permits traffic far beyond a specific flow."
                        ),
                    ),
                )
            )


def _check_disabled(
    rules: dict[IpFamily, list[RuleOutput]],
    families: tuple[IpFamily, ...],
    selected: Callable[[RuleOutput], bool],
    findings: _Findings,
    unverifiable: _Unverifiable,
) -> None:
    """Report rules that are present and ordered but disabled."""
    for family in families:
        for position, rule in enumerate(rules[family], start=1):
            if not selected(rule):
                continue
            if rule.enabled is None:
                unverifiable.add(
                    "disabled",
                    "the rule projection does not report its enabled state",
                    rule.name,
                )
                continue
            if rule.enabled:
                continue
            findings.add(
                AuditFinding(
                    check="disabled",
                    severity="low",
                    summary=f"Rule '{rule.name}' is disabled",
                    evidence=FindingEvidence(
                        rule_name=rule.name,
                        rule_id=rule.id,
                        position=position,
                        ip_family=family,
                        fields=["enabled"],
                        detail=(
                            "The rule is present and occupies an evaluation position but is "
                            "disabled, so it never matches traffic."
                        ),
                    ),
                )
            )


def _check_shadowed(
    rules: dict[IpFamily, list[RuleOutput]],
    families: tuple[IpFamily, ...],
    selected: Callable[[RuleOutput], bool],
    findings: _Findings,
    unverifiable: _Unverifiable,
) -> None:
    """Report later rules that an earlier enabled rule fully covers."""
    for family in families:
        family_rules = rules[family]
        for later_index in range(1, len(family_rules)):
            later = family_rules[later_index]
            if not selected(later):
                continue
            if later.enabled is None:
                unverifiable.add(
                    "shadowed",
                    "the rule projection does not report its enabled state",
                    later.name,
                )
                continue
            if not later.enabled:
                continue
            covering: tuple[int, RuleOutput] | None = None
            incomparable = False
            for earlier_index in range(later_index):
                earlier = family_rules[earlier_index]
                if earlier.enabled is not True:
                    continue
                coverage = _covers(earlier, later)
                if coverage is None:
                    incomparable = True
                    continue
                if coverage:
                    covering = (earlier_index, earlier)
                    break
            if covering is None:
                if incomparable:
                    unverifiable.add(
                        "shadowed",
                        "a rule projection omits a match criterion or the schedules differ, so "
                        "coverage cannot be decided",
                        later.name,
                    )
                continue
            earlier_index, earlier = covering
            duplicate = _duplicate(earlier, later)
            action_note = (
                ""
                if earlier.action == later.action
                else f" The covering rule's action is '{earlier.action}' while this rule's is "
                f"'{later.action}'."
            )
            findings.add(
                AuditFinding(
                    check="shadowed",
                    severity="high" if duplicate else "medium",
                    summary=(
                        f"Rule '{later.name}' duplicates rule '{earlier.name}'"
                        if duplicate
                        else f"Rule '{later.name}' is shadowed by rule '{earlier.name}'"
                    ),
                    evidence=FindingEvidence(
                        rule_name=later.name,
                        rule_id=later.id,
                        position=later_index + 1,
                        ip_family=family,
                        fields=[
                            "sourceZones",
                            "destinationZones",
                            "sourceNetworks",
                            "destinationNetworks",
                            "servicesOrGroups",
                        ],
                        detail=(
                            f"The earlier enabled rule '{earlier.name}' at position "
                            f"{earlier_index + 1} matches every flow this rule matches, so this "
                            f"rule can never be reached.{action_note}"
                        ),
                    ),
                )
            )


def _check_no_logging(
    rules: dict[IpFamily, list[RuleOutput]],
    families: tuple[IpFamily, ...],
    selected: Callable[[RuleOutput], bool],
    findings: _Findings,
    unverifiable: _Unverifiable,
) -> None:
    """Report enabled accept/drop rules whose traffic logging is off."""
    for family in families:
        for position, rule in enumerate(rules[family], start=1):
            if not selected(rule):
                continue
            if rule.enabled is None:
                unverifiable.add(
                    "no-logging",
                    "the rule projection does not report its enabled state",
                    rule.name,
                )
                continue
            if not rule.enabled or rule.action not in ("accept", "drop"):
                continue
            if rule.logTraffic is None:
                unverifiable.add(
                    "no-logging",
                    "the rule projection does not report the logging flag",
                    rule.name,
                )
                continue
            if rule.logTraffic:
                continue
            findings.add(
                AuditFinding(
                    check="no-logging",
                    severity="low",
                    summary=f"Rule '{rule.name}' does not log traffic",
                    evidence=FindingEvidence(
                        rule_name=rule.name,
                        rule_id=rule.id,
                        position=position,
                        ip_family=family,
                        fields=["logTraffic"],
                        detail=(
                            "The enabled rule accepts or drops traffic but traffic logging is "
                            "disabled, so its matches are not recorded."
                        ),
                    ),
                )
            )


def _check_unused_object(
    rules: dict[IpFamily, list[RuleOutput]],
    families: tuple[IpFamily, ...],
    nat_by_family: dict[IpFamily, list[NatRuleOutput]],
    groups: list[_GroupEntry],
    objects: list[_ObjectEntry],
    budget: _Budget,
    findings: _Findings,
    unverifiable: _Unverifiable,
) -> None:
    """Report user-created objects no scanned rule, NAT rule or group references.

    Built-in and auto-generated objects are skipped: an operator cannot remove them, so
    reporting them as removable is noise.
    """
    truncated_sources = [
        label
        for label in budget.truncated_collections
        if label.startswith(("firewall-rules", "nat-rules", "address-groups", "service-groups"))
    ]
    if truncated_sources:
        unverifiable.add(
            "unused-object",
            "the rule, NAT or group scan was truncated ("
            + ", ".join(truncated_sources)
            + "), so a reference may exist beyond the scanned portion",
        )
        return
    referenced = _referenced_names(rules, families, nat_by_family, groups)
    for entry in objects:
        if entry.built_in:
            # A built-in or auto-generated object cannot be removed by an operator, so it is
            # not a finding even when nothing references it.
            continue
        if entry.name in referenced:
            continue
        findings.add(
            AuditFinding(
                check="unused-object",
                severity="low",
                summary=f"{entry.object_type.replace('-', ' ').capitalize()} '{entry.name}' is unused",
                evidence=FindingEvidence(
                    object_name=entry.name,
                    object_type=entry.object_type,
                    ip_family=entry.family if entry.family in ("ipv4", "ipv6") else None,
                    fields=["reference-scan"],
                    detail=(
                        "No scanned firewall rule, NAT rule or group references this object, so "
                        "it can be reviewed for removal."
                    ),
                ),
            )
        )


def _check_nat_without_rule(
    nat_by_family: dict[IpFamily, list[NatRuleOutput]],
    rules: dict[IpFamily, list[RuleOutput]],
    families: tuple[IpFamily, ...],
    budget: _Budget,
    findings: _Findings,
    unverifiable: _Unverifiable,
) -> None:
    """Report NAT rules whose linked firewall rule is missing or does not exist."""
    rule_names = {rule.name for family in families for rule in rules[family]}
    rules_truncated = any(
        label.startswith("firewall-rules") for label in budget.truncated_collections
    )
    for family in families:
        for position, nat_rule in enumerate(nat_by_family.get(family, []), start=1):
            severity: Severity = "medium" if nat_rule.enabled else "low"
            if nat_rule.linked_firewall_rule is None:
                findings.add(
                    AuditFinding(
                        check="nat-without-rule",
                        severity=severity,
                        summary=f"NAT rule '{nat_rule.name}' has no linked firewall rule",
                        evidence=FindingEvidence(
                            object_name=nat_rule.name,
                            object_type="nat-rule",
                            position=position,
                            ip_family=family,
                            fields=["linkedFirewallRule"],
                            detail=(
                                "The NAT rule carries no linkedFirewallRule, so no firewall rule "
                                "is associated with the translation."
                            ),
                        ),
                    )
                )
                continue
            if nat_rule.linked_firewall_rule in rule_names:
                continue
            if rules_truncated:
                unverifiable.add(
                    "nat-without-rule",
                    "the firewall-rule scan was truncated, so the linked rule may exist beyond "
                    "the scanned portion",
                    nat_rule.name,
                )
                continue
            findings.add(
                AuditFinding(
                    check="nat-without-rule",
                    severity=severity,
                    summary=(
                        f"NAT rule '{nat_rule.name}' links to missing firewall rule "
                        f"'{nat_rule.linked_firewall_rule}'"
                    ),
                    evidence=FindingEvidence(
                        object_name=nat_rule.name,
                        object_type="nat-rule",
                        position=position,
                        ip_family=family,
                        fields=["linkedFirewallRule"],
                        detail=(
                            "The linkedFirewallRule names a rule that is not present in the "
                            "scanned firewall rule base."
                        ),
                    ),
                )
            )


def _check_unrestricted_service(
    rules: dict[IpFamily, list[RuleOutput]],
    families: tuple[IpFamily, ...],
    zones: list[Zone],
    budget: _Budget,
    selected: Callable[[RuleOutput], bool],
    findings: _Findings,
    unverifiable: _Unverifiable,
) -> None:
    """Report enabled accept rules from a non-WAN zone to WAN with any service."""
    zone_types: dict[str, str | None] = {
        zone.name.casefold(): zone.type for zone in zones if zone.name is not None
    }
    if "zones" in budget.truncated_collections:
        unverifiable.add(
            "unrestricted-service",
            "the zone list was truncated, so the WAN classification of a referenced zone may "
            "be missing",
        )
        return
    for family in families:
        for position, rule in enumerate(rules[family], start=1):
            if not selected(rule):
                continue
            if rule.enabled is None:
                unverifiable.add(
                    "unrestricted-service",
                    "the rule projection does not report its enabled state",
                    rule.name,
                )
                continue
            if not rule.enabled or rule.action != "accept":
                continue
            if rule.servicesOrGroups is None:
                unverifiable.add(
                    "unrestricted-service",
                    "the rule projection does not carry the service criterion",
                    rule.name,
                )
                continue
            if not rule.servicesOrGroups.any:
                continue
            if rule.sourceZones is None or rule.destinationZones is None:
                unverifiable.add(
                    "unrestricted-service",
                    "the rule projection does not carry the zone criteria",
                    rule.name,
                )
                continue
            destination_wan = _destination_includes_wan(rule.destinationZones, zone_types)
            source_non_wan = _source_includes_non_wan(rule.sourceZones, zone_types)
            if destination_wan is None or source_non_wan is None:
                unverifiable.add(
                    "unrestricted-service",
                    "the type of a referenced zone is unknown, so WAN membership cannot be "
                    "decided",
                    rule.name,
                )
                continue
            if not (destination_wan and source_non_wan):
                continue
            findings.add(
                AuditFinding(
                    check="unrestricted-service",
                    severity="high",
                    summary=(f"Rule '{rule.name}' allows any service from a non-WAN zone to WAN"),
                    evidence=FindingEvidence(
                        rule_name=rule.name,
                        rule_id=rule.id,
                        position=position,
                        ip_family=family,
                        fields=[
                            "servicesOrGroups.any",
                            "sourceZones",
                            "destinationZones",
                        ],
                        detail=(
                            "The enabled accept rule permits every service from a non-WAN zone "
                            "to a WAN zone, which is an unrestricted egress policy."
                        ),
                    ),
                )
            )


def _referenced_names(
    rules: dict[IpFamily, list[RuleOutput]],
    families: tuple[IpFamily, ...],
    nat_by_family: dict[IpFamily, list[NatRuleOutput]],
    groups: list[_GroupEntry],
) -> set[str]:
    """Every object name referenced by the scanned rules, NAT rules and groups."""
    names: set[str] = set()
    for family in families:
        for rule in rules[family]:
            for match in (rule.sourceNetworks, rule.destinationNetworks):
                if match is not None:
                    for field_name in _NETWORK_FIELDS:
                        names |= _ref_names(match, field_name)
            if rule.servicesOrGroups is not None:
                names |= _ref_names(rule.servicesOrGroups, "services")
                names |= _ref_names(rule.servicesOrGroups, "serviceGroups")
    for family in families:
        for nat_rule in nat_by_family.get(family, []):
            for nat_match in (
                nat_rule.original_source_networks,
                nat_rule.original_destination_networks,
            ):
                if nat_match is not None:
                    for field_name in _NAT_NETWORK_FIELDS:
                        names |= _string_names(getattr(nat_match, field_name, None))
            if nat_rule.original_services_or_groups is not None:
                names |= set(nat_rule.original_services_or_groups.services)
                names |= set(nat_rule.original_services_or_groups.service_groups)
            if nat_rule.translated_service is not None:
                names.add(nat_rule.translated_service)
            names |= _translation_names(nat_rule.translated_source)
            names |= _translation_names(nat_rule.translated_destination)
            for override in nat_rule.override_snat_for_outbound_interfaces:
                names |= _translation_names(override.translated_source)
    for group in groups:
        names |= set(group.members)
    return names


# -- Connectivity helpers --------------------------------------------------------------


def _address_families(family: AddressFamily | None) -> tuple[AddressFamily, ...]:
    """The address families a lookup covers."""
    if family is not None:
        return (family,)
    return ("ipv4", "ipv6", "fqdn")


def _inventory_families(family: IpFamily | None) -> tuple[AddressFamily, ...]:
    """The object families the audited rule bases can reference.

    An IPv4 firewall rule references IPv4 and FQDN objects; an IPv6 rule references IPv6
    objects. Inventorying a family whose rules were not scanned would report objects as
    unused only because their referencing rules were out of scope.
    """
    if family == "ipv4":
        return ("ipv4", "fqdn")
    if family == "ipv6":
        return ("ipv6",)
    return ("ipv4", "ipv6", "fqdn")


def _resolve_families(request: ExplainConnectivityInput) -> tuple[IpFamily, ...]:
    """The IP families to analyse, inferred from the endpoints when not supplied."""
    if request.ip_family is not None:
        return (request.ip_family,)
    inferred: set[IpFamily] = set()
    for endpoint in (request.source, request.destination):
        if endpoint.ip is not None:
            version = ipaddress.ip_address(endpoint.ip).version
            inferred.add("ipv4" if version == 4 else "ipv6")
    if len(inferred) > 1:
        return ()
    if inferred:
        return (inferred.pop(),)
    return ("ipv4", "ipv6")


def _resolve_endpoint(
    endpoint: ConnectivityEndpoint, interfaces: list[NetworkInterface]
) -> _ResolvedEndpoint:
    """Resolve one endpoint against the local interfaces and zones."""
    if endpoint.ip is not None:
        address = ipaddress.ip_address(endpoint.ip)
        hits: list[tuple[str, str | None, str]] = []
        for interface in interfaces:
            matched_address = _interface_contains(interface, address)
            if matched_address is None:
                continue
            name = interface.name or "unknown"
            zone = interface.zone.name if interface.zone is not None else None
            hits.append((name, zone, matched_address))
        return _ResolvedEndpoint(
            ip=endpoint.ip,
            zones={zone.casefold() for _, zone, _ in hits if zone is not None},
            interfaces=[name for name, _, _ in hits],
            interface_hits=hits,
            local=bool(hits),
            family="ipv4" if address.version == 4 else "ipv6",
        )
    if endpoint.zone is not None:
        return _ResolvedEndpoint(zone=endpoint.zone, zones={endpoint.zone.casefold()})
    return _ResolvedEndpoint(fqdn=endpoint.fqdn, unresolved=True)


def _wan_gateway(
    gateways: list[GatewayIpv4 | GatewayIpv6],
) -> GatewayIpv4 | GatewayIpv6 | None:
    """The first configured WAN gateway, which is the appliance's default route."""
    for gateway in gateways:
        if getattr(gateway, "type", None) == "wan":
            return gateway
    return None


def _routing_for(
    destination: _ResolvedEndpoint,
    gateways: list[GatewayIpv4 | GatewayIpv6],
    routes: list[UnicastRouteIpv4 | UnicastRouteIpv6],
    *,
    truncated: bool = False,
    item_limit: int | None = None,
) -> RoutingDecision:
    """Select the best configured route for a non-local destination.

    A static unicast route wins when one matches. Otherwise the configured WAN gateway is
    the appliance's default route: the contract exposes no live routing table, so the
    active/backup role and dynamic routing are not evaluated.

    When the gateway or route scan was truncated, the decision is marked ``truncated`` and a
    ``no-route`` conclusion is downgraded to ``not-verified``: a route beyond the scanned
    portion could change the answer, and a confident wrong ``no-route`` is exactly what this
    analysis must not produce.
    """
    if destination.ip is None:
        return RoutingDecision(decision="not-verified", note="the destination is not an IP address")
    cut = (
        f"the gateway and static-route scan was truncated after {item_limit} items, so a route "
        "beyond the scanned portion may change this decision"
        if truncated
        else None
    )
    address = ipaddress.ip_address(destination.ip)
    family: IpFamily = destination.family or ("ipv4" if address.version == 4 else "ipv6")
    best_route: UnicastRouteIpv4 | UnicastRouteIpv6 | None = None
    best_prefix = -1
    for route in routes:
        network = _route_network(route, family)
        if network is None:
            continue
        if address in network and network.prefixlen > best_prefix:
            best_route = route
            best_prefix = network.prefixlen
    if best_route is None:
        wan = _wan_gateway(gateways)
        if wan is not None:
            gateway_ip = getattr(wan, "ipv4Address", None) or getattr(wan, "ipv6Address", None)
            note = (
                "no configured static unicast route matches the destination, so the "
                "configured WAN gateway is used as the default route; the contract exposes "
                "no live routing table, so the active/backup role and dynamic routing are "
                "not evaluated"
            )
            return RoutingDecision(
                decision="default-route",
                destination=destination.ip,
                gateway=wan.name,
                gateway_ip=gateway_ip,
                interface=wan.interface.name if wan.interface is not None else None,
                truncated=truncated,
                note=f"{note}; {cut}" if cut is not None else note,
            )
        if cut is not None:
            return RoutingDecision(
                decision="not-verified",
                destination=destination.ip,
                truncated=True,
                note=(
                    "no configured static unicast route matches the destination and no WAN "
                    "gateway was found in the scanned portion; the gateway and static-route "
                    f"scan was truncated after {item_limit} items, so no-route cannot be "
                    "concluded"
                ),
            )
        return RoutingDecision(
            decision="no-route",
            destination=destination.ip,
            note=(
                "no configured static unicast route matches the destination and no WAN gateway "
                "is configured; dynamic routing is not evaluated"
            ),
        )
    gateway_ip = (
        best_route.gatewayIpv4
        if isinstance(best_route, UnicastRouteIpv4)
        else best_route.gatewayIpv6
    )
    interface = best_route.interface.name if best_route.interface is not None else None
    note = (
        "selected from the configured static unicast routes; the contract exposes no live "
        "routing table"
    )
    return RoutingDecision(
        decision="default-route" if best_prefix == 0 else "static-route",
        destination=destination.ip,
        route_name=best_route.name,
        gateway=_gateway_name(gateways, gateway_ip),
        gateway_ip=gateway_ip,
        interface=interface,
        truncated=truncated,
        note=f"{note}; {cut}" if cut is not None else note,
    )


def _evaluate_rules(
    family_rules: list[RuleOutput],
    family: IpFamily,
    request: ExplainConnectivityInput,
    source: _ResolvedEndpoint,
    destination: _ResolvedEndpoint,
    max_rules: int,
) -> _RuleOutcome:
    """Evaluate one family's rule base in order and stop at the first decisive rule.

    Every rule that matches all resolvable criteria but carries an unresolved criterion is
    collected as a structured candidate, not only the first one: the scan continues so the
    operator sees every rule that may match the flow. Once an earlier rule is indeterminate a
    later fully-resolved rule is still reported, but not as decisive, because the earlier rule
    may preempt it.
    """
    matched: list[RuleEvaluation] = []
    indeterminate: list[_IndeterminateRule] = []
    examined = 0
    for position, rule in enumerate(family_rules, start=1):
        if examined >= max_rules:
            return _RuleOutcome(
                matched=matched,
                verdict="not-verifiable" if indeterminate else "truncated",
                examined=examined,
                indeterminate=indeterminate,
                truncated=True,
            )
        examined += 1
        criteria = (
            ("sourceZones", _zone_match(rule.sourceZones, source.zones)),
            ("destinationZones", _zone_match(rule.destinationZones, destination.zones)),
            ("sourceNetworks", _network_match(rule.sourceNetworks)),
            ("destinationNetworks", _network_match(rule.destinationNetworks)),
            ("servicesOrGroups", _service_match(rule.servicesOrGroups, request.service)),
        )
        if any(value is False for _, value in criteria):
            # A criterion that definitively does not match excludes the rule: it must not be
            # decisive, and it is not a candidate either.
            continue
        unresolved = [name for name, value in criteria if value is None]
        matched_fields = [name for name, value in criteria if value is True]
        if unresolved:
            if rule.enabled is not True:
                continue
            matched.append(
                RuleEvaluation(
                    name=rule.name,
                    id=rule.id,
                    position=position,
                    ip_family=family,
                    enabled=rule.enabled,
                    action=rule.action,
                    decisive=False,
                    applied=False,
                    matched_fields=matched_fields,
                    unresolved_fields=unresolved,
                    log_traffic=rule.logTraffic,
                    note=(
                        "the rule matches every criterion that could be resolved, but its "
                        f"{', '.join(unresolved)} reference objects whose membership this "
                        "analysis does not resolve, so it may match the flow"
                    ),
                )
            )
            indeterminate.append(_IndeterminateRule(rule, position, unresolved))
            continue
        if rule.enabled is None:
            matched.append(
                RuleEvaluation(
                    name=rule.name,
                    id=rule.id,
                    position=position,
                    ip_family=family,
                    enabled=rule.enabled,
                    action=rule.action,
                    decisive=False,
                    applied=False,
                    matched_fields=matched_fields,
                    unresolved_fields=["enabled"],
                    log_traffic=rule.logTraffic,
                    note=(
                        "the rule matches the flow criteria but its enabled state is not "
                        "projected, so it may be decisive"
                    ),
                )
            )
            indeterminate.append(_IndeterminateRule(rule, position, ["enabled"]))
            continue
        preempted = bool(indeterminate)
        evaluation = RuleEvaluation(
            name=rule.name,
            id=rule.id,
            position=position,
            ip_family=family,
            enabled=rule.enabled,
            action=rule.action,
            decisive=rule.enabled and not preempted,
            applied=rule.enabled and not preempted,
            matched_fields=matched_fields,
            log_traffic=rule.logTraffic,
            note=(
                "disabled: matches the criteria but is not evaluated"
                if not rule.enabled
                else (
                    "matches the flow, but an earlier rule is indeterminate and may preempt it"
                    if preempted
                    else None
                )
            ),
        )
        matched.append(evaluation)
        if not rule.enabled or preempted:
            continue
        verdict = "allowed" if rule.action == "accept" else "denied"
        return _RuleOutcome(
            matched=matched, decisive=evaluation, verdict=verdict, examined=examined
        )
    return _RuleOutcome(
        matched=matched,
        verdict="not-verifiable" if indeterminate else "no-matching-rule",
        examined=examined,
        indeterminate=indeterminate,
    )


def _indeterminate_evidence(outcome: _RuleOutcome, family: IpFamily | None = None) -> str | None:
    """One bounded missing-evidence line naming every indeterminate rule of one family.

    The structured candidates are already in ``matched``; this line explains why the verdict
    is not verifiable. It is bounded to ``MAX_TEXT`` because it can become the verdict reason,
    so a large rule base cannot produce an over-long string.
    """
    if not outcome.indeterminate:
        return None
    scope = f"the {family} rule base has " if family is not None else ""
    header = (
        f"{scope}{len(outcome.indeterminate)} rule(s) match every resolvable criterion but "
        "carry a criterion this analysis cannot resolve, so the verdict is not verifiable: "
    )
    described: list[str] = []
    for index, item in enumerate(outcome.indeterminate):
        piece = (
            f"'{item.rule.name}' at position {item.position} "
            f"({', '.join(item.unresolved_fields)})"
        )
        remainder = len(outcome.indeterminate) - index - 1
        tail = f" and {remainder} more" if remainder > 0 else ""
        if len(header) + len(", ".join([*described, piece])) + len(tail) > MAX_TEXT:
            break
        described.append(piece)
    remainder = len(outcome.indeterminate) - len(described)
    more = f" and {remainder} more" if remainder > 0 else ""
    return f"{header}{', '.join(described)}{more}"


def _evaluate_nat(
    nat_by_family: dict[IpFamily, list[NatRuleOutput]],
    families: tuple[IpFamily, ...],
    request: ExplainConnectivityInput,
    source: _ResolvedEndpoint,
    destination: _ResolvedEndpoint,
    rule_names: set[str],
    rules_truncated: bool,
    both_families_scanned: bool,
) -> list[NatEvaluation]:
    """Report the NAT rules that definitely match the flow, with their rule linkage."""
    evaluations: list[NatEvaluation] = []
    for family in families:
        for position, nat_rule in enumerate(nat_by_family.get(family, []), start=1):
            if not nat_rule.enabled:
                continue
            matched_fields: list[str] = []
            unresolved = False
            criteria = (
                (
                    "inboundInterfaces",
                    _nat_interfaces_match(nat_rule.inbound_interfaces, source.interfaces),
                ),
                (
                    "outboundInterfaces",
                    _nat_interfaces_match(nat_rule.outbound_interfaces, destination.interfaces),
                ),
                (
                    "originalSourceNetworks",
                    _nat_networks_match(nat_rule.original_source_networks),
                ),
                (
                    "originalDestinationNetworks",
                    _nat_networks_match(nat_rule.original_destination_networks),
                ),
                (
                    "originalServicesOrGroups",
                    _nat_services_match(nat_rule.original_services_or_groups, request.service),
                ),
            )
            if any(value is False for _, value in criteria):
                # A criterion that definitively does not match excludes the NAT rule, exactly
                # like a zone mismatch: it must not be reported as matching the flow.
                continue
            for name, value in criteria:
                if value is True:
                    matched_fields.append(name)
                elif value is None:
                    unresolved = True
            if unresolved or not matched_fields:
                continue
            linked = nat_rule.linked_firewall_rule
            evaluations.append(
                NatEvaluation(
                    name=nat_rule.name,
                    id=nat_rule.id,
                    position=position,
                    ip_family=family,
                    enabled=nat_rule.enabled,
                    matched_fields=matched_fields,
                    linked_firewall_rule=linked,
                    linked_rule_exists=(
                        None
                        if linked is None or rules_truncated
                        else (
                            linked in rule_names
                            if both_families_scanned
                            else (True if linked in rule_names else None)
                        )
                    ),
                    translated_source=_translation_label(nat_rule.translated_source),
                    translated_destination=_translation_label(nat_rule.translated_destination),
                    note=(
                        "only NAT rules whose criteria all match definitely are reported; "
                        "object-based criteria are not resolved"
                    ),
                )
            )
            if len(evaluations) >= MAX_RULES_REPORTED:
                return evaluations
    return evaluations


def _translation_label(translation: NatRuleTranslationOutput | None) -> str | None:
    """Render a projected translation as one bounded label."""
    if translation is None:
        return None
    if translation.masq:
        return "masquerade"
    for value in (
        translation.ipv4_address,
        translation.fqdn_address,
        translation.ipv6_address,
    ):
        if value is not None:
            return value
    return None


def _explain_output(
    *,
    families: tuple[IpFamily, ...],
    source: _ResolvedEndpoint,
    destination: _ResolvedEndpoint,
    service: ServiceSummary,
    zones: list[Zone],
    interfaces: list[NetworkInterface],
    routing: RoutingDecision,
    verdict: str,
    verdict_reason: str,
    matched: list[RuleEvaluation],
    decisive: RuleEvaluation | None,
    nat: list[NatEvaluation],
    missing: list[str],
    notes: list[str],
    rules_examined: int,
    truncated: bool,
    budget: _Budget,
) -> ExplainConnectivityOutput:
    """Assemble the bounded explanation from the resolved pieces."""
    canonical_zones = {zone.name.casefold(): zone for zone in zones if zone.name is not None}
    zone_roles: dict[str, set[str]] = {}
    for role, endpoint in (("source", source), ("destination", destination)):
        for name in endpoint.zones:
            zone_roles.setdefault(name, set()).add(role)
    if routing.interface is not None:
        route_zone = _zone_of_interface(interfaces, routing.interface)
        if route_zone is not None:
            zone_roles.setdefault(route_zone.casefold(), set()).add("route")
    zone_models = [
        ZoneMatch(
            name=_canonical_zone_name(canonical_zones, name),
            type=canonical_zones[name].type if name in canonical_zones else None,
            roles=sorted(zone_roles[name]),  # type: ignore[arg-type]
        )
        for name in zone_roles
    ]

    interface_models: list[InterfaceMatch] = []
    seen: set[tuple[str, str, str]] = set()
    for role, endpoint in (("source", source), ("destination", destination)):
        for name, zone, address in endpoint.interface_hits:
            key = (name, role, address)
            if key in seen:
                continue
            seen.add(key)
            interface_models.append(
                InterfaceMatch(
                    name=name,
                    zone=zone,
                    ip_family="ipv4" if ":" not in address else "ipv6",
                    address=address,
                    role=role,  # type: ignore[arg-type]
                )
            )
    if routing.interface is not None:
        route_zone = _zone_of_interface(interfaces, routing.interface)
        key = (routing.interface, "route", routing.interface)
        if key not in seen:
            seen.add(key)
            interface_models.append(
                InterfaceMatch(
                    name=routing.interface,
                    zone=route_zone,
                    ip_family=destination.family or "ipv4",
                    address=None,
                    role="route",
                )
            )

    reported_rules = matched[:MAX_RULES_REPORTED]
    if len(matched) > MAX_RULES_REPORTED:
        # Every indeterminate rule is collected now, so the reported list can exceed the
        # output bound; say so instead of dropping the remainder silently.
        truncated = True
        notes.append(
            f"only the first {MAX_RULES_REPORTED} matching rules are reported; "
            f"{len(matched) - MAX_RULES_REPORTED} more matched the criteria"
        )

    return ExplainConnectivityOutput(
        verdict=verdict,  # type: ignore[arg-type]
        verdict_reason=verdict_reason,
        source=_endpoint_summary(source, canonical_zones),
        destination=_endpoint_summary(destination, canonical_zones),
        service=service,
        ip_families=list(families) if families else ["ipv4"],
        zones=zone_models,
        interfaces=interface_models,
        firewall_rules=reported_rules,
        decisive_rule=decisive,
        nat_rules=nat,
        routing=routing,
        missing_evidence=missing[:20],
        rules_examined=rules_examined,
        truncated=truncated,
        scan=budget.report(),
        notes=notes,
    )


def _endpoint_summary(
    endpoint: _ResolvedEndpoint, canonical_zones: dict[str, Zone]
) -> EndpointSummary:
    """Project one resolved endpoint into its bounded summary."""
    return EndpointSummary(
        ip=endpoint.ip,
        zone=endpoint.zone,
        fqdn=endpoint.fqdn,
        resolved_zones=[
            _canonical_zone_name(canonical_zones, name) for name in sorted(endpoint.zones)
        ],
        interfaces=list(endpoint.interfaces),
        local=endpoint.local,
    )


# -- find_object_usage helpers ---------------------------------------------------------


def _collect_references(
    target: str,
    rules: dict[IpFamily, list[RuleOutput]],
    nat: dict[IpFamily, list[NatRuleOutput]],
    groups: list[_GroupEntry],
    limit: int,
) -> tuple[list[ObjectReference], int]:
    """Collect every reference to *target*, bounded by *limit*, and count them all."""
    references: list[ObjectReference] = []
    total = 0

    def add(reference: ObjectReference) -> None:
        nonlocal total
        total += 1
        if len(references) < limit:
            references.append(reference)

    for family in ("ipv4", "ipv6"):
        for position, rule in enumerate(rules[family], start=1):
            for side, match in (
                ("sourceNetworks", rule.sourceNetworks),
                ("destinationNetworks", rule.destinationNetworks),
            ):
                if match is None:
                    continue
                for field_name in _NETWORK_FIELDS:
                    if target in _ref_names(match, field_name):
                        add(
                            ObjectReference(
                                kind="firewall-rule",
                                name=rule.name,
                                id=rule.id,
                                ip_family=family,
                                position=position,
                                enabled=rule.enabled,
                                field=f"{side}.{field_name}",
                                detail=f"referenced by firewall rule '{rule.name}'",
                            )
                        )
            if rule.servicesOrGroups is not None:
                for field_name in ("services", "serviceGroups"):
                    if target in _ref_names(rule.servicesOrGroups, field_name):
                        add(
                            ObjectReference(
                                kind="firewall-rule",
                                name=rule.name,
                                id=rule.id,
                                ip_family=family,
                                position=position,
                                enabled=rule.enabled,
                                field=f"servicesOrGroups.{field_name}",
                                detail=f"referenced by firewall rule '{rule.name}'",
                            )
                        )
        for position, nat_rule in enumerate(nat[family], start=1):
            for side, nat_match in (
                ("originalSourceNetworks", nat_rule.original_source_networks),
                ("originalDestinationNetworks", nat_rule.original_destination_networks),
            ):
                if nat_match is None:
                    continue
                for field_name in _NAT_NETWORK_FIELDS:
                    if target in _string_names(getattr(nat_match, field_name, None)):
                        add(
                            ObjectReference(
                                kind="nat-rule",
                                name=nat_rule.name,
                                id=nat_rule.id,
                                ip_family=family,
                                position=position,
                                enabled=nat_rule.enabled,
                                field=f"{side}.{field_name}",
                                detail=f"referenced by NAT rule '{nat_rule.name}'",
                            )
                        )
            if nat_rule.original_services_or_groups is not None:
                for field_name in ("services", "service_groups"):
                    if target in set(getattr(nat_rule.original_services_or_groups, field_name, [])):
                        add(
                            ObjectReference(
                                kind="nat-rule",
                                name=nat_rule.name,
                                id=nat_rule.id,
                                ip_family=family,
                                position=position,
                                enabled=nat_rule.enabled,
                                field=f"originalServicesOrGroups.{field_name}",
                                detail=f"referenced by NAT rule '{nat_rule.name}'",
                            )
                        )
            if nat_rule.translated_service == target:
                add(
                    ObjectReference(
                        kind="nat-rule",
                        name=nat_rule.name,
                        id=nat_rule.id,
                        ip_family=family,
                        position=position,
                        enabled=nat_rule.enabled,
                        field="translatedService",
                        detail=f"referenced by NAT rule '{nat_rule.name}'",
                    )
                )
            for side, translation in (
                ("translatedSource", nat_rule.translated_source),
                ("translatedDestination", nat_rule.translated_destination),
            ):
                if target in _translation_names(translation):
                    add(
                        ObjectReference(
                            kind="nat-rule",
                            name=nat_rule.name,
                            id=nat_rule.id,
                            ip_family=family,
                            position=position,
                            enabled=nat_rule.enabled,
                            field=side,
                            detail=f"referenced by NAT rule '{nat_rule.name}'",
                        )
                    )
            for override in nat_rule.override_snat_for_outbound_interfaces:
                if target in _translation_names(override.translated_source):
                    add(
                        ObjectReference(
                            kind="nat-rule",
                            name=nat_rule.name,
                            id=nat_rule.id,
                            ip_family=family,
                            position=position,
                            enabled=nat_rule.enabled,
                            field="overrideSnatForOutboundInterfaces.translatedSource",
                            detail=f"referenced by NAT rule '{nat_rule.name}'",
                        )
                    )
    for group in groups:
        if target in group.members:
            add(
                ObjectReference(
                    kind="group",
                    name=group.name,
                    id=group.id,
                    ip_family=group.family if group.family in ("ipv4", "ipv6") else None,
                    field="members",
                    detail=f"member of {group.kind} '{group.name}'",
                )
            )
    return references, total


# -- Registration ----------------------------------------------------------------------


def register_audit_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the three composite, read-only audit tools on *server*.

    The tools are ``ToolKind.READ`` and carry no write hints, so they are registered in
    read-only mode as well. They add no Sophos operation: every read goes through the
    domain adapter that owns it.
    """

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="audit_firewall_rules",
        title="Audit firewall rules",
        description=(
            "Run seven evidence-based, read-only checks over the firewall rule base and return "
            "bounded findings. Checks: any-any (enabled accept rule with any source and "
            "destination, or any service); disabled (present but disabled); shadowed (a later "
            "rule an earlier enabled rule fully covers, including exact duplicates); no-logging "
            "(enabled accept/drop rule without traffic logging); unused-object (address or "
            "service object referenced by no rule, NAT rule or group); nat-without-rule (NAT "
            "rule with a missing linkedFirewallRule or a link to a rule that does not exist); "
            "unrestricted-service (enabled accept rule from a non-WAN zone to WAN with any "
            "service). Inputs: optional ip_family, optional rule-name filter (it selects which "
            "rule-scoped findings are reported; the rule base is still read in full so "
            "shadowing follows real evaluation order) and optional checks. Returns at most 100 "
            "findings, each with rule name/id, evaluation position, severity and evidence. "
            "findings_truncated and scan.truncated are true only when a limit was actually hit. "
            "When the projection cannot support a claim the check is listed in not_verifiable "
            "instead of guessed. Shadowing compares projected criteria only: user-authentication "
            "and exclusion members are not projected, so treat a shadowing finding as a "
            "candidate for review. Reads the audited list operations through the domain "
            "adapters; adds no endpoint and never mutates."
        ),
    )
    async def audit_firewall_rules(
        request: AuditFirewallRulesInput, ctx: Context[AppContext]
    ) -> AuditFirewallRulesOutput:
        return await AuditAdapter.from_context(ctx).audit_firewall_rules(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="explain_connectivity",
        title="Explain connectivity",
        description=(
            "Explain, from configuration, which interface and zone, firewall rule and NAT rule "
            "apply to a flow, and why it is allowed or denied. Inputs: source and destination "
            "(an IP address, a zone name or an FQDN), a service name or protocol/port, optional "
            "ip_family and max_rules_examined. Output: an ordered explanation with the resolved "
            "interfaces and zones, matching firewall rules in evaluation order with the first "
            "decisive rule, matching NAT rules with their linkedFirewallRule, the routing "
            "decision (local, static route, default route or no route) and a verdict of allowed, "
            "denied, no-matching-rule or not-verifiable. method is always config-analysis: this "
            "is NOT a packet test, and the REST contract exposes no ping, traceroute, packet "
            "capture or live flow simulation. An IP is resolved to the local interface and zone "
            "that contain it; a non-local destination is routed over the configured static "
            "unicast routes and gateways (no live routing table exists). Rules whose network or "
            "service criteria reference objects are reported as not verifiable because "
            "address- and service-object membership is not resolved here; an FQDN endpoint "
            "cannot be resolved without DNS. Truncation is explicit. Read-only."
        ),
    )
    async def explain_connectivity(
        request: ExplainConnectivityInput, ctx: Context[AppContext]
    ) -> ExplainConnectivityOutput:
        return await AuditAdapter.from_context(ctx).explain_connectivity(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="find_object_usage",
        title="Find object usage",
        description=(
            "Find every reference to an address, address group, service or service group, "
            "read-only. The REST contract has no usage endpoint, so the tool scans the audited "
            "list operations and reports every firewall rule (with evaluation position, IP "
            "family and enabled state), NAT rule and group that references the object. Inputs: "
            "object_type (address, address-group, service, service-group), identifier (name or "
            "UUID; a UUID is resolved to its name from the list), optional ip_family to narrow "
            "address lookups, and max_references. Returns at most 100 references, whether the "
            "object itself was found, the total reference count and explicit truncation flags. "
            "A group membership counts as a reference. Never mutates and adds no endpoint."
        ),
    )
    async def find_object_usage(
        request: FindObjectUsageInput, ctx: Context[AppContext]
    ) -> FindObjectUsageOutput:
        return await AuditAdapter.from_context(ctx).find_object_usage(request)
