"""Pydantic models for the audit, connectivity-explanation and usage tools (#35).

These models describe three **composite, read-only** tools. They add no Sophos operation:
the tools call the audited list/get operations through the domain adapters of issues
#27-#31 and reason over the projected results. The models therefore describe what the
analysis is allowed to claim, not a wire payload.

Design rules encoded here:

* **Closed inputs, bounded outputs.** Every request model is ``extra="forbid"``; every
  output model is an explicit projection with bounded lists (findings, references,
  evidence fields, missing-evidence entries). No raw Sophos payload is ever returned.
* **Evidence or silence.** A finding carries the rule name/id, the 1-based evaluation
  position, the IP family, the projected fields that support it and a short detail. When
  the projection cannot support a claim the tool reports ``not_verifiable`` instead of
  guessing; :class:`UnverifiableCheck` is that channel.
* **Explicit truncation.** :class:`ScanReport` says which collections were read, how many
  items and pages were scanned, which collections were cut short and what the per-collection
  limit was. The top-level ``truncated`` flags are only true when a limit was actually hit.
* **Configuration analysis only.** :class:`ExplainConnectivityOutput` carries
  ``method="config-analysis"``: the REST contract exposes no ping, traceroute, packet
  capture or live flow simulation, so the tool explains configuration, not observed packets.

Field names are snake_case because these are MCP-facing models; the appliance's camelCase
wire names stay inside the domain models of the owning domains.
"""

from __future__ import annotations

import ipaddress
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sophos_firewall_mcp.models.common import ObjectNameOrId

__all__ = [
    "ALL_CHECKS",
    "MAX_EVIDENCE_FIELDS",
    "MAX_FINDINGS",
    "MAX_REFERENCES",
    "MAX_RULES_REPORTED",
    "MAX_TEXT",
    "AddressFamily",
    "AuditCheck",
    "AuditFinding",
    "AuditFirewallRulesInput",
    "AuditFirewallRulesOutput",
    "ConnectivityEndpoint",
    "ConnectivityService",
    "EndpointSummary",
    "ExplainConnectivityInput",
    "ExplainConnectivityOutput",
    "FindingEvidence",
    "FindObjectUsageInput",
    "FindObjectUsageOutput",
    "InterfaceMatch",
    "IpFamily",
    "NatEvaluation",
    "ObjectReference",
    "ObjectType",
    "RoutingDecision",
    "RuleEvaluation",
    "ScanReport",
    "ServiceSummary",
    "Severity",
    "UnverifiableCheck",
    "Verdict",
    "ZoneMatch",
]

#: The maximum number of findings one ``audit_firewall_rules`` call returns (issue #35).
MAX_FINDINGS = 100

#: The maximum number of object references one ``find_object_usage`` call returns.
MAX_REFERENCES = 100

#: The maximum number of matching firewall rules ``explain_connectivity`` reports.
MAX_RULES_REPORTED = 50

#: The maximum number of projected fields one finding cites as evidence.
MAX_EVIDENCE_FIELDS = 8

#: Upper bound for every free-text field, in characters.
MAX_TEXT = 400

#: The IP family a rule or NAT rule belongs to.
IpFamily = Literal["ipv4", "ipv6"]

#: The address family of an address object (FQDN objects have no IP family).
AddressFamily = Literal["ipv4", "ipv6", "fqdn"]

#: The audit checks issue #35 requires. The order is the canonical output order.
AuditCheck = Literal[
    "any-any",
    "disabled",
    "shadowed",
    "no-logging",
    "unused-object",
    "nat-without-rule",
    "unrestricted-service",
]

#: Every audit check in canonical order.
ALL_CHECKS: tuple[AuditCheck, ...] = (
    "any-any",
    "disabled",
    "shadowed",
    "no-logging",
    "unused-object",
    "nat-without-rule",
    "unrestricted-service",
)

#: Finding severity. ``high`` is a directly exploitable exposure, ``medium`` a policy or
#: linkage defect, ``low`` a hygiene issue and ``info`` an observation.
Severity = Literal["high", "medium", "low", "info"]

#: The object types ``find_object_usage`` understands.
ObjectType = Literal["address", "address-group", "service", "service-group"]

#: The connectivity verdicts issue #35 requires.
Verdict = Literal["allowed", "denied", "no-matching-rule", "not-verifiable"]

#: Where a reference to an object was found.
ReferenceKind = Literal["firewall-rule", "nat-rule", "group"]

#: The three roles an interface or zone can play in an explanation.
ZoneRole = Literal["source", "destination", "route"]


class _Input(BaseModel):
    """Base for the closed request models: the MCP contract is closed."""

    model_config = ConfigDict(extra="forbid")


class _Output(BaseModel):
    """Base for the bounded output projections: unknown members are ignored."""

    model_config = ConfigDict(extra="ignore")


# -- Shared output primitives ----------------------------------------------------------


class ScanReport(_Output):
    """What a bounded internal walk actually read.

    The audit tools never auto-paginate a tool call, but they do need a bounded internal
    walk to reason over a rule base. This report makes that walk visible: which collections
    were read, how many items and pages were consumed, which collections were cut short and
    what the per-collection limit was. ``truncated`` is true only when a limit was hit.
    """

    collections: list[str] = Field(
        default_factory=list,
        max_length=32,
        description="Collections the walk read, in the order they were first read.",
    )
    items_scanned: int = Field(default=0, ge=0, description="Items read across every collection.")
    pages_read: int = Field(default=0, ge=0, description="Pages requested across every collection.")
    item_limit_per_collection: int = Field(
        default=500, ge=1, description="Maximum items read from one collection."
    )
    truncated: bool = Field(
        default=False, description="True when at least one collection was cut short."
    )
    truncated_collections: list[str] = Field(
        default_factory=list,
        max_length=32,
        description="Collections that were cut short by the item or page limit.",
    )


class FindingEvidence(_Output):
    """The projected facts that support one finding.

    ``rule_name``/``rule_id``/``position``/``ip_family`` identify a rule-scoped finding;
    ``object_name``/``object_type`` identify an object- or NAT-scoped one. ``fields`` names
    the projected members the finding rests on and ``detail`` states the observation.
    """

    rule_name: str | None = Field(
        default=None, max_length=60, description="Rule name, when applicable."
    )
    rule_id: str | None = Field(
        default=None, max_length=64, description="Rule UUID, when returned."
    )
    position: int | None = Field(
        default=None, ge=1, description="1-based evaluation position in the family's rule base."
    )
    ip_family: IpFamily | None = Field(default=None, description="IP family of the rule or object.")
    object_name: str | None = Field(
        default=None, max_length=64, description="Object or NAT-rule name, when applicable."
    )
    object_type: str | None = Field(
        default=None, max_length=32, description="Object kind, for example 'address' or 'nat-rule'."
    )
    fields: list[str] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_FIELDS,
        description="Projected members the finding rests on.",
    )
    detail: str = Field(
        ..., min_length=1, max_length=MAX_TEXT, description="The observation, in one sentence."
    )


class AuditFinding(_Output):
    """One evidence-based audit finding."""

    check: AuditCheck = Field(..., description="The check that produced the finding.")
    severity: Severity = Field(..., description="Impact classification of the finding.")
    summary: str = Field(..., min_length=1, max_length=MAX_TEXT, description="One-line summary.")
    evidence: FindingEvidence = Field(..., description="Projected facts supporting the finding.")


class UnverifiableCheck(_Output):
    """A requested check the configuration could not support.

    The tool reports this instead of guessing: the reason names the missing evidence and
    ``subjects`` lists up to ten affected rules or objects.
    """

    check: AuditCheck = Field(..., description="The check that could not be completed.")
    reason: str = Field(..., min_length=1, max_length=MAX_TEXT, description="Why it is unknown.")
    subjects: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Up to ten rules or objects the missing evidence concerns.",
    )
    subject_count: int = Field(
        default=0, ge=0, description="How many subjects the missing evidence affects."
    )


# -- audit_firewall_rules --------------------------------------------------------------


class AuditFirewallRulesInput(_Input):
    """Input of ``audit_firewall_rules``.

    ``checks`` defaults to all seven checks. ``rule_name_contains`` selects which
    rule-scoped findings are reported; the rule base is still read in full so shadowing is
    evaluated in real evaluation order. ``max_findings`` is capped at 100 (issue #35).
    """

    ip_family: IpFamily | None = Field(
        default=None, description="Audit only this IP family; omit to audit IPv4 and IPv6."
    )
    rule_name_contains: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Report rule-scoped findings only for rules whose name contains this text.",
    )
    checks: list[AuditCheck] | None = Field(
        default=None,
        min_length=1,
        description="Checks to run; omit for all seven. Duplicate checks are rejected.",
    )
    max_findings: int = Field(
        default=MAX_FINDINGS,
        ge=1,
        le=MAX_FINDINGS,
        description="Maximum findings to return (1-100).",
    )

    @field_validator("checks")
    @classmethod
    def _unique_checks(cls, value: list[AuditCheck] | None) -> list[AuditCheck] | None:
        if value is None:
            return None
        if len(set(value)) != len(value):
            raise ValueError("checks must not contain duplicates")
        return value


class AuditFirewallRulesOutput(_Output):
    """Output of ``audit_firewall_rules``: bounded findings plus the scan it was based on."""

    findings: list[AuditFinding] = Field(
        default_factory=list,
        max_length=MAX_FINDINGS,
        description=(
            "Findings sorted by severity (high first), then canonical check order, bounded by "
            "max_findings."
        ),
    )
    findings_truncated: bool = Field(
        default=False, description="True only when more findings existed than were returned."
    )
    checks_run: list[AuditCheck] = Field(
        default_factory=list,
        max_length=len(ALL_CHECKS),
        description="The checks that were run, in canonical order.",
    )
    not_verifiable: list[UnverifiableCheck] = Field(
        default_factory=list,
        max_length=20,
        description="Checks the configuration could not support, with the missing evidence.",
    )
    rules_examined: int = Field(default=0, ge=0, description="Firewall rules read and evaluated.")
    nat_rules_examined: int = Field(
        default=0, ge=0, description="NAT rules read for the linkage checks."
    )
    scan: ScanReport = Field(..., description="The bounded scan the findings are based on.")
    notes: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Documented limitations that apply to this result.",
    )


# -- explain_connectivity --------------------------------------------------------------


class ConnectivityEndpoint(_Input):
    """One side of a flow: an IP address, a zone name or an FQDN.

    Exactly one member must be set. An IP is resolved to the local interface and zone that
    contain it; a zone is matched by name; an FQDN cannot be resolved without DNS, so it is
    reported as not verifiable instead of guessed.
    """

    ip: str | None = Field(default=None, description="IPv4 or IPv6 address of the endpoint.")
    zone: str | None = Field(default=None, min_length=1, max_length=60, description="Zone name.")
    fqdn: str | None = Field(
        default=None, min_length=1, max_length=253, description="FQDN to explain."
    )

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4 or IPv6 address") from exc
        return value

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        provided = [
            name
            for name, value in (("ip", self.ip), ("zone", self.zone), ("fqdn", self.fqdn))
            if value is not None
        ]
        if len(provided) != 1:
            raise ValueError("exactly one of ip, zone or fqdn must be provided")
        return self


class ConnectivityService(_Input):
    """The service side of a flow: a service object name, a protocol/port, or both.

    A service name can be matched against the services a rule references. A bare
    protocol/port cannot: the tool does not resolve service-object definitions, so a rule
    that references service objects is reported as not verifiable for that criterion.
    """

    name: str | None = Field(default=None, min_length=1, max_length=50, description="Service name.")
    protocol: Literal["tcp", "udp", "icmp", "icmpv6", "ip"] | None = Field(
        default=None, description="Protocol of the flow."
    )
    port: int | None = Field(
        default=None, ge=1, le=65535, description="Destination port (TCP/UDP only)."
    )

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.name is None and self.protocol is None:
            raise ValueError("provide a service name or a protocol")
        if self.port is not None and self.protocol not in ("tcp", "udp"):
            raise ValueError("port requires protocol 'tcp' or 'udp'")
        return self


class ExplainConnectivityInput(_Input):
    """Input of ``explain_connectivity``: a flow described by endpoints and a service."""

    source: ConnectivityEndpoint = Field(..., description="Where the flow comes from.")
    destination: ConnectivityEndpoint = Field(..., description="Where the flow goes to.")
    service: ConnectivityService = Field(..., description="Service, protocol and/or port.")
    ip_family: IpFamily | None = Field(
        default=None,
        description="IP family to analyse; inferred from the IP endpoints when omitted.",
    )
    max_rules_examined: int = Field(
        default=200,
        ge=1,
        le=500,
        description="Maximum firewall rules evaluated per IP family before reporting truncation.",
    )


class EndpointSummary(_Output):
    """How one endpoint was resolved before the rules were evaluated."""

    ip: str | None = Field(default=None, description="IP address, when the endpoint was an IP.")
    zone: str | None = Field(default=None, description="Zone name, when the endpoint was a zone.")
    fqdn: str | None = Field(default=None, description="FQDN, when the endpoint was an FQDN.")
    resolved_zones: list[str] = Field(
        default_factory=list, max_length=16, description="Zones the endpoint resolves to."
    )
    interfaces: list[str] = Field(
        default_factory=list, max_length=16, description="Local interfaces that contain the IP."
    )
    local: bool | None = Field(
        default=None,
        description="True when the IP belongs to a local interface; None when unknown.",
    )


class ServiceSummary(_Output):
    """The service side of the flow, echoed from the request."""

    name: str | None = Field(default=None, max_length=50)
    protocol: str | None = Field(default=None, max_length=16)
    port: int | None = Field(default=None, ge=1, le=65535)


class ZoneMatch(_Output):
    """One zone involved in the explanation, with its configured type."""

    name: str = Field(..., max_length=60)
    type: str | None = Field(
        default=None, max_length=16, description="Configured zone type, when known."
    )
    roles: list[ZoneRole] = Field(
        default_factory=list, max_length=3, description="Roles the zone plays in this flow."
    )


class InterfaceMatch(_Output):
    """One local interface involved in the explanation."""

    name: str = Field(..., max_length=58)
    zone: str | None = Field(default=None, max_length=60)
    ip_family: IpFamily
    address: str | None = Field(
        default=None, max_length=64, description="Interface address that matched."
    )
    role: ZoneRole = Field(..., description="Why the interface is part of the explanation.")


class RuleEvaluation(_Output):
    """One firewall rule the scan examined, in evaluation order.

    ``matched_fields`` names the criteria that matched. ``unresolved_fields`` names the
    criteria whose object membership the analysis could not resolve; such a rule is a
    candidate, not a decision. ``decisive`` marks the first enabled matching rule: its action
    decides the verdict. ``applied`` is false for a disabled rule that matches the criteria
    but is not evaluated by the appliance.
    """

    name: str = Field(..., max_length=60)
    id: str | None = Field(default=None, max_length=64)
    position: int = Field(..., ge=1, description="1-based evaluation position.")
    ip_family: IpFamily
    enabled: bool | None = Field(default=None, description="Projected enabled state.")
    action: str | None = Field(default=None, max_length=16, description="accept, drop or reject.")
    decisive: bool = Field(default=False, description="True for the first enabled matching rule.")
    applied: bool = Field(default=False, description="True when the rule is enabled and decisive.")
    matched_fields: list[str] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_FIELDS,
        description="Rule criteria that matched the flow.",
    )
    unresolved_fields: list[str] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_FIELDS,
        description="Criteria whose object membership could not be resolved.",
    )
    log_traffic: bool | None = Field(default=None, description="Projected logging flag.")
    note: str | None = Field(
        default=None, max_length=MAX_TEXT, description="Why the rule did not apply."
    )


class NatEvaluation(_Output):
    """One NAT rule that matched the flow, with its firewall-rule linkage."""

    name: str = Field(..., max_length=60)
    id: str | None = Field(default=None, max_length=64)
    position: int = Field(..., ge=1, description="1-based position in the NAT rule base.")
    ip_family: IpFamily
    enabled: bool = Field(..., description="Projected enabled state.")
    matched_fields: list[str] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_FIELDS,
        description="NAT criteria that matched the flow.",
    )
    linked_firewall_rule: str | None = Field(
        default=None, max_length=60, description="Name of the linked firewall rule, when returned."
    )
    linked_rule_exists: bool | None = Field(
        default=None,
        description="True when the linked firewall rule exists in the scanned rule base.",
    )
    translated_source: str | None = Field(default=None, max_length=64)
    translated_destination: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=MAX_TEXT)


class RoutingDecision(_Output):
    """The routing decision for a destination that is not local.

    This is configuration analysis over the static unicast routes and gateways: the
    contract exposes no live routing table, so dynamic routing is not evaluated.
    """

    decision: Literal["local", "static-route", "default-route", "no-route", "not-verified"] = Field(
        ..., description="How the destination is reached, or why that is unknown."
    )
    destination: str | None = Field(
        default=None, max_length=64, description="Destination that was routed."
    )
    route_name: str | None = Field(
        default=None, max_length=64, description="Matched static route name."
    )
    gateway: str | None = Field(
        default=None, max_length=50, description="Matched gateway name, if known."
    )
    gateway_ip: str | None = Field(
        default=None, max_length=64, description="Matched gateway address."
    )
    interface: str | None = Field(
        default=None, max_length=58, description="Matched egress interface."
    )
    truncated: bool = Field(
        default=False,
        description=(
            "True when the gateway or static-route scan was truncated, so a route that would "
            "change this decision may exist beyond the scanned portion."
        ),
    )
    note: str | None = Field(default=None, max_length=MAX_TEXT)


class ExplainConnectivityOutput(_Output):
    """Output of ``explain_connectivity``: an ordered, evidence-based explanation.

    ``method`` is always ``config-analysis``: this is not a packet test. ``verdict`` is the
    policy verdict, ``verdict_reason`` says exactly which rule, routing decision or missing
    evidence produced it, and ``missing_evidence`` lists every fact the analysis lacked.
    """

    method: Literal["config-analysis"] = Field(
        default="config-analysis",
        description="This is configuration analysis, not a packet test.",
    )
    verdict: Verdict = Field(..., description="Policy verdict for the described flow.")
    verdict_reason: str = Field(
        ..., min_length=1, max_length=MAX_TEXT, description="What produced the verdict."
    )
    source: EndpointSummary = Field(..., description="Resolved source endpoint.")
    destination: EndpointSummary = Field(..., description="Resolved destination endpoint.")
    service: ServiceSummary = Field(..., description="Service side of the flow.")
    ip_families: list[IpFamily] = Field(
        ..., min_length=1, max_length=2, description="IP families that were analysed."
    )
    zones: list[ZoneMatch] = Field(
        default_factory=list, max_length=32, description="Zones involved in the flow."
    )
    interfaces: list[InterfaceMatch] = Field(
        default_factory=list, max_length=32, description="Local interfaces involved in the flow."
    )
    firewall_rules: list[RuleEvaluation] = Field(
        default_factory=list,
        max_length=MAX_RULES_REPORTED,
        description="Matching firewall rules in evaluation order, including the decisive one.",
    )
    decisive_rule: RuleEvaluation | None = Field(
        default=None, description="The first enabled matching rule; its action decides the verdict."
    )
    nat_rules: list[NatEvaluation] = Field(
        default_factory=list,
        max_length=MAX_RULES_REPORTED,
        description="NAT rules that definitely match the flow.",
    )
    routing: RoutingDecision = Field(..., description="Routing decision for the destination.")
    missing_evidence: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="Facts the configuration did not provide; each one blocks a claim.",
    )
    rules_examined: int = Field(default=0, ge=0, description="Firewall rules evaluated.")
    truncated: bool = Field(
        default=False, description="True only when a scan or evaluation limit affected the result."
    )
    scan: ScanReport = Field(..., description="The bounded scan the explanation is based on.")
    notes: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Documented limitations that apply to this result.",
    )


# -- find_object_usage -----------------------------------------------------------------


class FindObjectUsageInput(_Input):
    """Input of ``find_object_usage``: one object type and a name or UUID.

    The REST contract has no usage endpoint, so the tool derives references by scanning the
    relevant list operations. ``ip_family`` narrows address and address-group lookups;
    ``max_references`` bounds the returned references.
    """

    object_type: ObjectType = Field(..., description="Kind of object to look up.")
    identifier: ObjectNameOrId = Field(
        ..., description="Object name or UUID (a UUID is resolved to its name from the list)."
    )
    ip_family: AddressFamily | None = Field(
        default=None,
        description="Narrow address and address-group lookups to one family; omit for all.",
    )
    max_references: int = Field(
        default=MAX_REFERENCES,
        ge=1,
        le=MAX_REFERENCES,
        description="Maximum references to return (1-100).",
    )


class ObjectReference(_Output):
    """One place an object is referenced."""

    kind: ReferenceKind = Field(..., description="firewall rule, NAT rule or group.")
    name: str = Field(..., max_length=64, description="Name of the referencing object.")
    id: str | None = Field(
        default=None, max_length=64, description="UUID of the referencing object."
    )
    ip_family: IpFamily | None = Field(
        default=None, description="IP family of the referencing object."
    )
    position: int | None = Field(
        default=None, ge=1, description="1-based position in the referencing rule base."
    )
    enabled: bool | None = Field(default=None, description="Enabled state of the referencing rule.")
    field: str = Field(..., max_length=64, description="Projected member that holds the reference.")
    detail: str | None = Field(default=None, max_length=MAX_TEXT)


class FindObjectUsageOutput(_Output):
    """Output of ``find_object_usage``: every reference found, bounded and explicit.

    ``found`` says whether the object itself exists in the scanned collections.
    ``reference_count`` is the number of references found before ``max_references`` cut the
    list; ``truncated`` is true only when that cut or a scan limit actually happened.
    """

    object_type: ObjectType = Field(..., description="Kind of object that was searched for.")
    identifier: str = Field(..., max_length=64, description="Identifier the search was issued for.")
    resolved_name: str | None = Field(
        default=None, max_length=64, description="Canonical name of the object, when it was found."
    )
    resolved_id: str | None = Field(
        default=None, max_length=64, description="UUID of the object, if found."
    )
    found: bool = Field(..., description="True when the object exists in the scanned collections.")
    references: list[ObjectReference] = Field(
        default_factory=list,
        max_length=MAX_REFERENCES,
        description="References in firewall rules, NAT rules and groups.",
    )
    reference_count: int = Field(default=0, ge=0, description="References found before truncation.")
    truncated: bool = Field(
        default=False,
        description="True only when a reference or scan limit actually cut the result.",
    )
    scan: ScanReport = Field(..., description="The bounded scan the references are based on.")
    notes: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Documented limitations that apply to this result.",
    )
