"""MCP prompts: user-controlled templates for the server's three analysis workflows.

A prompt is a template a *user* selects, not an action a model chooses: the client renders
it into one user message and the model then calls the tools the message names. The three
prompts here are the workflows this server exists for -- audit the rule base, explain a
flow, find unused objects -- and each one is a self-contained instruction that names the
real tools, the exact ``request`` shape and the argument values, so a client that renders
it needs no other context.

The prompts are read-only by construction: they only name read-only tools, and the audit
and unused-object prompts say explicitly that nothing may be changed. They are registered
in both modes, because a read-only deployment is exactly where an audit is useful.

Nothing here touches the network or the tool registry: a prompt is a string built from its
arguments.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the mcp import out of this module
    from mcp.server.mcpserver import MCPServer

    from sophos_firewall_mcp.context import AppContext

__all__ = ["register_prompts"]

#: The seven audit checks, in the order the audit tool documents them.
AUDIT_CHECKS: tuple[str, ...] = (
    "any-any",
    "disabled",
    "shadowed",
    "no-logging",
    "unused-object",
    "nat-without-rule",
    "unrestricted-service",
)

#: Object types ``find_object_usage`` accepts.
OBJECT_TYPES: tuple[str, ...] = ("address", "address-group", "service", "service-group")

#: The IP families ``audit_firewall_rules`` accepts. FQDN objects have no IP family, so the
#: audit scan is left unfiltered for them: an FQDN object can be referenced by both rule
#: families, and the unused-object check must see both.
AUDIT_IP_FAMILIES: tuple[str, ...] = ("ipv4", "ipv6")


def _request(payload: dict[str, object]) -> str:
    """Render a tool call's ``arguments`` object as compact JSON.

    The wrapper is shown literally rather than described, because the single most common
    first-call failure is a flat argument object.
    """
    return json.dumps({"request": payload}, ensure_ascii=False)


def _audit_message(
    ip_family: str | None,
    checks: str | None,
    rule_name_contains: str | None,
) -> str:
    """The audit instruction, with the caller's filters folded into the tool call."""
    payload: dict[str, object] = {}
    if ip_family:
        payload["ip_family"] = ip_family
    if checks:
        payload["checks"] = [check.strip() for check in checks.split(",") if check.strip()]
    if rule_name_contains:
        payload["rule_name_contains"] = rule_name_contains
    payload["max_findings"] = 100

    scope = f"only {ip_family} rules" if ip_family else "IPv4 and IPv6 rules"
    filter_note = (
        f"\n   Only rules whose name contains {rule_name_contains!r} are reported; the whole rule base\n"
        "   is still read, so shadowing follows real evaluation order.\n"
        if rule_name_contains
        else ""
    )
    return f"""Audit this Sophos Firewall's rule base ({scope}) and report what needs attention.

1. Call `audit_firewall_rules` with:

   {_request(payload)}

   Omit `checks` to run all seven: any-any, disabled, shadowed, no-logging, unused-object,
   nat-without-rule, unrestricted-service.
{filter_note}
2. Group the findings by severity (`high`, `medium`, `low`, `info`) and by check. Each
   finding carries `check`, `severity`, `summary` and `evidence`; a rule-scoped finding
   names the rule, its evaluation position and its IP family, and an object- or
   NAT-scoped finding names the object instead.

3. Confirm every high-severity finding before you report it:
   - a rule finding: `firewall_rule_get` with `ip_family` set to the finding's family and
     {_request({"ip_family": "ipv4", "id_or_name": "<rule name>"})}
   - a NAT finding: `nat_rule_get` with the same shape (the same `ip_family` and
     `id_or_name`)
   - an unused-object finding: `find_object_usage` with
     {_request({"object_type": "address", "identifier": "<object name>"})}

4. Report the count per check, the highest-severity items with their evidence, and every
   check listed in `notVerifiable` (the projection could not support that claim). Say so
   when `findingsTruncated` or `scan.truncated` is true instead of implying the list is
   complete.

5. Change nothing. This is a read-only audit: no create, update, move, delete or
   enable/disable call. A `shadowed` finding is a candidate for review, not proof, because
   user-authentication and exclusion members are not compared."""


def _explain_message(
    source: str,
    destination: str,
    endpoint_type: str | None,
    service: str,
    protocol: str | None,
    port: int | None,
) -> str:
    """The flow-explanation instruction, with the caller's endpoints folded in."""
    kind = endpoint_type or "ip"
    if port is not None and protocol not in ("tcp", "udp"):
        raise ValueError("port requires protocol 'tcp' or 'udp'")
    service_payload: dict[str, object] = {"name": service}
    if protocol:
        service_payload["protocol"] = protocol
    if port is not None:
        service_payload["port"] = port
    payload: dict[str, object] = {
        "source": {kind: source},
        "destination": {kind: destination},
        "service": service_payload,
    }

    return f"""Explain, from configuration, why this flow is allowed or denied.

1. Call `explain_connectivity` with:

   {_request(payload)}

   An endpoint is exactly one of `ip`, `zone` or `fqdn`; both endpoints above are read as
   `{kind}`. The service is required: `name` is the service object name. `protocol`/`port` are
   recorded in the result summary but do not change the service match, which uses the name.

2. Read the result in order: the resolved source interface and zone, the resolved
   destination, the matching firewall rules in evaluation order with the first decisive
   rule, the matching NAT rules with their `linkedFirewallRule`, and the routing decision
   (local, static route, default route or no route).

3. State the verdict -- `allowed`, `denied`, `no-matching-rule` or `not-verifiable` -- and
   name the single rule that decided it. Quote the rule's name and evaluation position.

4. If the verdict is `not-verifiable`, say which criterion could not be resolved: an
   address- or service-object membership, or an FQDN without DNS. Confirm the surrounding
   configuration with `firewall_rule_list`
   ({_request({"ip_family": "ipv4", "page": 1, "page_size": 10})}), `zone_list` and
   `network_interface_list`.

5. This is configuration analysis, not a packet test. The API exposes no ping, traceroute,
   packet capture or live flow simulation, so never claim the appliance forwarded or
   dropped a packet. Change nothing."""


def _unused_message(object_type: str | None, ip_family: str | None) -> str:
    """The unused-object instruction, with the caller's filters folded in."""
    audit_payload: dict[str, object] = {"checks": ["unused-object"], "max_findings": 100}
    if ip_family in AUDIT_IP_FAMILIES:
        audit_payload["ip_family"] = ip_family
    usage_payload: dict[str, object] = {
        "object_type": object_type or "address",
        "identifier": "<object name>",
    }
    if ip_family:
        usage_payload["ip_family"] = ip_family

    scope = f"only {ip_family} objects" if ip_family else "IPv4, IPv6 and FQDN objects"
    type_note = (
        f"Only `{object_type}` objects are in scope."
        if object_type
        else f"`object_type` is one of {', '.join(OBJECT_TYPES)}."
    )
    family_note = (
        "\n   FQDN objects have no IP family, so the audit scans both rule families; the\n"
        "   usage lookup is narrowed to FQDN objects.\n"
        if ip_family == "fqdn"
        else ""
    )
    return f"""Find address and service objects that nothing references ({scope}).

1. Call `audit_firewall_rules` with:

   {_request(audit_payload)}

   The `unused-object` check reports an address or service object that no firewall rule,
   NAT rule or group references.
{family_note}
2. Confirm every candidate with `find_object_usage`:

   {_request(usage_payload)}

   {type_note}
   The result lists every firewall rule (with evaluation position, IP family and enabled
   state), NAT rule and group that references the object, plus whether the object itself
   was found and the total reference count.

3. Report only objects with zero references, grouped by type, with the object name and
   type. A group membership counts as a reference, so an object used only by a group is
   not unused. Say so when `max_references` truncates a result instead of implying the
   object is unused.

4. Delete nothing. This is a read-only report; removing an object is a separate, explicit
   decision for the operator, and a delete is refused while the object is still
   referenced."""


def register_prompts(server: MCPServer[AppContext]) -> None:
    """Register the server's prompts on ``server``.

    Args:
        server: The server being built. Registration happens before the lifespan starts,
            so the prompt list is fixed for the process lifetime.
    """

    @server.prompt(
        name="audit_firewall",
        title="Audit the firewall rule base",
        description=(
            "Run the seven read-only rule-base checks, triage the findings by severity and "
            "confirm the high-severity ones with the read tools."
        ),
    )
    def audit_firewall(
        ip_family: Annotated[
            str | None,
            Field(description="Audit only this IP family: 'ipv4' or 'ipv6'. Omit for both."),
        ] = None,
        checks: Annotated[
            str | None,
            Field(
                description=(
                    "Comma-separated subset of the seven checks: "
                    f"{', '.join(AUDIT_CHECKS)}. Omit for all seven."
                )
            ),
        ] = None,
        rule_name_contains: Annotated[
            str | None,
            Field(
                description="Report rule-scoped findings only for rules whose name contains this text."
            ),
        ] = None,
    ) -> str:
        """Audit the firewall rule base and report what needs attention."""
        return _audit_message(ip_family, checks, rule_name_contains)

    @server.prompt(
        name="explain_flow",
        title="Explain why a flow is allowed or denied",
        description=(
            "Resolve the interfaces, zones, firewall rule and NAT rule that apply to one "
            "flow, and state the verdict with the rule that decided it."
        ),
    )
    def explain_flow(
        source: Annotated[
            str,
            Field(description="Source IP address, zone name or FQDN."),
        ],
        destination: Annotated[
            str,
            Field(description="Destination IP address, zone name or FQDN."),
        ],
        service: Annotated[
            str,
            Field(
                min_length=1,
                description=(
                    "Service object name the flow is described by (required). "
                    "`explain_connectivity` needs a service."
                ),
            ),
        ],
        endpoint_type: Annotated[
            str | None,
            Field(
                description=(
                    "How to read source and destination: 'ip' (default), 'zone' or 'fqdn'."
                )
            ),
        ] = None,
        protocol: Annotated[
            str | None,
            Field(description="Protocol of the flow: tcp, udp, icmp, icmpv6 or ip."),
        ] = None,
        port: Annotated[
            int | None,
            Field(
                description=(
                    "Destination port (TCP or UDP only; requires `protocol` to be 'tcp' or 'udp')."
                )
            ),
        ] = None,
    ) -> str:
        """Explain, from configuration, why a flow is allowed or denied."""
        return _explain_message(source, destination, endpoint_type, service, protocol, port)

    @server.prompt(
        name="find_unused_objects",
        title="Find unused address and service objects",
        description=(
            "Find address and service objects that no rule, NAT rule or group references, "
            "and confirm each candidate with the usage lookup."
        ),
    )
    def find_unused_objects(
        object_type: Annotated[
            str | None,
            Field(
                description=(
                    "Restrict to one object type: address, address-group, service or "
                    "service-group. Omit for all four."
                )
            ),
        ] = None,
        ip_family: Annotated[
            str | None,
            Field(
                description=(
                    "Restrict address lookups to 'ipv4', 'ipv6' or 'fqdn'. Omit for all. "
                    "An FQDN object has no IP family, so the audit scans both rule families "
                    "and the usage lookup is narrowed to FQDN objects."
                )
            ),
        ] = None,
    ) -> str:
        """Find address and service objects that nothing references."""
        return _unused_message(object_type, ip_family)
