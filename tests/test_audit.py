"""Contract, behaviour, bound and discovery tests for the audit tools (#35).

Every HTTP interaction runs against RESPX: no firewall, no network and no real credential.
The tests prove, per check, that a finding is reported only when the projected evidence
supports it and that the negative case stays silent; they prove the shadowing order, the
NAT linkage, the object-usage scan, the four connectivity verdicts, the bounded output and
truncation flags, the closed input models and the published annotations.

The audit tools are composite: they add no Sophos operation. The tests therefore assert
that the calls go to the audited domain paths (through the domain adapters) and never to an
invented endpoint.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from mcp import Client
from pydantic import ValidationError

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.models.audit import (
    AuditFirewallRulesInput,
    ConnectivityEndpoint,
    ConnectivityService,
    ExplainConnectivityInput,
    FindObjectUsageInput,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.audit import register_audit_tools

HOST = "192.0.2.10"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
UUID_2 = "9c858901-8a57-4791-81fe-4c455b099bc9"

RULES_V4 = "/firewall/rules/ipv4"
RULES_V6 = "/firewall/rules/ipv6"
NAT_V4 = "/nat/rules/ipv4"
NAT_V6 = "/nat/rules/ipv6"
ADDR_V4 = "/network/addresses/ipv4"
ADDR_V6 = "/network/addresses/ipv6"
ADDR_FQDN = "/network/addresses/fqdn"
GROUP_V4 = "/network/address-groups/ipv4"
GROUP_V6 = "/network/address-groups/ipv6"
GROUP_FQDN = "/network/address-groups/fqdn"
SERVICES = "/network/services"
SERVICE_GROUPS = "/network/service-groups"
INTERFACES = "/network/interfaces/network-interfaces"
ZONES = "/network/zones"
GATEWAYS_V4 = "/routing/gateways/ipv4"
GATEWAYS_V6 = "/routing/gateways/ipv6"
ROUTES_V4 = "/routing/static-unicast-routes/ipv4"
ROUTES_V6 = "/routing/static-unicast-routes/ipv6"

AUDIT_TOOLS = {"audit_firewall_rules", "explain_connectivity", "find_object_usage"}


# -- Fixtures and helpers --------------------------------------------------------------


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "host": HOST,
        "port": 4444,
        "api_key": KEY,
        "verify_ssl": False,
        "timeout": 5.0,
        "read_only_mode": False,
    }
    values.update(overrides)
    return Settings(**values)


def make_server(*, read_only: bool = False):
    return create_server(make_settings(read_only_mode=read_only), domains=[register_audit_tools])


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


async def call_tool(name: str, arguments: dict[str, Any], *, read_only: bool = False) -> Any:
    """Call one audit tool through the official SDK client (full lifespan included)."""
    server = make_server(read_only=read_only)
    async with Client(server) as client:
        return await client.call_tool(name, {"request": arguments})


def page(items: list[dict[str, Any]], *, total: int | None = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {"current": 1, "size": 100, "maxSize": 100}
    if total is not None:
        metadata["total"] = total
    return {"items": items, "pages": metadata}


EMPTY_PAGE = page([])


def install(router: Any, responses: dict[str, Any]) -> None:
    """Serve every GET from a path-keyed map; unconfigured collections are empty pages."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        prefix = "/api/firewall-config/v1"
        if path.startswith(prefix):
            path = path[len(prefix) :]
        value = responses.get(path, EMPTY_PAGE)
        if callable(value):
            value = value(request)
        return httpx.Response(200, json=value)

    router.get(url__regex=r".*").mock(side_effect=handler)


def called_paths(router: Any) -> set[str]:
    prefix = "/api/firewall-config/v1"
    return {
        call.request.url.path[len(prefix) :]
        for call in router.calls
        if call.request.url.path.startswith(prefix)
    }


def firewall_rule(name: str = "rule", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": UUID,
        "name": name,
        "ruleType": "firewall",
        "enabled": True,
        "action": "accept",
        "sourceZones": {"any": True},
        "destinationZones": {"any": True},
        "sourceNetworks": {"any": True},
        "destinationNetworks": {"any": True},
        "servicesOrGroups": {"any": True},
        "logTraffic": True,
    }
    payload.update(overrides)
    return payload


def nat_rule(name: str = "nat", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": UUID,
        "name": name,
        "enabled": True,
        "originalServicesOrGroups": {"any": True},
        "inboundInterfaces": {"any": True},
        "outboundInterfaces": {"any": True},
        "originalSourceNetworks": {"any": True},
        "originalDestinationNetworks": {"any": True},
        "linkedFirewallRule": {"name": "allow-web"},
    }
    payload.update(overrides)
    return payload


def ipv4_address(name: str = "web-server", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": UUID,
        "name": name,
        "type": "ipv4Address",
        "ipv4Address": "10.0.0.5",
    }
    payload.update(overrides)
    return payload


def ipv4_group(
    name: str = "web-servers", members: tuple[str, ...] = ("web-server",)
) -> dict[str, Any]:
    return {
        "id": UUID_2,
        "name": name,
        "ipv4Addresses": [{"name": member} for member in members],
    }


def service(name: str = "HTTP") -> dict[str, Any]:
    return {
        "id": UUID,
        "name": name,
        "type": "tcpOrUdp",
        "services": [{"protocol": "tcp", "destinationPort": {"from": 80, "to": 80}}],
    }


def service_group(
    name: str = "web-services", members: tuple[str, ...] = ("HTTP",)
) -> dict[str, Any]:
    return {
        "id": UUID_2,
        "name": name,
        "services": [{"name": member} for member in members],
    }


def interface(
    name: str = "Port1",
    zone: str = "LAN",
    address: str = "10.0.0.1",
    cidr: int = 24,
) -> dict[str, Any]:
    return {
        "id": UUID,
        "name": name,
        "type": "physical",
        "zone": {"name": zone},
        "ipv4": {"assignmentType": "static", "ipv4Address": address, "cidr": cidr},
    }


def zone(name: str = "LAN", zone_type: str = "lan") -> dict[str, Any]:
    return {"id": UUID, "name": name, "type": zone_type}


def gateway(name: str = "wan-gateway", address: str = "203.0.113.1") -> dict[str, Any]:
    return {
        "id": UUID,
        "name": name,
        "type": "wan",
        "interface": {"name": "Port2"},
        "ipv4Address": address,
    }


def route(
    name: str = "default-route",
    destination: str = "0.0.0.0",
    cidr: int = 0,
    gateway_address: str = "203.0.113.1",
    interface_name: str = "Port2",
) -> dict[str, Any]:
    return {
        "id": UUID,
        "name": name,
        "destinationAddressIpv4": destination,
        "cidr": cidr,
        "gatewayIpv4": gateway_address,
        "interface": {"name": interface_name},
    }


# -- audit_firewall_rules: per-check positive and negative -----------------------------


async def test_any_any_reports_an_enabled_accept_all_rule(router: Any) -> None:
    install(router, {RULES_V4: page([firewall_rule(name="allow-all")])})

    result = await call_tool("audit_firewall_rules", {"checks": ["any-any"], "ip_family": "ipv4"})

    assert result.is_error is False
    output = result.structured_content
    assert output is not None
    assert len(output["findings"]) == 1
    finding = output["findings"][0]
    assert finding["check"] == "any-any"
    assert finding["severity"] == "high"
    assert finding["evidence"]["ruleName"] == "allow-all"
    assert finding["evidence"]["position"] == 1
    assert finding["evidence"]["ipFamily"] == "ipv4"
    assert finding["evidence"]["fields"] == [
        "sourceZones.any",
        "destinationZones.any",
        "servicesOrGroups.any",
    ]
    assert output["checksRun"] == ["any-any"]
    assert output["rulesExamined"] == 1
    assert output["scan"]["collections"] == ["firewall-rules-ipv4"]
    assert output["scan"]["truncated"] is False


async def test_any_any_stays_silent_for_specific_criteria(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="allow-web",
                        sourceZones={"zones": [{"name": "LAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                        servicesOrGroups={"services": [{"name": "HTTP"}]},
                    )
                ]
            )
        },
    )

    result = await call_tool("audit_firewall_rules", {"checks": ["any-any"], "ip_family": "ipv4"})

    assert result.is_error is False
    assert result.structured_content["findings"] == []


async def test_any_any_reports_any_service_with_medium_severity(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="allow-any-service",
                        sourceZones={"zones": [{"name": "LAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                    )
                ]
            )
        },
    )

    result = await call_tool("audit_firewall_rules", {"checks": ["any-any"], "ip_family": "ipv4"})

    finding = result.structured_content["findings"][0]
    assert finding["severity"] == "medium"
    assert finding["evidence"]["fields"] == ["servicesOrGroups.any"]


async def test_any_any_ignores_a_disabled_rule(router: Any) -> None:
    install(router, {RULES_V4: page([firewall_rule(name="off", enabled=False)])})

    result = await call_tool("audit_firewall_rules", {"checks": ["any-any"], "ip_family": "ipv4"})

    assert result.structured_content["findings"] == []


async def test_disabled_reports_a_disabled_rule_and_ignores_an_enabled_one(
    router: Any,
) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(name="enabled-rule", enabled=True),
                    firewall_rule(name="disabled-rule", enabled=False),
                ]
            )
        },
    )

    result = await call_tool("audit_firewall_rules", {"checks": ["disabled"], "ip_family": "ipv4"})

    findings = result.structured_content["findings"]
    assert [finding["evidence"]["ruleName"] for finding in findings] == ["disabled-rule"]
    assert findings[0]["evidence"]["position"] == 2
    assert findings[0]["evidence"]["fields"] == ["enabled"]


async def test_disabled_is_not_verifiable_without_an_enabled_state(router: Any) -> None:
    payload = firewall_rule(name="unknown-state")
    del payload["enabled"]
    install(router, {RULES_V4: page([payload])})

    result = await call_tool("audit_firewall_rules", {"checks": ["disabled"], "ip_family": "ipv4"})

    output = result.structured_content
    assert output["findings"] == []
    assert output["notVerifiable"][0]["check"] == "disabled"
    assert output["notVerifiable"][0]["subjects"] == ["unknown-state"]


async def test_shadowed_reports_the_earlier_covering_rule(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(name="allow-all"),
                    firewall_rule(
                        name="allow-web",
                        sourceZones={"zones": [{"name": "LAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                        servicesOrGroups={"services": [{"name": "HTTP"}]},
                    ),
                ]
            )
        },
    )

    result = await call_tool("audit_firewall_rules", {"checks": ["shadowed"], "ip_family": "ipv4"})

    findings = result.structured_content["findings"]
    assert len(findings) == 1
    assert findings[0]["check"] == "shadowed"
    assert findings[0]["evidence"]["ruleName"] == "allow-web"
    assert findings[0]["evidence"]["position"] == 2
    assert "allow-all" in findings[0]["evidence"]["detail"]
    assert "position 1" in findings[0]["evidence"]["detail"]


async def test_shadowed_stays_silent_when_the_later_rule_is_broader(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="allow-web",
                        sourceZones={"zones": [{"name": "LAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                        servicesOrGroups={"services": [{"name": "HTTP"}]},
                    ),
                    firewall_rule(name="allow-all"),
                ]
            )
        },
    )

    result = await call_tool("audit_firewall_rules", {"checks": ["shadowed"], "ip_family": "ipv4"})

    assert result.structured_content["findings"] == []


async def test_shadowed_marks_an_exact_duplicate(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(name="first"),
                    firewall_rule(name="second"),
                ]
            )
        },
    )

    result = await call_tool("audit_firewall_rules", {"checks": ["shadowed"], "ip_family": "ipv4"})

    findings = result.structured_content["findings"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "duplicates" in findings[0]["summary"]


async def test_shadowed_ignores_a_disabled_covering_rule(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(name="disabled-all", enabled=False),
                    firewall_rule(name="allow-web"),
                ]
            )
        },
    )

    result = await call_tool("audit_firewall_rules", {"checks": ["shadowed"], "ip_family": "ipv4"})

    assert result.structured_content["findings"] == []


async def test_no_logging_reports_an_unlogged_accept_rule(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(name="logged", logTraffic=True),
                    firewall_rule(name="unlogged", logTraffic=False),
                ]
            )
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["no-logging"], "ip_family": "ipv4"}
    )

    findings = result.structured_content["findings"]
    assert [finding["evidence"]["ruleName"] for finding in findings] == ["unlogged"]
    assert findings[0]["evidence"]["fields"] == ["logTraffic"]


async def test_no_logging_ignores_a_reject_rule(router: Any) -> None:
    install(
        router,
        {RULES_V4: page([firewall_rule(name="reject-rule", action="reject", logTraffic=False)])},
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["no-logging"], "ip_family": "ipv4"}
    )

    assert result.structured_content["findings"] == []


async def test_no_logging_is_not_verifiable_without_the_flag(router: Any) -> None:
    payload = firewall_rule(name="no-flag")
    del payload["logTraffic"]
    install(router, {RULES_V4: page([payload])})

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["no-logging"], "ip_family": "ipv4"}
    )

    output = result.structured_content
    assert output["findings"] == []
    assert output["notVerifiable"][0]["check"] == "no-logging"


async def test_unused_object_reports_an_unreferenced_address(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="use-web",
                        sourceNetworks={"ipv4Addresses": [{"name": "web-server"}]},
                    )
                ]
            ),
            ADDR_V4: page(
                [
                    ipv4_address(name="web-server"),
                    ipv4_address(name="orphan", id=UUID_2),
                ]
            ),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv4"}
    )

    findings = result.structured_content["findings"]
    assert [finding["evidence"]["objectName"] for finding in findings] == ["orphan"]
    assert findings[0]["check"] == "unused-object"
    assert findings[0]["evidence"]["objectType"] == "address"
    assert findings[0]["evidence"]["ipFamily"] == "ipv4"


async def test_unused_object_counts_a_group_membership_as_a_reference(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="use-group")]),
            ADDR_V4: page([ipv4_address(name="group-member")]),
            GROUP_V4: page([ipv4_group(name="web-servers", members=("group-member",))]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv4"}
    )

    assert result.structured_content["findings"] == []


async def test_unused_object_counts_a_nat_reference_as_a_reference(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="allow-web")]),
            NAT_V4: page(
                [
                    nat_rule(
                        name="dnat",
                        originalDestinationNetworks={"ipv4Addresses": [{"name": "web-server"}]},
                    )
                ]
            ),
            ADDR_V4: page([ipv4_address(name="web-server")]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv4"}
    )

    assert result.structured_content["findings"] == []


async def test_unused_object_does_not_inventory_an_unscanned_family(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="use-web",
                        sourceNetworks={"ipv4Addresses": [{"name": "web-server"}]},
                    )
                ]
            ),
            ADDR_V4: page([ipv4_address(name="web-server")]),
            ADDR_V6: page(
                [
                    {
                        "id": UUID_2,
                        "name": "v6-orphan",
                        "type": "ipv6Address",
                        "ipv6Address": "2001:db8::1",
                    }
                ]
            ),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv4"}
    )

    output = result.structured_content
    assert output["findings"] == []
    assert ADDR_V6 not in called_paths(router)
    assert ADDR_FQDN in called_paths(router)


async def test_unused_object_scans_both_families_when_ip_family_is_set(router: Any) -> None:
    # H1: with ip_family=ipv6 the IPv4 rule base is still read for references, so a service
    # used by an IPv4 rule is not reported as removable.
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="use-8080",
                        servicesOrGroups={"services": [{"name": "8080"}]},
                    )
                ]
            ),
            RULES_V6: page([]),
            SERVICES: page([service("8080"), service("orphan-service")]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv6"}
    )

    output = result.structured_content
    assert [finding["evidence"]["objectName"] for finding in output["findings"]] == [
        "orphan-service"
    ]
    assert RULES_V4 in called_paths(router)
    assert any("both IP families" in note for note in output["notes"])


async def test_unused_object_excludes_built_in_objects(router: Any) -> None:
    # M5: built-in and auto-generated objects cannot be removed, so they are not findings.
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="r1")]),
            ADDR_V4: page(
                [
                    ipv4_address(name="##ALL_RW"),
                    ipv4_address(name="#Port2", id=UUID_2),
                    ipv4_address(name="orphan", id="11111111-1111-1111-1111-111111111111"),
                ]
            ),
            SERVICES: page(
                [
                    dict(
                        service("AH"),
                        createdAt="1970-01-01T00:00:00Z",
                        updatedAt="1970-01-01T00:00:00Z",
                    ),
                    service("orphan-service"),
                ]
            ),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv4"}
    )

    output = result.structured_content
    assert [finding["evidence"]["objectName"] for finding in output["findings"]] == [
        "orphan",
        "orphan-service",
    ]
    assert any("built-in" in note for note in output["notes"])


async def test_unused_object_note_states_the_built_in_heuristic(router: Any) -> None:
    # L7: the exclusion is a heuristic, not a contract flag. The note must say so, name the
    # epoch sentinel and report how many objects it skipped. The live run of 2026-11-15 showed
    # the appliance stamps every service with the epoch, so a user-created service is excluded
    # too; the note has to admit that instead of implying the object is built-in.
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="r1")]),
            ADDR_V4: page([ipv4_address(name="##ALL_RW")]),
            SERVICES: page(
                [
                    dict(
                        service("AH"),
                        createdAt="1970-01-01T00:00:00Z",
                        updatedAt="1970-01-01T00:00:00Z",
                    ),
                    dict(
                        service("DOCKHAND_MCP"),
                        createdAt="1970-01-01T00:00:00Z",
                        updatedAt="1970-01-01T00:00:00Z",
                    ),
                ]
            ),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv4"}
    )

    output = result.structured_content
    assert output["findings"] == []
    note = next(item for item in output["notes"] if "built-in" in item)
    assert "heuristic" in note
    assert "1970-01-01T00:00:00Z" in note
    assert "every service" in note
    assert "3 object(s) were excluded" in note


async def test_unused_object_is_not_verifiable_when_the_rule_scan_is_truncated(
    router: Any,
) -> None:
    install(router, {RULES_V4: page([firewall_rule(name="r1")], total=1000)})

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv4"}
    )

    output = result.structured_content
    assert output["findings"] == []
    assert output["notVerifiable"][0]["check"] == "unused-object"
    assert output["scan"]["truncated"] is True


async def test_nat_without_rule_reports_a_missing_link(router: Any) -> None:
    payload = nat_rule(name="dnat")
    del payload["linkedFirewallRule"]
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="allow-web")]),
            NAT_V4: page([payload]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["nat-without-rule"], "ip_family": "ipv4"}
    )

    findings = result.structured_content["findings"]
    assert len(findings) == 1
    assert findings[0]["check"] == "nat-without-rule"
    assert findings[0]["evidence"]["objectName"] == "dnat"
    assert findings[0]["evidence"]["objectType"] == "nat-rule"
    assert findings[0]["evidence"]["fields"] == ["linkedFirewallRule"]


async def test_nat_without_rule_reports_a_link_to_a_missing_rule(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="allow-web")]),
            NAT_V4: page([nat_rule(name="dnat", linkedFirewallRule={"name": "deleted-rule"})]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["nat-without-rule"], "ip_family": "ipv4"}
    )

    findings = result.structured_content["findings"]
    assert len(findings) == 1
    assert "deleted-rule" in findings[0]["summary"]


async def test_nat_without_rule_accepts_an_existing_link(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="allow-web")]),
            NAT_V4: page([nat_rule(name="dnat", linkedFirewallRule={"name": "allow-web"})]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["nat-without-rule"], "ip_family": "ipv4"}
    )

    assert result.structured_content["findings"] == []


async def test_unrestricted_service_reports_lan_to_wan_with_any_service(
    router: Any,
) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="allow-egress",
                        sourceZones={"zones": [{"name": "LAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                    )
                ]
            ),
            ZONES: page([zone("LAN", "lan"), zone("WAN", "wan")]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules",
        {"checks": ["unrestricted-service"], "ip_family": "ipv4"},
    )

    findings = result.structured_content["findings"]
    assert len(findings) == 1
    assert findings[0]["check"] == "unrestricted-service"
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["ruleName"] == "allow-egress"


async def test_unrestricted_service_ignores_wan_to_wan(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="wan-to-wan",
                        sourceZones={"zones": [{"name": "WAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                    )
                ]
            ),
            ZONES: page([zone("WAN", "wan")]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules",
        {"checks": ["unrestricted-service"], "ip_family": "ipv4"},
    )

    assert result.structured_content["findings"] == []


async def test_unrestricted_service_ignores_a_specific_service(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="allow-web",
                        sourceZones={"zones": [{"name": "LAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                        servicesOrGroups={"services": [{"name": "HTTP"}]},
                    )
                ]
            ),
            ZONES: page([zone("LAN", "lan"), zone("WAN", "wan")]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules",
        {"checks": ["unrestricted-service"], "ip_family": "ipv4"},
    )

    assert result.structured_content["findings"] == []


async def test_unrestricted_service_is_not_verifiable_for_an_unknown_zone(
    router: Any,
) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="allow-egress",
                        sourceZones={"zones": [{"name": "MYSTERY"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                    )
                ]
            ),
            ZONES: page([zone("WAN", "wan")]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules",
        {"checks": ["unrestricted-service"], "ip_family": "ipv4"},
    )

    output = result.structured_content
    assert output["findings"] == []
    assert output["notVerifiable"][0]["check"] == "unrestricted-service"


async def test_all_checks_run_together_without_an_output_bound_error(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(name="allow-all", logTraffic=False),
                    firewall_rule(name="disabled-rule", enabled=False),
                    firewall_rule(
                        name="allow-egress",
                        sourceZones={"zones": [{"name": "LAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                        logTraffic=False,
                    ),
                ]
            ),
            NAT_V4: page([nat_rule(name="dnat", linkedFirewallRule={"name": "deleted-rule"})]),
            ZONES: page([zone("LAN", "lan"), zone("WAN", "wan")]),
            ADDR_V4: page([ipv4_address(name="orphan")]),
            SERVICES: page([service("HTTP")]),
        },
    )

    result = await call_tool("audit_firewall_rules", {})

    assert result.is_error is False
    output = result.structured_content
    checks = {finding["check"] for finding in output["findings"]}
    assert checks == {
        "any-any",
        "disabled",
        "shadowed",
        "no-logging",
        "unused-object",
        "nat-without-rule",
        "unrestricted-service",
    }
    assert output["checksRun"] == [
        "any-any",
        "disabled",
        "shadowed",
        "no-logging",
        "unused-object",
        "nat-without-rule",
        "unrestricted-service",
    ]
    assert output["rulesExamined"] == 3
    assert output["natRulesExamined"] == 1


async def test_checks_filter_limits_the_work_and_the_output(router: Any) -> None:
    install(router, {RULES_V4: page([firewall_rule(name="disabled", enabled=False)])})

    result = await call_tool("audit_firewall_rules", {"checks": ["disabled"], "ip_family": "ipv4"})

    output = result.structured_content
    assert output["checksRun"] == ["disabled"]
    assert [finding["check"] for finding in output["findings"]] == ["disabled"]
    # Only the rule collection was read: no NAT, zone or object scan happened.
    assert called_paths(router) == {RULES_V4}


async def test_rule_name_filter_selects_reported_findings(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(name="web-disabled", enabled=False),
                    firewall_rule(name="db-disabled", enabled=False),
                ]
            )
        },
    )

    result = await call_tool(
        "audit_firewall_rules",
        {"checks": ["disabled"], "ip_family": "ipv4", "rule_name_contains": "web"},
    )

    findings = result.structured_content["findings"]
    assert [finding["evidence"]["ruleName"] for finding in findings] == ["web-disabled"]
    assert any("rule_name_contains" in note for note in result.structured_content["notes"])


async def test_rule_name_filter_skips_non_rule_scoped_checks(router: Any) -> None:
    # M6: a rule-name filter must narrow the report, not leave 100 unrelated object findings.
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="allow-all")]),
            ADDR_V4: page([ipv4_address(name="orphan")]),
            SERVICES: page([service("HTTP")]),
        },
    )

    result = await call_tool("audit_firewall_rules", {"rule_name_contains": "zzz-no-match"})

    output = result.structured_content
    assert output["findings"] == []
    assert "unused-object" not in output["checksRun"]
    assert "nat-without-rule" not in output["checksRun"]
    assert any("non-rule-scoped" in note for note in output["notes"])


async def test_findings_are_bounded_and_truncation_is_explicit(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(name="off-1", enabled=False),
                    firewall_rule(name="off-2", enabled=False),
                    firewall_rule(name="off-3", enabled=False),
                ]
            )
        },
    )

    result = await call_tool(
        "audit_firewall_rules",
        {"checks": ["disabled"], "ip_family": "ipv4", "max_findings": 2},
    )

    output = result.structured_content
    assert len(output["findings"]) == 2
    assert output["findingsTruncated"] is True


async def test_findings_are_sorted_by_severity_before_truncation(router: Any) -> None:
    # M4: a medium shadowed finding must not be dropped while low disabled findings are kept.
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="cover",
                        servicesOrGroups={"services": [{"name": "HTTP"}]},
                    ),
                    firewall_rule(
                        name="shadowed",
                        sourceZones={"zones": [{"name": "LAN"}]},
                        destinationZones={"zones": [{"name": "WAN"}]},
                        servicesOrGroups={"services": [{"name": "HTTP"}]},
                    ),
                    firewall_rule(name="off-1", enabled=False),
                    firewall_rule(name="off-2", enabled=False),
                    firewall_rule(name="off-3", enabled=False),
                ]
            )
        },
    )

    result = await call_tool(
        "audit_firewall_rules",
        {
            "checks": ["disabled", "shadowed"],
            "ip_family": "ipv4",
            "max_findings": 2,
        },
    )

    output = result.structured_content
    assert output["findingsTruncated"] is True
    assert [finding["check"] for finding in output["findings"]] == ["shadowed", "disabled"]
    assert output["findings"][0]["severity"] == "medium"


async def test_a_truncated_scan_is_reported_with_its_collection(router: Any) -> None:
    install(router, {RULES_V4: page([firewall_rule(name="r1")], total=1000)})

    result = await call_tool("audit_firewall_rules", {"checks": ["disabled"], "ip_family": "ipv4"})

    scan = result.structured_content["scan"]
    assert scan["truncated"] is True
    assert scan["truncatedCollections"] == ["firewall-rules-ipv4"]
    assert scan["pagesRead"] == 5
    assert scan["itemLimitPerCollection"] == 500


async def test_audit_reads_the_audited_paths_with_the_documented_pagination(
    router: Any,
) -> None:
    install(router, {RULES_V4: page([firewall_rule(name="r1")])})

    result = await call_tool("audit_firewall_rules", {"checks": ["disabled"], "ip_family": "ipv4"})

    assert result.is_error is False
    assert called_paths(router) == {RULES_V4}
    query = dict(router.calls.last.request.url.params)
    assert query["pageSize"] == "100"
    assert query["pageTotal"] == "true"
    assert router.calls.last.request.headers["authorization"] == f"Bearer {KEY}"


async def test_audit_maps_a_transport_failure_to_a_sanitized_error(router: Any) -> None:
    router.get(url__regex=r".*").mock(
        return_value=httpx.Response(401, json={"error": "unauthenticated"})
    )

    result = await call_tool("audit_firewall_rules", {"checks": ["disabled"], "ip_family": "ipv4"})

    assert result.is_error is True
    text = result.content[0].text
    # A 401 is an authentication failure (the key), not a permission problem (the profile).
    assert "authentication failed" in text
    assert KEY not in text


# -- explain_connectivity: the four verdicts and the ordered evidence ------------------


def connectivity_collections(
    *,
    rules: list[dict[str, Any]],
    nat: list[dict[str, Any]] | None = None,
    routes: list[dict[str, Any]] | None = None,
    gateways: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        RULES_V4: page(rules),
        RULES_V6: page([]),
        NAT_V4: page(nat if nat is not None else []),
        NAT_V6: page([]),
        INTERFACES: page(
            [
                interface("Port1", "LAN", "10.0.0.1", 24),
                interface("Port2", "WAN", "203.0.113.2", 24),
            ]
        ),
        ZONES: page([zone("LAN", "lan"), zone("WAN", "wan")]),
        GATEWAYS_V4: page(gateways if gateways is not None else [gateway()]),
        GATEWAYS_V6: page([]),
        ROUTES_V4: page(routes if routes is not None else [route()]),
        ROUTES_V6: page([]),
    }


ALLOW_RULE = firewall_rule(
    name="allow-web",
    sourceZones={"zones": [{"name": "LAN"}]},
    destinationZones={"zones": [{"name": "WAN"}]},
    servicesOrGroups={"services": [{"name": "HTTP"}]},
)


async def test_explain_connectivity_allows_a_flow(router: Any) -> None:
    install(router, connectivity_collections(rules=[ALLOW_RULE]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    assert result.is_error is False
    output = result.structured_content
    assert output["method"] == "config-analysis"
    assert output["verdict"] == "allowed"
    assert "allow-web" in output["verdictReason"]
    assert output["decisiveRule"]["name"] == "allow-web"
    assert output["decisiveRule"]["position"] == 1
    assert output["decisiveRule"]["applied"] is True
    assert output["source"]["resolvedZones"] == ["LAN"]
    assert output["source"]["interfaces"] == ["Port1"]
    assert output["destination"]["resolvedZones"] == ["WAN"]
    assert output["routing"]["decision"] == "default-route"
    assert output["routing"]["gateway"] == "wan-gateway"
    assert output["routing"]["interface"] == "Port2"
    assert output["ipFamilies"] == ["ipv4"]
    assert output["truncated"] is False


async def test_explain_connectivity_denies_a_flow(router: Any) -> None:
    install(
        router,
        connectivity_collections(rules=[dict(ALLOW_RULE, name="block-web", action="drop")]),
    )

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["verdict"] == "denied"
    assert output["decisiveRule"]["action"] == "drop"


async def test_explain_connectivity_reports_no_matching_rule(router: Any) -> None:
    install(router, connectivity_collections(rules=[]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["verdict"] == "no-matching-rule"
    assert output["decisiveRule"] is None
    assert output["firewallRules"] == []


# B1: a rule whose service criterion does not match must never be decisive. The matrix is
# 12 zone pairs x 4 service names; only LAN -> WAN with DNS matches the DNS-only block rule.
ZONE_PAIRS = [
    ("LAN", "WAN"),
    ("LAN", "DMZ"),
    ("LAN", "VPN"),
    ("DMZ", "WAN"),
    ("DMZ", "LAN"),
    ("DMZ", "VPN"),
    ("VPN", "WAN"),
    ("VPN", "LAN"),
    ("VPN", "DMZ"),
    ("WAN", "LAN"),
    ("WAN", "DMZ"),
    ("WAN", "VPN"),
]
SERVICE_NAMES = ["DNS", "SSH", "HTTPS", "NoSuchService"]


@pytest.mark.parametrize(("source_zone", "destination_zone"), ZONE_PAIRS)
@pytest.mark.parametrize("service_name", SERVICE_NAMES)
async def test_explain_connectivity_never_decides_on_a_mismatched_service(
    router: Any,
    source_zone: str,
    destination_zone: str,
    service_name: str,
) -> None:
    rule = firewall_rule(
        name="DNS to WAN - BLOCK",
        action="drop",
        sourceZones={"zones": [{"name": "LAN"}]},
        destinationZones={"zones": [{"name": "WAN"}]},
        servicesOrGroups={"services": [{"name": "DNS"}, {"name": "DNS - DoT (853)"}]},
    )
    install(router, connectivity_collections(rules=[rule]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"zone": source_zone},
            "destination": {"zone": destination_zone},
            "service": {"name": service_name},
            "ip_family": "ipv4",
        },
    )

    output = result.structured_content
    matches = source_zone == "LAN" and destination_zone == "WAN" and service_name == "DNS"
    if matches:
        assert output["verdict"] == "denied"
        assert output["decisiveRule"]["name"] == "DNS to WAN - BLOCK"
    else:
        assert output["verdict"] == "no-matching-rule"
        assert output["decisiveRule"] is None
        assert output["firewallRules"] == []


async def test_explain_connectivity_does_not_allow_on_a_mismatched_service(
    router: Any,
) -> None:
    # B1 also produces a false `allowed` when the mismatched rule is an accept rule.
    rule = firewall_rule(
        name="DNS to WAN - ALLOW",
        action="accept",
        sourceZones={"zones": [{"name": "LAN"}]},
        destinationZones={"zones": [{"name": "WAN"}]},
        servicesOrGroups={"services": [{"name": "DNS"}]},
    )
    install(router, connectivity_collections(rules=[rule]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"zone": "LAN"},
            "destination": {"zone": "WAN"},
            "service": {"name": "SSH"},
            "ip_family": "ipv4",
        },
    )

    output = result.structured_content
    assert output["verdict"] == "no-matching-rule"
    assert output["decisiveRule"] is None


async def test_explain_connectivity_does_not_report_a_nat_rule_with_a_mismatched_service(
    router: Any,
) -> None:
    # The same latent bug in _evaluate_nat: a False service criterion must exclude the rule.
    nat = nat_rule(
        name="dnat",
        originalServicesOrGroups={"services": [{"name": "DNS"}]},
    )
    install(router, connectivity_collections(rules=[ALLOW_RULE], nat=[nat]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "SSH"},
        },
    )

    assert result.structured_content["natRules"] == []


async def test_explain_connectivity_is_not_verifiable_for_object_criteria(
    router: Any,
) -> None:
    rule = firewall_rule(
        name="allow-object",
        sourceZones={"zones": [{"name": "LAN"}]},
        destinationZones={"zones": [{"name": "WAN"}]},
        sourceNetworks={"ipv4Addresses": [{"name": "LAN-NET"}]},
    )
    install(router, connectivity_collections(rules=[rule]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["verdict"] == "not-verifiable"
    assert output["decisiveRule"] is None
    assert any("allow-object" in item for item in output["missingEvidence"])
    assert any("sourceNetworks" in item for item in output["missingEvidence"])


async def test_explain_connectivity_reports_the_candidate_rule_when_not_verifiable(
    router: Any,
) -> None:
    # M7: the indeterminate rule must be a structured candidate, not only prose.
    rule = firewall_rule(
        name="allow-object",
        sourceZones={"zones": [{"name": "LAN"}]},
        destinationZones={"zones": [{"name": "WAN"}]},
        sourceNetworks={"ipv4Addresses": [{"name": "LAN-NET"}]},
    )
    install(router, connectivity_collections(rules=[rule]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["verdict"] == "not-verifiable"
    assert output["decisiveRule"] is None
    candidates = output["firewallRules"]
    assert [candidate["name"] for candidate in candidates] == ["allow-object"]
    candidate = candidates[0]
    assert candidate["position"] == 1
    assert candidate["decisive"] is False
    assert candidate["applied"] is False
    assert candidate["unresolvedFields"] == ["sourceNetworks"]
    assert candidate["matchedFields"] == [
        "sourceZones",
        "destinationZones",
        "destinationNetworks",
        "servicesOrGroups",
    ]


async def test_explain_connectivity_reports_every_indeterminate_rule(router: Any) -> None:
    # L6: every indeterminate rule is a structured candidate, not only the first one, and a
    # later fully-resolved rule is reported but not decisive because an earlier rule may
    # preempt it.
    first = firewall_rule(
        name="allow-object-a",
        sourceZones={"zones": [{"name": "LAN"}]},
        destinationZones={"zones": [{"name": "WAN"}]},
        sourceNetworks={"ipv4Addresses": [{"name": "LAN-NET"}]},
    )
    second = firewall_rule(
        name="allow-object-b",
        sourceZones={"zones": [{"name": "LAN"}]},
        destinationZones={"zones": [{"name": "WAN"}]},
        destinationNetworks={"ipv4Addresses": [{"name": "WAN-NET"}]},
    )
    later = firewall_rule(
        name="allow-web",
        sourceZones={"zones": [{"name": "LAN"}]},
        destinationZones={"zones": [{"name": "WAN"}]},
        servicesOrGroups={"services": [{"name": "HTTP"}]},
    )
    install(router, connectivity_collections(rules=[first, second, later]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["verdict"] == "not-verifiable"
    assert output["decisiveRule"] is None
    candidates = output["firewallRules"]
    assert [candidate["name"] for candidate in candidates] == [
        "allow-object-a",
        "allow-object-b",
        "allow-web",
    ]
    assert [candidate["position"] for candidate in candidates] == [1, 2, 3]
    assert candidates[0]["unresolvedFields"] == ["sourceNetworks"]
    assert candidates[1]["unresolvedFields"] == ["destinationNetworks"]
    assert candidates[2]["decisive"] is False
    assert candidates[2]["applied"] is False
    assert "preempt" in candidates[2]["note"]
    evidence = [item for item in output["missingEvidence"] if "allow-object" in item]
    assert len(evidence) == 1
    assert "allow-object-a" in evidence[0]
    assert "allow-object-b" in evidence[0]
    assert "2 rule(s)" in evidence[0]


async def test_explain_connectivity_bounds_the_indeterminate_evidence(router: Any) -> None:
    # L6: the evidence line names every candidate but stays within the model's text bound, so a
    # large rule base cannot produce an over-long verdict reason.
    rules = [
        firewall_rule(
            name=f"allow-object-{index:02d}",
            sourceZones={"zones": [{"name": "LAN"}]},
            destinationZones={"zones": [{"name": "WAN"}]},
            sourceNetworks={"ipv4Addresses": [{"name": f"LAN-NET-{index}"}]},
        )
        for index in range(12)
    ]
    install(router, connectivity_collections(rules=rules))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["verdict"] == "not-verifiable"
    assert len(output["firewallRules"]) == 12
    evidence = next(item for item in output["missingEvidence"] if "rule(s)" in item)
    assert len(evidence) <= 400
    assert "12 rule(s)" in evidence
    assert "more" in evidence
    assert len(output["verdictReason"]) <= 400


async def test_explain_connectivity_is_not_verifiable_for_an_fqdn(router: Any) -> None:
    install(router, connectivity_collections(rules=[ALLOW_RULE]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"fqdn": "example.com"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["verdict"] == "not-verifiable"
    assert output["method"] == "config-analysis"
    assert any("FQDN" in item for item in output["missingEvidence"])


async def test_explain_connectivity_reports_a_disabled_matching_rule(router: Any) -> None:
    disabled = dict(ALLOW_RULE, name="allow-web-disabled", enabled=False)
    install(router, connectivity_collections(rules=[disabled]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["verdict"] == "no-matching-rule"
    assert output["firewallRules"][0]["name"] == "allow-web-disabled"
    assert output["firewallRules"][0]["applied"] is False
    assert output["firewallRules"][0]["decisive"] is False


async def test_explain_connectivity_reports_nat_linkage(router: Any) -> None:
    install(
        router,
        connectivity_collections(
            rules=[ALLOW_RULE],
            nat=[nat_rule(name="dnat", linkedFirewallRule={"name": "allow-web"})],
        ),
    )

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert len(output["natRules"]) == 1
    nat = output["natRules"][0]
    assert nat["name"] == "dnat"
    assert nat["linkedFirewallRule"] == "allow-web"
    assert nat["linkedRuleExists"] is True


async def test_explain_connectivity_reports_a_nat_rule_without_a_link(router: Any) -> None:
    payload = nat_rule(name="dnat")
    del payload["linkedFirewallRule"]
    install(router, connectivity_collections(rules=[ALLOW_RULE], nat=[payload]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    nat = result.structured_content["natRules"][0]
    assert nat["linkedFirewallRule"] is None
    assert nat["linkedRuleExists"] is None


async def test_explain_connectivity_reports_a_static_route(router: Any) -> None:
    install(
        router,
        connectivity_collections(
            rules=[ALLOW_RULE],
            routes=[route("web-route", "198.51.100.0", 24)],
        ),
    )

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    routing = result.structured_content["routing"]
    assert routing["decision"] == "static-route"
    assert routing["routeName"] == "web-route"


async def test_explain_connectivity_reports_no_route(router: Any) -> None:
    install(router, connectivity_collections(rules=[ALLOW_RULE], routes=[], gateways=[]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["routing"]["decision"] == "no-route"
    assert any("route" in item for item in output["missingEvidence"])


async def test_explain_connectivity_does_not_conclude_no_route_from_a_truncated_scan(
    router: Any,
) -> None:
    # L8: a truncated gateway/route scan must not produce a confident no-route.
    collections = connectivity_collections(rules=[ALLOW_RULE], routes=[], gateways=[])
    collections[GATEWAYS_V4] = page([], total=1000)
    install(router, collections)

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    routing = output["routing"]
    assert routing["decision"] == "not-verified"
    assert routing["truncated"] is True
    assert "truncated" in routing["note"]
    assert "no-route cannot be concluded" in routing["note"]
    assert any("truncated" in item for item in output["missingEvidence"])
    assert output["truncated"] is True


async def test_explain_connectivity_marks_a_truncated_route_scan(router: Any) -> None:
    # L8: a matching route is still reported, but the decision is marked truncated because a
    # more specific route may exist beyond the scanned portion.
    collections = connectivity_collections(
        rules=[ALLOW_RULE], routes=[route("web-route", "198.51.100.0", 24)]
    )
    collections[ROUTES_V4] = page([route("web-route", "198.51.100.0", 24)], total=1000)
    install(router, collections)

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    routing = output["routing"]
    assert routing["decision"] == "static-route"
    assert routing["routeName"] == "web-route"
    assert routing["truncated"] is True
    assert "truncated" in routing["note"]
    assert any("truncated" in item for item in output["missingEvidence"])


async def test_explain_connectivity_marks_a_truncated_default_route(router: Any) -> None:
    # L8: the WAN default route is still reported, but the truncation is recorded because a
    # static route beyond the scanned portion could take precedence.
    collections = connectivity_collections(rules=[ALLOW_RULE], routes=[], gateways=[gateway()])
    collections[GATEWAYS_V4] = page([gateway()], total=1000)
    install(router, collections)

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "8.8.8.8"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    routing = output["routing"]
    assert routing["decision"] == "default-route"
    assert routing["gateway"] == "wan-gateway"
    assert routing["truncated"] is True
    assert "truncated" in routing["note"]
    assert len(routing["note"]) <= 400
    assert any("truncated" in item for item in output["missingEvidence"])


async def test_explain_connectivity_uses_the_wan_gateway_as_the_default_route(
    router: Any,
) -> None:
    # H4: the appliance has no static unicast route but one WAN gateway, which *is* the
    # default route. Reporting no-route for an internet destination is wrong.
    install(router, connectivity_collections(rules=[ALLOW_RULE], routes=[]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "8.8.8.8"},
            "service": {"name": "HTTP"},
        },
    )

    routing = result.structured_content["routing"]
    assert routing["decision"] == "default-route"
    assert routing["gateway"] == "wan-gateway"
    assert routing["gatewayIp"] == "203.0.113.1"
    assert routing["interface"] == "Port2"
    assert "WAN gateway" in routing["note"]


async def test_explain_connectivity_analyses_both_families_for_a_zone_flow(
    router: Any,
) -> None:
    install(
        router,
        {
            RULES_V4: page([ALLOW_RULE]),
            RULES_V6: page([dict(ALLOW_RULE, name="allow-web-v6")]),
            NAT_V4: page([]),
            NAT_V6: page([]),
            INTERFACES: page([interface("Port1", "LAN", "10.0.0.1", 24)]),
            ZONES: page([zone("LAN", "lan"), zone("WAN", "wan")]),
        },
    )

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"zone": "LAN"},
            "destination": {"zone": "WAN"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["ipFamilies"] == ["ipv4", "ipv6"]
    assert output["verdict"] == "allowed"
    assert output["routing"]["decision"] == "not-verified"


async def test_explain_connectivity_infers_the_family_when_one_rule_base_is_empty(
    router: Any,
) -> None:
    # M8: both endpoints are zones, so the family is ambiguous, but the IPv6 rule base is
    # empty. The natural answer is IPv4, not not-verifiable.
    install(
        router,
        {
            RULES_V4: page([ALLOW_RULE]),
            RULES_V6: page([]),
            NAT_V4: page([]),
            NAT_V6: page([]),
            INTERFACES: page([interface("Port1", "LAN", "10.0.0.1", 24)]),
            ZONES: page([zone("LAN", "lan"), zone("WAN", "wan")]),
        },
    )

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"zone": "LAN"},
            "destination": {"zone": "WAN"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["ipFamilies"] == ["ipv4"]
    assert output["verdict"] == "allowed"
    assert any("ipv6 rule base is empty" in note for note in output["notes"])


async def test_explain_connectivity_is_not_verifiable_when_the_rule_scan_is_truncated(
    router: Any,
) -> None:
    install(
        router,
        connectivity_collections(
            rules=[
                firewall_rule(
                    name="other",
                    destinationZones={"zones": [{"name": "LAN"}]},
                ),
                ALLOW_RULE,
            ]
        ),
    )

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
            "max_rules_examined": 1,
        },
    )

    output = result.structured_content
    assert output["verdict"] == "not-verifiable"
    assert output["truncated"] is True
    assert any("truncated" in item for item in output["missingEvidence"])


async def test_explain_connectivity_states_it_is_not_a_packet_test(router: Any) -> None:
    install(router, connectivity_collections(rules=[ALLOW_RULE]))

    result = await call_tool(
        "explain_connectivity",
        {
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "198.51.100.9"},
            "service": {"name": "HTTP"},
        },
    )

    output = result.structured_content
    assert output["method"] == "config-analysis"
    assert any("not a packet test" in note for note in output["notes"])


# -- find_object_usage ----------------------------------------------------------------


async def test_find_object_usage_reports_rules_nat_and_groups(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="allow-source",
                        sourceNetworks={"ipv4Addresses": [{"name": "web-server"}]},
                    ),
                    firewall_rule(
                        name="allow-group",
                        destinationNetworks={"ipv4Groups": [{"name": "web-servers"}]},
                    ),
                ]
            ),
            NAT_V4: page(
                [
                    nat_rule(
                        name="dnat",
                        originalDestinationNetworks={"ipv4Addresses": [{"name": "web-server"}]},
                    )
                ]
            ),
            ADDR_V4: page([ipv4_address(name="web-server")]),
            GROUP_V4: page([ipv4_group(name="web-servers", members=("web-server",))]),
        },
    )

    result = await call_tool(
        "find_object_usage", {"object_type": "address", "identifier": "web-server"}
    )

    assert result.is_error is False
    output = result.structured_content
    assert output["found"] is True
    assert output["resolvedName"] == "web-server"
    assert output["referenceCount"] == 3
    kinds = {reference["kind"] for reference in output["references"]}
    assert kinds == {"firewall-rule", "nat-rule", "group"}
    rule_reference = next(
        reference for reference in output["references"] if reference["kind"] == "firewall-rule"
    )
    assert rule_reference["name"] == "allow-source"
    assert rule_reference["position"] == 1
    assert rule_reference["field"] == "sourceNetworks.ipv4Addresses"
    group_reference = next(
        reference for reference in output["references"] if reference["kind"] == "group"
    )
    assert group_reference["name"] == "web-servers"
    assert group_reference["field"] == "members"


async def test_find_object_usage_resolves_a_uuid_to_its_name(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="allow-source",
                        sourceNetworks={"ipv4Addresses": [{"name": "web-server"}]},
                    )
                ]
            ),
            ADDR_V4: page([ipv4_address(name="web-server")]),
        },
    )

    result = await call_tool("find_object_usage", {"object_type": "address", "identifier": UUID})

    output = result.structured_content
    assert output["found"] is True
    assert output["resolvedName"] == "web-server"
    assert output["resolvedId"] == UUID
    assert output["referenceCount"] == 1


async def test_find_object_usage_reports_an_unknown_object(router: Any) -> None:
    install(router, {ADDR_V4: page([])})

    result = await call_tool("find_object_usage", {"object_type": "address", "identifier": "ghost"})

    output = result.structured_content
    assert output["found"] is False
    assert output["resolvedName"] is None
    assert output["references"] == []
    assert any("not found" in note for note in output["notes"])


async def test_find_object_usage_bounds_the_references(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [
                    firewall_rule(
                        name="rule-1",
                        sourceNetworks={"ipv4Addresses": [{"name": "web-server"}]},
                    ),
                    firewall_rule(
                        name="rule-2",
                        destinationNetworks={"ipv4Addresses": [{"name": "web-server"}]},
                    ),
                ]
            ),
            ADDR_V4: page([ipv4_address(name="web-server")]),
        },
    )

    result = await call_tool(
        "find_object_usage",
        {"object_type": "address", "identifier": "web-server", "max_references": 1},
    )

    output = result.structured_content
    assert len(output["references"]) == 1
    assert output["referenceCount"] == 2
    assert output["truncated"] is True


async def test_find_object_usage_scans_service_groups(router: Any) -> None:
    install(
        router,
        {
            RULES_V4: page(
                [firewall_rule(name="allow-web", servicesOrGroups={"services": [{"name": "HTTP"}]})]
            ),
            SERVICES: page([service("HTTP")]),
            SERVICE_GROUPS: page([service_group("web-services", ("HTTP",))]),
        },
    )

    result = await call_tool("find_object_usage", {"object_type": "service", "identifier": "HTTP"})

    output = result.structured_content
    assert output["found"] is True
    assert output["referenceCount"] == 2
    assert {reference["kind"] for reference in output["references"]} == {
        "firewall-rule",
        "group",
    }


async def test_find_object_usage_reports_a_truncated_scan(router: Any) -> None:
    install(router, {RULES_V4: page([firewall_rule(name="r1")], total=1000)})

    result = await call_tool("find_object_usage", {"object_type": "address", "identifier": "ghost"})

    output = result.structured_content
    assert output["truncated"] is True
    assert output["scan"]["truncated"] is True
    assert any("truncated" in note for note in output["notes"])


# -- Closed inputs --------------------------------------------------------------------


def test_audit_input_rejects_unknown_members() -> None:
    with pytest.raises(ValidationError):
        AuditFirewallRulesInput.model_validate({"checks": ["disabled"], "bogus": 1})


def test_audit_input_rejects_duplicate_checks() -> None:
    with pytest.raises(ValidationError, match="duplicates"):
        AuditFirewallRulesInput.model_validate({"checks": ["disabled", "disabled"]})


def test_audit_input_rejects_an_unknown_check() -> None:
    with pytest.raises(ValidationError):
        AuditFirewallRulesInput.model_validate({"checks": ["invented-check"]})


def test_audit_input_bounds_max_findings() -> None:
    with pytest.raises(ValidationError):
        AuditFirewallRulesInput.model_validate({"max_findings": 101})


def test_connectivity_endpoint_requires_exactly_one_selector() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        ConnectivityEndpoint.model_validate({"ip": "10.0.0.5", "zone": "LAN"})
    with pytest.raises(ValidationError, match="exactly one"):
        ConnectivityEndpoint.model_validate({})


def test_connectivity_endpoint_rejects_an_invalid_ip() -> None:
    with pytest.raises(ValidationError, match="valid IPv4 or IPv6"):
        ConnectivityEndpoint.model_validate({"ip": "not-an-ip"})


def test_connectivity_service_requires_a_name_or_protocol() -> None:
    with pytest.raises(ValidationError, match="service name or a protocol"):
        ConnectivityService.model_validate({})


def test_connectivity_service_port_requires_tcp_or_udp() -> None:
    with pytest.raises(ValidationError, match="port requires protocol"):
        ConnectivityService.model_validate({"protocol": "icmp", "port": 80})


def test_explain_input_rejects_unknown_members() -> None:
    with pytest.raises(ValidationError):
        ExplainConnectivityInput.model_validate(
            {
                "source": {"ip": "10.0.0.5"},
                "destination": {"ip": "10.0.0.6"},
                "service": {"protocol": "tcp", "port": 443},
                "bogus": True,
            }
        )


def test_find_object_usage_input_bounds_references() -> None:
    with pytest.raises(ValidationError):
        FindObjectUsageInput.model_validate(
            {"object_type": "address", "identifier": "x", "max_references": 101}
        )


def test_find_object_usage_input_rejects_an_unknown_object_type() -> None:
    with pytest.raises(ValidationError):
        FindObjectUsageInput.model_validate({"object_type": "nat-rule", "identifier": "x"})


async def test_an_invalid_request_is_rejected_before_any_request(router: Any) -> None:
    result = await call_tool("audit_firewall_rules", {"checks": ["disabled"], "bogus": 1})

    assert result.is_error is True
    assert router.calls == []


# -- Discovery and annotations ---------------------------------------------------------


async def tool_map(*, read_only: bool = False) -> dict[str, Any]:
    server = make_server(read_only=read_only)
    return {tool.name: tool for tool in await server.list_tools()}


async def test_the_audit_domain_publishes_exactly_three_tools() -> None:
    tools = await tool_map()

    assert set(tools) == AUDIT_TOOLS


async def test_read_only_mode_still_registers_the_audit_tools() -> None:
    tools = await tool_map(read_only=True)

    assert set(tools) == AUDIT_TOOLS


async def test_audit_tools_carry_read_only_annotations() -> None:
    tools = await tool_map()

    for name in AUDIT_TOOLS:
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.read_only_hint is True
        assert annotations.destructive_hint is None
        assert annotations.idempotent_hint is None


async def test_audit_tool_descriptions_state_their_limits() -> None:
    tools = await tool_map()

    audit = tools["audit_firewall_rules"].description
    assert "notVerifiable" in audit
    assert "never mutates" in audit
    explain = tools["explain_connectivity"].description
    assert "config-analysis" in explain
    assert "NOT a packet test" in explain
    usage = tools["find_object_usage"].description
    assert "no usage endpoint" in usage
    for name in AUDIT_TOOLS:
        assert tools[name].title
        assert tools[name].description


async def test_audit_description_states_the_two_finding_shapes(router: Any) -> None:
    """L3: object-scoped findings carry the object, not the rule, and the description says so."""
    tools = await tool_map()
    description = tools["audit_firewall_rules"].description
    assert "rule-scoped finding" in description
    assert "object- or NAT-scoped finding" in description
    assert "leaves the rule fields null" in description

    # The published shape matches the description: an unused-object finding has no rule.
    install(
        router,
        {
            RULES_V4: page([firewall_rule(name="r1")]),
            ADDR_V4: page([ipv4_address(name="orphan")]),
            SERVICES: page([]),
        },
    )

    result = await call_tool(
        "audit_firewall_rules", {"checks": ["unused-object"], "ip_family": "ipv4"}
    )

    finding = result.structured_content["findings"][0]
    assert finding["check"] == "unused-object"
    assert finding["evidence"]["ruleName"] is None
    assert finding["evidence"]["ruleId"] is None
    assert finding["evidence"]["position"] is None
    assert finding["evidence"]["objectName"] == "orphan"
