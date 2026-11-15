"""Contract, model, discovery and read-only tests for the firewall-rule tools (#27).

Every HTTP interaction runs against RESPX: no firewall, no network and no real credential.
The tests prove, per operation, the exact method, path, query, headers, content type, body
and status handling; they prove the model contract (closed inputs, explicit ``enabled``,
``position`` and WAF exclusion); and they prove the registry (16 tools, the four mutation
composites absent in read-only mode, no bulk delete).

The last group cross-checks the models against ``firewall_config_openapi.yaml`` so a typo
in a field name cannot silently diverge from the audited contract.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, get_args

import httpx
import pytest
import respx
import yaml
from mcp import Client
from pydantic import ValidationError

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.models.common import Pages
from sophos_firewall_mcp.models.firewall import (
    AnySelection,
    CreateFirewallRuleIpv4Input,
    CreateFirewallRuleIpv6Input,
    DscpMarking,
    FirewallRuleIpv4Output,
    FirewallRuleIpv6Output,
    Ipv4Networks,
    ListFirewallRulesInput,
    ListFirewallRulesIpv4Output,
    MoveFirewallRuleInput,
    ObjectReference,
    UpdateFirewallRuleIpv4Input,
    UpdateFirewallRuleIpv6Input,
    ZoneReference,
    validate_object_name_or_id,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.firewall_rules import register_firewall_tools

HOST = "192.0.2.10"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
SPEC_PATH = Path(__file__).resolve().parents[1] / "firewall_config_openapi.yaml"

UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

IPV4_COLLECTION = f"{BASE}/firewall/rules/ipv4"
IPV6_COLLECTION = f"{BASE}/firewall/rules/ipv6"
IPV4_ITEM = f"{BASE}/firewall/rules/ipv4/allow-lan-to-wan"
IPV6_ITEM = f"{BASE}/firewall/rules/ipv6/allow-lan-to-wan-v6"

READ_TOOLS = {
    "firewall_rule_list_ipv4",
    "firewall_rule_list_ipv6",
    "firewall_rule_get_ipv4",
    "firewall_rule_get_ipv6",
}

MUTATION_TOOLS = {
    "firewall_rule_create_ipv4",
    "firewall_rule_create_ipv6",
    "firewall_rule_update_ipv4",
    "firewall_rule_update_ipv6",
    "firewall_rule_delete_ipv4",
    "firewall_rule_delete_ipv6",
    "firewall_rule_move_ipv4",
    "firewall_rule_move_ipv6",
    "firewall_rule_set_enabled_ipv4",
    "firewall_rule_set_enabled_ipv6",
    "firewall_rule_clone_ipv4",
    "firewall_rule_clone_ipv6",
}

ALL_TOOLS = READ_TOOLS | MUTATION_TOOLS

#: The minimal valid create request used by several tests.
MINIMAL_CREATE: dict[str, Any] = {
    "name": "allow-lan-to-wan",
    "sourceZones": {"any": True},
    "destinationZones": {"any": True},
    "sourceNetworks": {"any": True},
    "destinationNetworks": {"any": True},
    "servicesOrGroups": {"any": True},
    "position": "bottom",
}


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
    return create_server(make_settings(read_only_mode=read_only), domains=[register_firewall_tools])


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


async def call(server: Any, name: str, request: dict[str, Any]) -> Any:
    async with Client(server) as client:
        return await client.call_tool(name, {"request": request})


def body_of(route: Any) -> dict[str, Any]:
    return json.loads(route.calls.last.request.content)


def query_of(route: Any) -> dict[str, str]:
    return dict(route.calls.last.request.url.params.multi_items())


def ipv4_rule(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": UUID,
        "name": "allow-lan-to-wan",
        "description": "Allow LAN to WAN",
        "ruleType": "firewall",
        "enabled": False,
        "action": "accept",
        "sourceZones": {"zones": [{"name": "lan"}]},
        "destinationZones": {"any": True},
        "sourceNetworks": {"ipv4Addresses": [{"name": "LAN-10.0.0.0/8"}]},
        "destinationNetworks": {"any": True},
        "servicesOrGroups": {"services": [{"name": "HTTP"}]},
        "logTraffic": True,
        "schedule": {"name": "All The Time"},
        "createdAt": "2026-11-15T10:00:00.000Z",
        "updatedAt": "2026-11-15T10:05:00.000Z",
    }
    payload.update(overrides)
    return payload


def ipv6_rule(**overrides: Any) -> dict[str, Any]:
    payload = ipv4_rule(
        name="allow-lan-to-wan-v6",
        sourceNetworks={"ipv6Addresses": [{"name": "2001:db8::/32"}]},
        destinationNetworks={"ipv6Groups": [{"name": "WAN-IPV6"}]},
    )
    payload.update(overrides)
    return payload


def page(items: list[dict[str, Any]], **pages: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {"current": 1, "size": 50, "maxSize": 100}
    metadata.update(pages)
    return {"items": items, "pages": metadata}


# -- List ------------------------------------------------------------------------------


async def test_list_ipv4_contract(router: Any) -> None:
    route = router.get(IPV4_COLLECTION).mock(
        return_value=httpx.Response(200, json=page([ipv4_rule()]))
    )

    result = await call(
        make_server(),
        "firewall_rule_list_ipv4",
        {"page": 2, "pageSize": 10, "pageTotal": True, "nameContains": "allow"},
    )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert str(request.url).startswith(f"{IPV4_COLLECTION}?")
    assert query_of(route) == {
        "nameContains": "allow",
        "page": "2",
        "pageSize": "10",
        "pageTotal": "true",
    }
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["accept"] == "application/json"
    assert "content-type" not in request.headers
    assert request.content == b""

    output = result.structured_content
    assert output is not None
    assert [item["name"] for item in output["items"]] == ["allow-lan-to-wan"]
    assert output["items"][0]["ipFamily"] == "ipv4"
    assert output["items"][0]["enabled"] is False
    assert {key: value for key, value in output["pages"].items() if value is not None} == {
        "current": 1,
        "size": 50,
        "maxSize": 100,
    }
    assert output["wafRulesSkipped"] == 0


async def test_list_ipv6_contract(router: Any) -> None:
    route = router.get(IPV6_COLLECTION).mock(
        return_value=httpx.Response(200, json=page([ipv6_rule()], current=3, total=7))
    )

    result = await call(make_server(), "firewall_rule_list_ipv6", {"page": 3, "pageTotal": True})

    assert result.is_error is False
    assert query_of(route) == {"page": "3", "pageSize": "50", "pageTotal": "true"}
    output = result.structured_content
    assert output is not None
    assert output["items"][0]["ipFamily"] == "ipv6"
    assert output["items"][0]["sourceNetworks"]["ipv6Addresses"] == [{"name": "2001:db8::/32"}]
    assert output["pages"]["current"] == 3
    assert output["pages"]["total"] == 7
    assert "wafRulesSkipped" not in output


async def test_list_applies_name_not_equals_filter(router: Any) -> None:
    route = router.get(IPV4_COLLECTION).mock(return_value=httpx.Response(200, json=page([])))

    result = await call(make_server(), "firewall_rule_list_ipv4", {"nameNotEquals": "blocked"})

    assert result.is_error is False
    assert query_of(route) == {
        "nameNotEquals": "blocked",
        "page": "1",
        "pageSize": "50",
        "pageTotal": "false",
    }


async def test_list_rejects_both_name_filters_before_any_request(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_list_ipv4",
        {"nameContains": "a", "nameNotEquals": "b"},
    )

    assert result.is_error is True
    assert "mutually exclusive" in result.content[0].text
    assert router.calls == []


async def test_list_rejects_a_page_size_above_the_live_limit(router: Any) -> None:
    result = await call(make_server(), "firewall_rule_list_ipv4", {"pageSize": 101})

    assert result.is_error is True
    assert router.calls == []


async def test_list_ipv4_skips_waf_rules_and_reports_the_count(router: Any) -> None:
    router.get(IPV4_COLLECTION).mock(
        return_value=httpx.Response(
            200,
            json=page(
                [
                    ipv4_rule(),
                    ipv4_rule(name="waf-rule", ruleType="waf", wafRule={"name": "waf"}),
                ]
            ),
        )
    )

    result = await call(make_server(), "firewall_rule_list_ipv4", {})

    assert result.is_error is False
    output = result.structured_content
    assert output is not None
    assert [item["name"] for item in output["items"]] == ["allow-lan-to-wan"]
    assert output["wafRulesSkipped"] == 1


async def test_list_preserves_a_missing_pages_object(router: Any) -> None:
    router.get(IPV4_COLLECTION).mock(
        return_value=httpx.Response(200, json={"items": [ipv4_rule()]})
    )

    result = await call(make_server(), "firewall_rule_list_ipv4", {})

    assert result.is_error is False
    assert result.structured_content["pages"] is None


async def test_list_rejects_a_malformed_rule_payload(router: Any) -> None:
    router.get(IPV4_COLLECTION).mock(
        return_value=httpx.Response(200, json=page([{"ruleType": "firewall"}]))
    )

    result = await call(make_server(), "firewall_rule_list_ipv4", {})

    assert result.is_error is True
    assert "does not match the contract" in result.content[0].text


async def test_list_maps_401_to_a_sanitized_auth_tool_error(router: Any) -> None:
    router.get(IPV4_COLLECTION).mock(
        return_value=httpx.Response(401, json={"error": "unauthenticated"})
    )

    result = await call(make_server(), "firewall_rule_list_ipv4", {})

    assert result.is_error is True
    text = result.content[0].text
    assert "not allowed" in text
    assert "unauthenticated" in text
    assert KEY not in text


# -- Get -------------------------------------------------------------------------------


async def test_get_ipv4_contract_encodes_the_name(router: Any) -> None:
    route = router.get(f"{BASE}/firewall/rules/ipv4/My%20Rule").mock(
        return_value=httpx.Response(200, json=ipv4_rule(name="My Rule"))
    )

    result = await call(make_server(), "firewall_rule_get_ipv4", {"idOrName": "My Rule"})

    assert result.is_error is False
    assert route.calls.last.request.method == "GET"
    assert str(route.calls.last.request.url) == f"{BASE}/firewall/rules/ipv4/My%20Rule"
    output = result.structured_content
    assert output is not None
    assert output["name"] == "My Rule"
    assert output["id"] == UUID
    assert output["sourceZones"] == {"any": False, "zones": [{"name": "lan"}]}
    assert output["destinationZones"] == {"any": True, "zones": []}
    assert output["createdAt"].startswith("2026-11-15T10:00:00")


async def test_get_ipv6_contract(router: Any) -> None:
    route = router.get(IPV6_ITEM).mock(return_value=httpx.Response(200, json=ipv6_rule()))

    result = await call(
        make_server(), "firewall_rule_get_ipv6", {"idOrName": "allow-lan-to-wan-v6"}
    )

    assert result.is_error is False
    assert route.calls.last.request.method == "GET"
    assert result.structured_content["ipFamily"] == "ipv6"


async def test_get_accepts_a_uuid_identifier(router: Any) -> None:
    route = router.get(f"{BASE}/firewall/rules/ipv4/{UUID}").mock(
        return_value=httpx.Response(200, json=ipv4_rule())
    )

    result = await call(make_server(), "firewall_rule_get_ipv4", {"idOrName": UUID})

    assert result.is_error is False
    assert str(route.calls.last.request.url) == f"{BASE}/firewall/rules/ipv4/{UUID}"


async def test_get_rejects_a_waf_rule(router: Any) -> None:
    router.get(IPV4_ITEM).mock(return_value=httpx.Response(200, json=ipv4_rule(ruleType="waf")))

    result = await call(make_server(), "firewall_rule_get_ipv4", {"idOrName": "allow-lan-to-wan"})

    assert result.is_error is True
    assert "WAF rules are out of scope" in result.content[0].text


async def test_get_maps_404_to_a_sanitized_tool_error(router: Any) -> None:
    router.get(f"{BASE}/firewall/rules/ipv4/missing").mock(
        return_value=httpx.Response(
            404, json={"error": "resourceNotFound", "message": "Resource not found."}
        )
    )

    result = await call(make_server(), "firewall_rule_get_ipv4", {"idOrName": "missing"})

    assert result.is_error is True
    text = result.content[0].text
    assert "does not exist" in text
    assert "resourceNotFound" in text
    assert KEY not in text


# -- Create ----------------------------------------------------------------------------


async def test_create_ipv4_contract_always_sends_enabled_and_position(router: Any) -> None:
    route = router.post(IPV4_COLLECTION).mock(return_value=httpx.Response(201, json=ipv4_rule()))

    result = await call(make_server(), "firewall_rule_create_ipv4", dict(MINIMAL_CREATE))

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    body = body_of(route)
    assert body["enabled"] is False
    assert body["ruleType"] == "firewall"
    assert body["position"] == "bottom"
    assert body["action"] == "accept"
    assert body["sourceZones"] == {"any": True}
    assert "id" not in body
    assert "createdAt" not in body
    assert "updatedAt" not in body
    assert result.structured_content["enabled"] is False


async def test_create_ipv4_returns_the_applied_enabled_state(router: Any) -> None:
    router.post(IPV4_COLLECTION).mock(
        return_value=httpx.Response(201, json=ipv4_rule(enabled=True))
    )

    result = await call(
        make_server(), "firewall_rule_create_ipv4", {**MINIMAL_CREATE, "enabled": True}
    )

    assert result.is_error is False
    assert result.structured_content["enabled"] is True


async def test_create_ipv6_contract(router: Any) -> None:
    route = router.post(IPV6_COLLECTION).mock(return_value=httpx.Response(201, json=ipv6_rule()))

    result = await call(
        make_server(),
        "firewall_rule_create_ipv6",
        {
            **MINIMAL_CREATE,
            "name": "allow-lan-to-wan-v6",
            "sourceNetworks": {"ipv6Addresses": [{"name": "2001:db8::/32"}]},
            "destinationNetworks": {"any": True},
            "position": "top",
        },
    )

    assert result.is_error is False
    assert route.calls.last.request.method == "POST"
    body = body_of(route)
    assert body["enabled"] is False
    assert body["position"] == "top"
    assert body["sourceNetworks"] == {"ipv6Addresses": [{"name": "2001:db8::/32"}]}
    assert result.structured_content["ipFamily"] == "ipv6"


async def test_create_relative_position_sends_the_anchor(router: Any) -> None:
    route = router.post(IPV4_COLLECTION).mock(return_value=httpx.Response(201, json=ipv4_rule()))

    result = await call(
        make_server(),
        "firewall_rule_create_ipv4",
        {**MINIMAL_CREATE, "position": "after", "referenceItem": {"name": "allow-dns"}},
    )

    assert result.is_error is False
    assert body_of(route)["referenceItem"] == {"name": "allow-dns"}


async def test_create_rejects_the_waf_variant_before_any_request(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_create_ipv4",
        {**MINIMAL_CREATE, "ruleType": "waf"},
    )

    assert result.is_error is True
    assert router.calls == []


async def test_create_requires_position_before_any_request(router: Any) -> None:
    request = {key: value for key, value in MINIMAL_CREATE.items() if key != "position"}

    result = await call(make_server(), "firewall_rule_create_ipv4", request)

    assert result.is_error is True
    assert router.calls == []


async def test_create_relative_position_requires_an_anchor(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_create_ipv4",
        {**MINIMAL_CREATE, "position": "before"},
    )

    assert result.is_error is True
    assert "referenceItem" in result.content[0].text
    assert router.calls == []


async def test_create_rejects_an_unknown_member(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_create_ipv4",
        {**MINIMAL_CREATE, "sourceZone": {"any": True}},
    )

    assert result.is_error is True
    assert router.calls == []


async def test_create_maps_409_to_a_conflict_tool_error(router: Any) -> None:
    router.post(IPV4_COLLECTION).mock(
        return_value=httpx.Response(
            409, json={"error": "resourceConflict", "message": "Conflicts."}
        )
    )

    result = await call(make_server(), "firewall_rule_create_ipv4", dict(MINIMAL_CREATE))

    assert result.is_error is True
    text = result.content[0].text
    assert "conflicts with the current firewall state" in text
    assert "resourceConflict" in text


# -- Update ----------------------------------------------------------------------------


async def test_update_ipv4_sends_only_the_changed_members(router: Any) -> None:
    route = router.patch(IPV4_ITEM).mock(
        return_value=httpx.Response(200, json=ipv4_rule(enabled=True))
    )

    result = await call(
        make_server(),
        "firewall_rule_update_ipv4",
        {"idOrName": "allow-lan-to-wan", "enabled": True},
    )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "PATCH"
    assert request.headers["content-type"] == "application/json"
    assert body_of(route) == {"enabled": True}
    assert result.structured_content["enabled"] is True


async def test_update_ipv6_sends_only_the_changed_members(router: Any) -> None:
    route = router.patch(IPV6_ITEM).mock(
        return_value=httpx.Response(200, json=ipv6_rule(description="updated"))
    )

    result = await call(
        make_server(),
        "firewall_rule_update_ipv6",
        {
            "idOrName": "allow-lan-to-wan-v6",
            "description": "updated",
            "sourceNetworks": {"ipv6Groups": [{"name": "LAN-IPV6"}]},
        },
    )

    assert result.is_error is False
    assert body_of(route) == {
        "description": "updated",
        "sourceNetworks": {"ipv6Groups": [{"name": "LAN-IPV6"}]},
    }
    assert result.structured_content["ipFamily"] == "ipv6"


async def test_update_sends_an_explicit_null_to_remove_an_optional_member(router: Any) -> None:
    route = router.patch(IPV4_ITEM).mock(
        return_value=httpx.Response(200, json=ipv4_rule(description=None))
    )

    result = await call(
        make_server(),
        "firewall_rule_update_ipv4",
        {"idOrName": "allow-lan-to-wan", "description": None},
    )

    assert result.is_error is False
    assert body_of(route) == {"description": None}


async def test_update_rejects_null_for_a_member_that_cannot_be_removed(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_update_ipv4",
        {"idOrName": "allow-lan-to-wan", "enabled": None},
    )

    assert result.is_error is True
    assert "cannot be null" in result.content[0].text
    assert router.calls == []


async def test_update_rejects_an_empty_patch(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_update_ipv4",
        {"idOrName": "allow-lan-to-wan"},
    )

    assert result.is_error is True
    assert "no fields to update" in result.content[0].text
    assert router.calls == []


async def test_update_does_not_send_the_identifier_in_the_body(router: Any) -> None:
    route = router.patch(IPV4_ITEM).mock(return_value=httpx.Response(200, json=ipv4_rule()))

    await call(
        make_server(),
        "firewall_rule_update_ipv4",
        {"idOrName": "allow-lan-to-wan", "logTraffic": False},
    )

    assert "idOrName" not in body_of(route)


# -- Delete ----------------------------------------------------------------------------


async def test_delete_ipv4_contract(router: Any) -> None:
    route = router.delete(IPV4_ITEM).mock(return_value=httpx.Response(200, json={"deleted": True}))

    result = await call(
        make_server(), "firewall_rule_delete_ipv4", {"idOrName": "allow-lan-to-wan"}
    )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "DELETE"
    assert "content-type" not in request.headers
    assert request.content == b""
    assert result.structured_content == {"deleted": True, "idOrName": "allow-lan-to-wan"}


async def test_delete_ipv6_contract(router: Any) -> None:
    route = router.delete(IPV6_ITEM).mock(return_value=httpx.Response(200, json={"deleted": True}))

    result = await call(
        make_server(), "firewall_rule_delete_ipv6", {"idOrName": "allow-lan-to-wan-v6"}
    )

    assert result.is_error is False
    assert route.calls.last.request.method == "DELETE"


async def test_delete_maps_404_to_a_sanitized_tool_error(router: Any) -> None:
    router.delete(f"{BASE}/firewall/rules/ipv4/missing").mock(
        return_value=httpx.Response(404, json={"error": "resourceNotFound"})
    )

    result = await call(make_server(), "firewall_rule_delete_ipv4", {"idOrName": "missing"})

    assert result.is_error is True
    assert "does not exist" in result.content[0].text
    assert KEY not in result.content[0].text


# -- Move ------------------------------------------------------------------------------


async def test_move_ipv4_contract(router: Any) -> None:
    route = router.post(f"{BASE}/firewall/rules/ipv4/move").mock(
        return_value=httpx.Response(200, json={})
    )

    result = await call(
        make_server(),
        "firewall_rule_move_ipv4",
        {
            "name": "allow-lan-to-wan",
            "position": "after",
            "referenceItem": {"name": "allow-dns"},
        },
    )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert body_of(route) == {
        "name": "allow-lan-to-wan",
        "position": "after",
        "referenceItem": {"name": "allow-dns"},
    }
    assert result.structured_content == {
        "moved": True,
        "name": "allow-lan-to-wan",
        "position": "after",
        "referenceItem": {"name": "allow-dns"},
    }


async def test_move_ipv6_contract(router: Any) -> None:
    route = router.post(f"{BASE}/firewall/rules/ipv6/move").mock(
        return_value=httpx.Response(200, json={})
    )

    result = await call(
        make_server(),
        "firewall_rule_move_ipv6",
        {"name": "allow-lan-to-wan-v6", "position": "bottom"},
    )

    assert result.is_error is False
    assert body_of(route) == {"name": "allow-lan-to-wan-v6", "position": "bottom"}


async def test_move_requires_a_name_and_rejects_id_or_name(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_move_ipv4",
        {"idOrName": "allow-lan-to-wan", "position": "top"},
    )

    assert result.is_error is True
    assert router.calls == []


async def test_move_relative_position_requires_an_anchor(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_move_ipv4",
        {"name": "allow-lan-to-wan", "position": "after"},
    )

    assert result.is_error is True
    assert "referenceItem" in result.content[0].text
    assert router.calls == []


# -- Composite: set_enabled ------------------------------------------------------------


async def test_set_enabled_ipv4_patches_only_enabled(router: Any) -> None:
    route = router.patch(IPV4_ITEM).mock(
        return_value=httpx.Response(200, json=ipv4_rule(enabled=False))
    )

    result = await call(
        make_server(),
        "firewall_rule_set_enabled_ipv4",
        {"idOrName": "allow-lan-to-wan", "enabled": False},
    )

    assert result.is_error is False
    assert route.calls.last.request.method == "PATCH"
    assert body_of(route) == {"enabled": False}
    assert result.structured_content["enabled"] is False


async def test_set_enabled_ipv6_patches_only_enabled(router: Any) -> None:
    route = router.patch(IPV6_ITEM).mock(
        return_value=httpx.Response(200, json=ipv6_rule(enabled=True))
    )

    result = await call(
        make_server(),
        "firewall_rule_set_enabled_ipv6",
        {"idOrName": "allow-lan-to-wan-v6", "enabled": True},
    )

    assert result.is_error is False
    assert body_of(route) == {"enabled": True}
    assert result.structured_content["enabled"] is True


async def test_set_enabled_requires_an_explicit_target_state(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_set_enabled_ipv4",
        {"idOrName": "allow-lan-to-wan"},
    )

    assert result.is_error is True
    assert router.calls == []


# -- Composite: clone ------------------------------------------------------------------


async def test_clone_ipv4_reads_then_creates_without_inheriting_enabled(router: Any) -> None:
    get_route = router.get(IPV4_ITEM).mock(
        return_value=httpx.Response(200, json=ipv4_rule(enabled=True))
    )
    post_route = router.post(IPV4_COLLECTION).mock(
        return_value=httpx.Response(
            201, json=ipv4_rule(name="allow-lan-to-wan-copy", enabled=False)
        )
    )

    result = await call(
        make_server(),
        "firewall_rule_clone_ipv4",
        {
            "source": "allow-lan-to-wan",
            "name": "allow-lan-to-wan-copy",
            "position": "bottom",
        },
    )

    assert result.is_error is False
    assert get_route.called is True
    assert post_route.called is True
    body = body_of(post_route)
    assert body["name"] == "allow-lan-to-wan-copy"
    assert body["enabled"] is False
    assert body["position"] == "bottom"
    assert body["ruleType"] == "firewall"
    assert body["sourceZones"] == {"zones": [{"name": "lan"}]}
    assert body["servicesOrGroups"] == {"services": [{"name": "HTTP"}]}
    for read_only in ("id", "createdAt", "updatedAt"):
        assert read_only not in body
    assert result.structured_content["name"] == "allow-lan-to-wan-copy"


async def test_clone_ipv6_reads_then_creates(router: Any) -> None:
    router.get(IPV6_ITEM).mock(return_value=httpx.Response(200, json=ipv6_rule()))
    post_route = router.post(IPV6_COLLECTION).mock(
        return_value=httpx.Response(201, json=ipv6_rule(name="copy-v6"))
    )

    result = await call(
        make_server(),
        "firewall_rule_clone_ipv6",
        {"source": "allow-lan-to-wan-v6", "name": "copy-v6", "position": "top"},
    )

    assert result.is_error is False
    body = body_of(post_route)
    assert body["name"] == "copy-v6"
    assert body["enabled"] is False
    assert body["sourceNetworks"] == {"ipv6Addresses": [{"name": "2001:db8::/32"}]}
    assert result.structured_content["ipFamily"] == "ipv6"


async def test_clone_rejects_a_waf_source_without_creating(router: Any) -> None:
    get_route = router.get(IPV4_ITEM).mock(
        return_value=httpx.Response(200, json=ipv4_rule(ruleType="waf"))
    )
    post_route = router.post(IPV4_COLLECTION).mock(
        return_value=httpx.Response(201, json=ipv4_rule())
    )

    result = await call(
        make_server(),
        "firewall_rule_clone_ipv4",
        {"source": "allow-lan-to-wan", "name": "copy", "position": "bottom"},
    )

    assert result.is_error is True
    assert "WAF rules are out of scope" in result.content[0].text
    assert get_route.called is True
    assert post_route.called is False


async def test_clone_requires_a_position(router: Any) -> None:
    result = await call(
        make_server(),
        "firewall_rule_clone_ipv4",
        {"source": "allow-lan-to-wan", "name": "copy"},
    )

    assert result.is_error is True
    assert router.calls == []


# -- Registry, annotations and schemas -------------------------------------------------


async def test_write_mode_registers_all_sixteen_tools() -> None:
    server = make_server()

    names = {tool.name for tool in await server.list_tools()}

    assert names == ALL_TOOLS
    assert len(names) == 16


async def test_read_only_mode_registers_only_the_four_read_tools() -> None:
    server = make_server(read_only=True)

    names = {tool.name for tool in await server.list_tools()}

    assert names == READ_TOOLS


async def test_no_bulk_delete_tool_is_registered() -> None:
    server = make_server()

    names = {tool.name for tool in await server.list_tools()}

    assert not any("bulk" in name for name in names)
    assert not any("group" in name for name in names)


async def test_every_tool_description_names_its_operation_id() -> None:
    server = make_server()
    tools = {tool.name: tool for tool in await server.list_tools()}
    expected = {
        "firewall_rule_list_ipv4": "getAllFirewallRulesIpv4",
        "firewall_rule_list_ipv6": "getAllFirewallRulesIpv6",
        "firewall_rule_get_ipv4": "getFirewallRuleIpv4",
        "firewall_rule_get_ipv6": "getFirewallRuleIpv6",
        "firewall_rule_create_ipv4": "createFirewallRuleIpv4",
        "firewall_rule_create_ipv6": "createFirewallRuleIpv6",
        "firewall_rule_update_ipv4": "updateFirewallRuleIpv4",
        "firewall_rule_update_ipv6": "updateFirewallRuleIpv6",
        "firewall_rule_delete_ipv4": "deleteFirewallRuleIpv4",
        "firewall_rule_delete_ipv6": "deleteFirewallRuleIpv6",
        "firewall_rule_move_ipv4": "moveFirewallRuleIpv4",
        "firewall_rule_move_ipv6": "moveFirewallRuleIpv6",
        "firewall_rule_set_enabled_ipv4": "updateFirewallRuleIpv4",
        "firewall_rule_set_enabled_ipv6": "updateFirewallRuleIpv6",
        "firewall_rule_clone_ipv4": "getFirewallRuleIpv4",
        "firewall_rule_clone_ipv6": "getFirewallRuleIpv6",
    }

    for name, operation_id in expected.items():
        assert operation_id in tools[name].description
        assert tools[name].description.strip() != ""


async def test_read_tools_carry_no_write_hints() -> None:
    server = make_server()
    tools = {tool.name: tool for tool in await server.list_tools()}

    for name in READ_TOOLS:
        wire = tools[name].annotations.model_dump(by_alias=True, exclude_none=True)
        assert wire["readOnlyHint"] is True
        assert wire["openWorldHint"] is False
        assert "destructiveHint" not in wire
        assert "idempotentHint" not in wire


@pytest.mark.parametrize(
    ("name", "destructive", "idempotent"),
    [
        ("firewall_rule_create_ipv4", False, False),
        ("firewall_rule_create_ipv6", False, False),
        ("firewall_rule_update_ipv4", True, True),
        ("firewall_rule_update_ipv6", True, True),
        ("firewall_rule_delete_ipv4", True, True),
        ("firewall_rule_delete_ipv6", True, True),
        ("firewall_rule_move_ipv4", True, True),
        ("firewall_rule_move_ipv6", True, True),
        ("firewall_rule_set_enabled_ipv4", True, True),
        ("firewall_rule_set_enabled_ipv6", True, True),
        ("firewall_rule_clone_ipv4", False, False),
        ("firewall_rule_clone_ipv6", False, False),
    ],
)
async def test_mutation_tools_declare_their_risk_and_idempotence(
    name: str, destructive: bool, idempotent: bool
) -> None:
    server = make_server()
    tools = {tool.name: tool for tool in await server.list_tools()}

    wire = tools[name].annotations.model_dump(by_alias=True, exclude_none=True)

    assert wire["readOnlyHint"] is False
    assert wire["destructiveHint"] is destructive
    assert wire["idempotentHint"] is idempotent
    assert wire["openWorldHint"] is False


async def test_create_input_schema_is_closed_and_requires_position() -> None:
    server = make_server()
    tool = next(
        tool for tool in await server.list_tools() if tool.name == "firewall_rule_create_ipv4"
    )

    schema = tool.input_schema["$defs"]["CreateFirewallRuleIpv4Input"]

    assert schema["additionalProperties"] is False
    assert "position" in schema["required"]
    assert schema["properties"]["enabled"]["default"] is False
    assert schema["properties"]["ruleType"]["const"] == "firewall"
    assert schema["properties"]["position"]["enum"] == ["after", "before", "bottom", "top"]


async def test_output_schemas_are_object_rooted_and_typed() -> None:
    server = make_server()
    tools = {tool.name: tool for tool in await server.list_tools()}

    for name in ("firewall_rule_get_ipv4", "firewall_rule_get_ipv6"):
        output = tools[name].output_schema
        assert output is not None
        assert output["type"] == "object"
        assert "name" in output["required"]
        assert "ipFamily" in output["properties"]

    listing = tools["firewall_rule_list_ipv4"].output_schema
    assert listing is not None
    assert listing["type"] == "object"
    assert "items" in listing["properties"]
    assert "wafRulesSkipped" in listing["properties"]


# -- Model contract --------------------------------------------------------------------


def test_create_defaults_enabled_to_false_and_dumps_it_explicitly() -> None:
    model = CreateFirewallRuleIpv4Input(**MINIMAL_CREATE)

    assert model.enabled is False
    assert model.model_dump(exclude_none=True)["enabled"] is False


def test_create_rejects_the_waf_rule_type() -> None:
    with pytest.raises(ValidationError):
        CreateFirewallRuleIpv4Input(**{**MINIMAL_CREATE, "ruleType": "waf"})


def test_create_requires_a_position() -> None:
    request = {key: value for key, value in MINIMAL_CREATE.items() if key != "position"}

    with pytest.raises(ValidationError):
        CreateFirewallRuleIpv4Input(**request)


def test_create_model_requires_an_anchor_for_relative_position() -> None:
    with pytest.raises(ValidationError, match="referenceItem"):
        CreateFirewallRuleIpv4Input(**{**MINIMAL_CREATE, "position": "after"})


def test_create_model_rejects_an_unknown_member() -> None:
    with pytest.raises(ValidationError):
        CreateFirewallRuleIpv4Input(**{**MINIMAL_CREATE, "sourceZone": {"any": True}})


def test_create_rejects_an_empty_network_selection() -> None:
    with pytest.raises(ValidationError):
        CreateFirewallRuleIpv4Input(**{**MINIMAL_CREATE, "sourceNetworks": {"ipv4Addresses": []}})


def test_ipv6_create_rejects_an_ipv4_network_member() -> None:
    with pytest.raises(ValidationError):
        CreateFirewallRuleIpv6Input(
            **{
                **MINIMAL_CREATE,
                "name": "v6-rule",
                "sourceNetworks": {"ipv4Addresses": [{"name": "LAN"}]},
            }
        )


def test_zone_reference_enforces_the_contract_pattern() -> None:
    assert ZoneReference(name="lan").name == "lan"
    with pytest.raises(ValidationError):
        ZoneReference(name="0lan")
    with pytest.raises(ValidationError):
        ZoneReference(name="lan-1")


def test_object_reference_rejects_an_empty_name() -> None:
    with pytest.raises(ValidationError):
        ObjectReference(name="")


def test_object_name_or_id_accepts_a_uuid_and_a_name() -> None:
    assert validate_object_name_or_id(UUID) == UUID
    assert validate_object_name_or_id("allow-lan-to-wan") == "allow-lan-to-wan"


@pytest.mark.parametrize("value", ["a/b", "a\\b", "..", "bad,name", " leading"])
def test_object_name_or_id_rejects_unsafe_identifiers(value: str) -> None:
    with pytest.raises(ValueError):
        validate_object_name_or_id(value)


def test_list_input_validates_the_page_bounds() -> None:
    with pytest.raises(ValidationError):
        ListFirewallRulesInput(page=0)
    with pytest.raises(ValidationError):
        ListFirewallRulesInput(pageSize=0)
    with pytest.raises(ValidationError):
        ListFirewallRulesInput(pageSize=101)


def test_list_input_rejects_both_name_filters() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        ListFirewallRulesInput(nameContains="a", nameNotEquals="b")


def test_any_selection_rejects_extra_members() -> None:
    assert AnySelection(any=True).any is True
    with pytest.raises(ValidationError):
        AnySelection(any=True, zones=[{"name": "lan"}])


def test_network_selection_requires_at_least_one_member() -> None:
    with pytest.raises(ValidationError):
        Ipv4Networks()


def test_update_model_rejects_null_for_a_member_that_cannot_be_removed() -> None:
    with pytest.raises(ValidationError, match="cannot be null"):
        UpdateFirewallRuleIpv4Input(idOrName="allow-lan-to-wan", action=None)


def test_update_allows_null_for_a_removable_member() -> None:
    model = UpdateFirewallRuleIpv4Input(idOrName="allow-lan-to-wan", description=None)

    assert model.model_dump(exclude_unset=True) == {
        "idOrName": "allow-lan-to-wan",
        "description": None,
    }


def test_update_excludes_members_the_caller_did_not_set() -> None:
    model = UpdateFirewallRuleIpv4Input(idOrName="allow-lan-to-wan", enabled=True)

    assert model.model_dump(exclude_unset=True, exclude={"idOrName"}) == {"enabled": True}


def test_move_input_requires_a_name() -> None:
    with pytest.raises(ValidationError):
        MoveFirewallRuleInput(position="top")
    assert MoveFirewallRuleInput(name="allow-lan-to-wan", position="top").name == (
        "allow-lan-to-wan"
    )


def test_output_projects_any_and_selected_matches() -> None:
    rule = FirewallRuleIpv4Output.model_validate(ipv4_rule())

    assert rule.sourceZones is not None
    assert rule.sourceZones.any is False
    assert [zone.name for zone in rule.sourceZones.zones] == ["lan"]
    assert rule.destinationZones is not None
    assert rule.destinationZones.any is True
    assert rule.destinationZones.zones == []
    assert rule.sourceNetworks is not None
    assert [address.name for address in rule.sourceNetworks.ipv4Addresses] == ["LAN-10.0.0.0/8"]


def test_output_ignores_unknown_server_members() -> None:
    rule = FirewallRuleIpv4Output.model_validate(ipv4_rule(unexpectedMember={"x": 1}))

    assert rule.name == "allow-lan-to-wan"
    assert "unexpectedMember" not in rule.model_dump()


def test_ipv6_output_keeps_the_ipv6_match_members() -> None:
    rule = FirewallRuleIpv6Output.model_validate(ipv6_rule())

    assert rule.ipFamily == "ipv6"
    assert rule.sourceNetworks is not None
    assert [address.name for address in rule.sourceNetworks.ipv6Addresses] == ["2001:db8::/32"]
    assert rule.destinationNetworks is not None
    assert [group.name for group in rule.destinationNetworks.ipv6Groups] == ["WAN-IPV6"]


def test_output_enabled_is_none_only_when_the_appliance_omits_it() -> None:
    payload = ipv4_rule()
    payload.pop("enabled")

    assert FirewallRuleIpv4Output.model_validate(payload).enabled is None


def test_list_output_preserves_the_pages_metadata() -> None:
    output = ListFirewallRulesIpv4Output(
        items=[],
        pages=Pages(current=2, size=10, maxSize=100, total=47, items=10),
        wafRulesSkipped=3,
    )

    assert output.pages is not None
    assert output.pages.total == 47
    assert output.wafRulesSkipped == 3
    assert output.model_dump()["pages"]["maxSize"] == 100


# -- Contract cross-check against the audited OpenAPI document -------------------------


@lru_cache(maxsize=1)
def _spec() -> dict[str, Any]:
    return yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))


def _properties(schema: dict[str, Any]) -> set[str]:
    return set(schema.get("properties", {}))


def _resolve(node: dict[str, Any]) -> dict[str, Any]:
    """Resolve one local ``$ref`` against the audited document."""
    ref = node.get("$ref")
    if ref is None:
        return node
    target: Any = _spec()
    for part in ref.lstrip("#/").split("/"):
        target = target[part]
    return target


def test_create_models_cover_exactly_the_contract_properties() -> None:
    ipv4_schema = _spec()["paths"]["/firewall/rules/ipv4"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    ipv4_variant = _resolve(ipv4_schema["oneOf"][0])
    rule_fields, position_fields = (
        _properties(ipv4_variant["allOf"][0]),
        _properties(ipv4_variant["allOf"][1]),
    )
    assert set(CreateFirewallRuleIpv4Input.model_fields) == rule_fields | position_fields

    ipv6_schema = _spec()["paths"]["/firewall/rules/ipv6"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["allOf"]
    assert set(CreateFirewallRuleIpv6Input.model_fields) == (
        _properties(ipv6_schema[0]) | _properties(ipv6_schema[1])
    )


def test_update_models_cover_exactly_the_contract_properties() -> None:
    for family, model in (
        ("ipv4", UpdateFirewallRuleIpv4Input),
        ("ipv6", UpdateFirewallRuleIpv6Input),
    ):
        schema = _spec()["paths"][f"/firewall/rules/{family}/{{idOrName}}"]["patch"]["requestBody"][
            "content"
        ]["application/json"]["schema"]
        assert set(model.model_fields) == _properties(schema) | {"idOrName"}


def test_list_input_covers_exactly_the_contract_query_parameters() -> None:
    parameters = _spec()["paths"]["/firewall/rules/ipv4"]["get"]["parameters"]

    assert set(ListFirewallRulesInput.model_fields) == {
        parameter["name"] for parameter in parameters
    }


def test_move_input_covers_exactly_the_contract_body() -> None:
    schema = _spec()["paths"]["/firewall/rules/ipv4/move"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]

    assert set(MoveFirewallRuleInput.model_fields) == _properties(schema)


def test_dscp_marking_enum_matches_the_contract() -> None:
    schema = _spec()["paths"]["/firewall/rules/ipv4/{idOrName}"]["patch"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    expected = schema["properties"]["qos"]["allOf"][0]["properties"]["dscpMarking"]["enum"]

    assert list(get_args(DscpMarking)) == expected
