"""Contract tests for the NAT-rule tools (issue #28, IPv4 and IPv6).

Every test runs against RESPX: no firewall, no network, no real credentials, and no write
against the lab. The suite proves, per operation, the exact request (method, path, query,
media type, body), the projected output, the annotations and the read-only filter; it also
proves the model contract (required fields, family separation, oneOf variants, enums,
``sfos-object-name`` validation) and the JSON Merge Patch behavior of update.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from mcp import Client
from pydantic import ValidationError

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.models.common import ListPage, ObjectRef
from sophos_firewall_mcp.models.nat import (
    NatRuleCreateIpv4Input,
    NatRuleCreateIpv6Input,
    NatRuleDeleteInput,
    NatRuleGetInput,
    NatRuleInterfacesInput,
    NatRuleIpv4NetworksInput,
    NatRuleIpv4TranslatedDestinationInput,
    NatRuleIpv4TranslatedSourceInput,
    NatRuleIpv6NetworksInput,
    NatRuleIpv6TranslatedDestinationInput,
    NatRuleIpv6TranslatedSourceInput,
    NatRuleListInput,
    NatRuleMoveInput,
    NatRuleOutput,
    NatRuleServicesInput,
    NatRuleUpdateIpv4Input,
    NatRuleUpdateIpv6Input,
    project_nat_rule,
    project_nat_rule_page,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.nat_rules import (
    IPV4_MOVE_PATH,
    IPV4_RULES_PATH,
    IPV6_MOVE_PATH,
    IPV6_RULES_PATH,
    register_nat_tools,
)

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
IPV4_URL = f"{BASE}{IPV4_RULES_PATH}"
IPV6_URL = f"{BASE}{IPV6_RULES_PATH}"
IPV4_MOVE_URL = f"{BASE}{IPV4_MOVE_PATH}"
IPV6_MOVE_URL = f"{BASE}{IPV6_MOVE_PATH}"
UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

READ_TOOLS = {
    "nat_rule_list",
    "nat_rule_get",
}
MUTATION_TOOLS = {
    "nat_rule_create",
    "nat_rule_update",
    "nat_rule_delete",
    "nat_rule_move",
}
ALL_TOOLS = READ_TOOLS | MUTATION_TOOLS

#: A complete IPv4 NAT-rule payload as the appliance returns it, including an unknown member
#: that must be ignored rather than echoed.
IPV4_RULE: dict[str, Any] = {
    "id": UUID,
    "name": "outbound-masq",
    "description": "Masquerade outbound traffic on WAN.",
    "enabled": True,
    "linkedFirewallRule": {"name": "allow-web"},
    "originalServicesOrGroups": {"any": True},
    "translatedService": {"name": "https"},
    "inboundInterfaces": {"interfaces": [{"name": "Port1"}]},
    "outboundInterfaces": {"interfaces": [{"name": "Port2"}]},
    "loadBalancingMethod": "roundRobin",
    "healthCheck": {
        "rule": {"protocol": "tcp", "port": 443, "interval": 10, "timeout": 3, "retry": 2}
    },
    "originalSourceNetworks": {
        "macAddresses": [{"name": "mac-host"}],
        "ipv4Addresses": [{"name": "lan-subnet"}],
        "ipv4Groups": [{"name": "lan-group"}],
        "fqdnAddresses": [{"name": "app.example.com"}],
        "fqdnGroups": [{"name": "fqdn-group"}],
        "countries": [{"name": "Spain"}],
        "countryGroups": [{"name": "Europe"}],
    },
    "originalDestinationNetworks": {"any": True},
    "translatedSource": {"masq": True},
    "translatedDestination": {"ipv4Address": {"name": "webfarm-pool"}},
    "overrideSnatForOutboundInterfaces": [
        {
            "outboundInterface": {"name": "Port2"},
            "translatedSource": {"ipv4Address": {"name": "port2-egress"}},
        }
    ],
    "createdAt": "2026-11-15T10:00:00Z",
    "updatedAt": "2026-11-15T10:00:00Z",
    "unknownField": "must be ignored",
}

#: A complete IPv6 NAT-rule payload, with the IPv6-only translation shape.
IPV6_RULE: dict[str, Any] = {
    "id": "9b2f0c1e-1111-4a2b-8c3d-0305e82c3301",
    "name": "outbound-masq-v6",
    "enabled": False,
    "originalServicesOrGroups": {"services": [{"name": "https"}]},
    "inboundInterfaces": {"any": True},
    "outboundInterfaces": {"any": True},
    "originalSourceNetworks": {
        "ipv6Addresses": [{"name": "lan-subnet-v6"}],
        "ipv6Groups": [{"name": "lan-group-v6"}],
    },
    "originalDestinationNetworks": {"any": True},
    "translatedSource": {"ipv6Address": {"name": "port2-egress-v6"}},
    "translatedDestination": {"ipv6Address": {"name": "dmz-ipv6-host"}},
    "overrideSnatForOutboundInterfaces": [
        {
            "outboundInterface": {"name": "Port2"},
            "translatedSource": {"ipv6Address": {"name": "port2-egress-v6"}},
        }
    ],
}

#: Minimal valid create body for IPv4 (the six contract-required fields).
MINIMAL_CREATE: dict[str, Any] = {
    "ip_family": "ipv4",
    "name": "outbound-masq",
    "original_services_or_groups": {"any": True},
    "inbound_interfaces": {"any": True},
    "outbound_interfaces": {"any": True},
    "original_source_networks": {"any": True},
    "original_destination_networks": {"any": True},
}


# -- Helpers and fixtures --------------------------------------------------------------


def make_settings(*, read_only: bool = False) -> Settings:
    return Settings(
        host=HOST,
        api_key=KEY,
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=read_only,
    )


def make_server(*, read_only: bool = False):
    return create_server(make_settings(read_only=read_only), domains=[register_nat_tools])


#: The tools that take the required ``ip_family`` argument.
MERGED_TOOLS = {
    "nat_rule_list",
    "nat_rule_get",
    "nat_rule_create",
    "nat_rule_update",
    "nat_rule_delete",
    "nat_rule_move",
}


async def call_tool(
    name: str,
    request: dict[str, Any],
    *,
    read_only: bool = False,
    family: str = "ipv4",
) -> Any:
    """Call one registered tool through the official SDK client."""
    if name in MERGED_TOOLS:
        request = {"ip_family": family, **request}
    async with Client(make_server(read_only=read_only)) as client:
        return await client.call_tool(name, {"request": request})


async def tools_by_name(*, read_only: bool = False) -> dict[str, Any]:
    server = make_server(read_only=read_only)
    return {tool.name: tool for tool in await server.list_tools()}


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


# -- Discovery, annotations and read-only mode ----------------------------------------


async def test_registers_exactly_the_six_curated_tools():
    tools = await tools_by_name()

    assert set(tools) == ALL_TOOLS
    assert len(tools) == 6
    for tool in tools.values():
        assert tool.title
        assert tool.description
        assert tool.input_schema["type"] == "object"
        assert tool.output_schema is not None
        assert tool.output_schema["type"] == "object"


async def test_bulk_delete_is_not_registered():
    tools = await tools_by_name()

    assert not any("bulk" in name for name in tools)
    assert not any("delete_all" in name for name in tools)


async def test_read_tools_have_read_only_annotations():
    tools = await tools_by_name()

    for name in READ_TOOLS:
        annotations = tools[name].annotations.model_dump(by_alias=True, exclude_none=True)
        assert annotations["readOnlyHint"] is True
        assert "destructiveHint" not in annotations
        assert "idempotentHint" not in annotations
        assert annotations["openWorldHint"] is True


async def test_mutation_tools_declare_explicit_hints():
    tools = await tools_by_name()

    for name in MUTATION_TOOLS:
        annotations = tools[name].annotations.model_dump(by_alias=True, exclude_none=True)
        assert annotations["readOnlyHint"] is False
        assert annotations["openWorldHint"] is True
        assert isinstance(annotations["destructiveHint"], bool)
        assert isinstance(annotations["idempotentHint"], bool)

    for name in ("nat_rule_create", "nat_rule_create"):
        annotations = tools[name].annotations.model_dump(by_alias=True, exclude_none=True)
        assert annotations["destructiveHint"] is False
        assert annotations["idempotentHint"] is False

    for name in (
        "nat_rule_update",
        "nat_rule_update",
        "nat_rule_delete",
        "nat_rule_delete",
        "nat_rule_move",
        "nat_rule_move",
    ):
        annotations = tools[name].annotations.model_dump(by_alias=True, exclude_none=True)
        assert annotations["destructiveHint"] is True
        assert annotations["idempotentHint"] is True


async def test_read_only_mode_registers_only_read_tools():
    tools = await tools_by_name(read_only=True)

    assert set(tools) == READ_TOOLS


async def test_input_schema_is_closed_and_excludes_the_context_parameter():
    tools = await tools_by_name()

    for name, tool in tools.items():
        schema = tool.input_schema
        assert set(schema["properties"]) == {"request"}
        assert "ctx" not in schema["properties"]
        model_name = schema["$defs"].keys() - {"Pages", "ListPage"}
        for definition in model_name:
            if "additionalProperties" in schema["$defs"][definition]:
                assert schema["$defs"][definition]["additionalProperties"] is False
        assert name.startswith("nat_rule_")


async def test_list_output_schema_is_a_bounded_page():
    tools = await tools_by_name()

    for name in ("nat_rule_list", "nat_rule_list"):
        schema = tools[name].output_schema
        assert schema["type"] == "object"
        assert set(schema["properties"]) == {"items", "pages"}
        assert schema["properties"]["items"]["type"] == "array"


# -- List ------------------------------------------------------------------------------


async def test_list_ipv4_sends_pagination_and_one_name_filter(router: Any):
    route = router.get(IPV4_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [IPV4_RULE],
                "pages": {"current": 2, "size": 10, "maxSize": 100, "total": 3, "items": 25},
            },
        )
    )

    result = await call_tool(
        "nat_rule_list",
        {"page": 2, "page_size": 10, "page_total": True, "name_contains": "outbound"},
    )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.params["page"] == "2"
    assert request.url.params["pageSize"] == "10"
    assert request.url.params["pageTotal"] == "true"
    assert request.url.params["nameContains"] == "outbound"
    assert "nameNotEquals" not in request.url.params
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert route.call_count == 1

    page = result.structured_content
    assert page["items"][0]["name"] == "outbound-masq"
    assert page["items"][0]["position"] == 11
    assert page["pages"] == {
        "current": 2,
        "size": 10,
        "maxSize": 100,
        "total": 3,
        "items": 25,
    }


async def test_list_ipv6_sends_default_pagination(router: Any):
    route = router.get(IPV6_URL).mock(return_value=httpx.Response(200, json={"items": [IPV6_RULE]}))

    result = await call_tool("nat_rule_list", {}, family="ipv6")

    assert result.is_error is False
    request = route.calls.last.request
    assert request.url.params["page"] == "1"
    assert request.url.params["pageSize"] == "10"
    assert request.url.params["pageTotal"] == "false"
    assert result.structured_content["pages"] is None
    assert result.structured_content["items"][0]["name"] == "outbound-masq-v6"
    assert result.structured_content["items"][0]["position"] == 1


async def test_list_rejects_both_name_filters_without_any_request(router: Any):
    route = router.get(IPV4_URL).mock(return_value=httpx.Response(200, json={"items": []}))

    result = await call_tool("nat_rule_list", {"name_contains": "a", "name_not_equals": "b"})

    assert result.is_error is True
    assert "mutually exclusive" in result.content[0].text
    assert route.call_count == 0


# -- Get -------------------------------------------------------------------------------


async def test_get_ipv4_percent_encodes_the_name(router: Any):
    route = router.get(f"{IPV4_URL}/My%20Rule").mock(
        return_value=httpx.Response(200, json=IPV4_RULE)
    )

    result = await call_tool("nat_rule_get", {"id_or_name": "My Rule"})

    assert result.is_error is False
    assert str(route.calls.last.request.url) == f"{IPV4_URL}/My%20Rule"
    assert result.structured_content["id"] == UUID


async def test_get_ipv6_accepts_a_uuid(router: Any):
    route = router.get(f"{IPV6_URL}/{UUID}").mock(return_value=httpx.Response(200, json=IPV6_RULE))

    result = await call_tool("nat_rule_get", {"id_or_name": UUID}, family="ipv6")

    assert result.is_error is False
    assert str(route.calls.last.request.url) == f"{IPV6_URL}/{UUID}"


# -- Create ----------------------------------------------------------------------------


async def test_create_ipv4_sends_the_contract_body_and_content_type(router: Any):
    route = router.post(IPV4_URL).mock(return_value=httpx.Response(201, json=IPV4_RULE))

    result = await call_tool(
        "nat_rule_create",
        {
            "name": "outbound-masq",
            "description": "Masquerade outbound traffic on WAN.",
            "position": "before",
            "reference_item": {"name": "nat-rule-1"},
            "original_services_or_groups": {"any": True},
            "inbound_interfaces": {"interfaces": [{"name": "Port1"}]},
            "outbound_interfaces": {"interfaces": [{"name": "Port2"}]},
            "original_source_networks": {"any": True},
            "original_destination_networks": {"any": True},
            "translated_source": {"masq": True},
            "translated_destination": {"ipv4_address": {"name": "webfarm-pool"}},
        },
    )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == {
        "name": "outbound-masq",
        "description": "Masquerade outbound traffic on WAN.",
        "enabled": True,
        "position": "before",
        "referenceItem": {"name": "nat-rule-1"},
        "originalServicesOrGroups": {"any": True},
        "inboundInterfaces": {"interfaces": [{"name": "Port1"}]},
        "outboundInterfaces": {"interfaces": [{"name": "Port2"}]},
        "originalSourceNetworks": {"any": True},
        "originalDestinationNetworks": {"any": True},
        "translatedSource": {"masq": True},
        "translatedDestination": {"ipv4Address": {"name": "webfarm-pool"}},
    }
    assert result.structured_content["enabled"] is True


async def test_create_always_sends_the_resolved_enabled_flag(router: Any):
    route = router.post(IPV4_URL).mock(
        return_value=httpx.Response(201, json={**IPV4_RULE, "enabled": False})
    )

    result = await call_tool("nat_rule_create", {**MINIMAL_CREATE, "enabled": False})

    assert result.is_error is False
    body = json.loads(route.calls.last.request.content)
    assert body["enabled"] is False
    assert result.structured_content["enabled"] is False


async def test_create_ipv6_sends_the_family_specific_body(router: Any):
    route = router.post(IPV6_URL).mock(return_value=httpx.Response(201, json=IPV6_RULE))

    result = await call_tool(
        "nat_rule_create",
        {
            "name": "outbound-masq-v6",
            "original_services_or_groups": {"services": [{"name": "https"}]},
            "inbound_interfaces": {"any": True},
            "outbound_interfaces": {"any": True},
            "original_source_networks": {"ipv6_addresses": [{"name": "lan-subnet-v6"}]},
            "original_destination_networks": {"any": True},
            "translated_source": {"ipv6_address": {"name": "port2-egress-v6"}},
            "translated_destination": {"ipv6_address": {"name": "dmz-ipv6-host"}},
        },
        family="ipv6",
    )

    assert result.is_error is False
    body = json.loads(route.calls.last.request.content)
    assert body["originalSourceNetworks"] == {"ipv6Addresses": [{"name": "lan-subnet-v6"}]}
    assert body["translatedSource"] == {"ipv6Address": {"name": "port2-egress-v6"}}
    assert body["translatedDestination"] == {"ipv6Address": {"name": "dmz-ipv6-host"}}
    assert "ipv4Address" not in json.dumps(body)


# -- Update (PATCH, JSON Merge Patch) --------------------------------------------------


async def test_update_ipv4_sends_only_the_set_fields(router: Any):
    route = router.patch(f"{IPV4_URL}/outbound-masq").mock(
        return_value=httpx.Response(200, json=IPV4_RULE)
    )

    result = await call_tool("nat_rule_update", {"id_or_name": "outbound-masq", "enabled": False})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "PATCH"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == {"enabled": False}


async def test_update_ipv4_explicit_null_removes_an_optional_property(router: Any):
    route = router.patch(f"{IPV4_URL}/outbound-masq").mock(
        return_value=httpx.Response(200, json={**IPV4_RULE, "translatedSource": None})
    )

    result = await call_tool(
        "nat_rule_update",
        {"id_or_name": "outbound-masq", "translated_source": None},
    )

    assert result.is_error is False
    assert json.loads(route.calls.last.request.content) == {"translatedSource": None}
    assert result.structured_content["translatedSource"] is None


async def test_update_ipv6_sends_a_partial_body(router: Any):
    route = router.patch(f"{IPV6_URL}/{UUID}").mock(
        return_value=httpx.Response(200, json=IPV6_RULE)
    )

    result = await call_tool(
        "nat_rule_update",
        {
            "id_or_name": UUID,
            "description": "updated",
            "original_source_networks": {"ipv6_addresses": [{"name": "lan-subnet-v6"}]},
        },
        family="ipv6",
    )

    assert result.is_error is False
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "description": "updated",
        "originalSourceNetworks": {"ipv6Addresses": [{"name": "lan-subnet-v6"}]},
    }


# -- Delete ----------------------------------------------------------------------------


async def test_delete_ipv4_sends_delete_without_a_body(router: Any):
    route = router.delete(f"{IPV4_URL}/outbound-masq").mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )

    result = await call_tool("nat_rule_delete", {"id_or_name": "outbound-masq"})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "DELETE"
    assert request.content == b""
    assert result.structured_content == {
        "deleted": True,
        "idOrName": "outbound-masq",
    }


async def test_delete_ipv6_sends_delete(router: Any):
    route = router.delete(f"{IPV6_URL}/{UUID}").mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )

    result = await call_tool("nat_rule_delete", {"id_or_name": UUID}, family="ipv6")

    assert result.is_error is False
    assert str(route.calls.last.request.url) == f"{IPV6_URL}/{UUID}"


# -- Move ------------------------------------------------------------------------------


async def test_move_ipv4_sends_name_position_and_reference(router: Any):
    route = router.post(IPV4_MOVE_URL).mock(return_value=httpx.Response(200, json={}))

    result = await call_tool(
        "nat_rule_move",
        {
            "name": "outbound-masq",
            "position": "before",
            "reference_item": {"name": "nat-rule-1"},
        },
    )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == {
        "name": "outbound-masq",
        "position": "before",
        "referenceItem": {"name": "nat-rule-1"},
    }
    assert result.structured_content == {
        "name": "outbound-masq",
        "position": "before",
        "referenceItem": {"name": "nat-rule-1"},
    }


async def test_move_ipv6_sends_only_the_position_when_top(router: Any):
    route = router.post(IPV6_MOVE_URL).mock(return_value=httpx.Response(200, json={}))

    result = await call_tool(
        "nat_rule_move", {"name": "outbound-masq-v6", "position": "top"}, family="ipv6"
    )

    assert result.is_error is False
    assert json.loads(route.calls.last.request.content) == {
        "name": "outbound-masq-v6",
        "position": "top",
    }
    assert result.structured_content["referenceItem"] is None


# -- Error mapping ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "payload", "status", "error_code", "fragment"),
    [
        (
            "nat_rule_get",
            {"id_or_name": "missing"},
            404,
            "objectNotFound",
            "does not exist",
        ),
        (
            "nat_rule_create",
            MINIMAL_CREATE,
            409,
            "objectAlreadyExists",
            "conflicts with the current firewall state",
        ),
        (
            "nat_rule_update",
            {"id_or_name": "outbound-masq", "enabled": False},
            400,
            "invalidRequest",
            "rejected the request as invalid",
        ),
        (
            "nat_rule_delete",
            {"id_or_name": "outbound-masq"},
            401,
            "authenticationFailed",
            "authentication failed",
        ),
        (
            "nat_rule_list",
            {},
            500,
            "internalError",
            "unexpected error",
        ),
    ],
)
async def test_transport_errors_become_sanitized_tool_errors(
    router: Any,
    tool: str,
    payload: dict[str, Any],
    status: int,
    error_code: str,
    fragment: str,
):
    method = {
        "nat_rule_get": router.get,
        "nat_rule_create": router.post,
        "nat_rule_update": router.patch,
        "nat_rule_delete": router.delete,
        "nat_rule_list": router.get,
    }[tool]
    url = {
        "nat_rule_get": f"{IPV4_URL}/missing",
        "nat_rule_create": IPV4_URL,
        "nat_rule_update": f"{IPV4_URL}/outbound-masq",
        "nat_rule_delete": f"{IPV4_URL}/outbound-masq",
        "nat_rule_list": IPV4_URL,
    }[tool]
    method(url).mock(
        return_value=httpx.Response(
            status,
            json={"error": error_code, "message": "raw appliance detail", "code": "x"},
        )
    )

    result = await call_tool(tool, payload)

    assert result.is_error is True
    text = result.content[0].text
    assert fragment in text
    assert f"HTTP {status}" in text
    assert error_code in text
    assert "raw appliance detail" not in text
    assert KEY not in text


async def test_list_rejects_a_malformed_rule_payload(router: Any):
    """A 200 body that does not match the output model becomes a sanitized ToolError."""
    malformed = {**IPV4_RULE, "enabled": "not-a-boolean"}
    router.get(IPV4_URL).mock(
        return_value=httpx.Response(200, json={"items": [malformed], "pages": None})
    )

    result = await call_tool("nat_rule_list", {})

    assert result.is_error is True
    text = result.content[0].text
    assert "does not match the documented schema" in text
    assert "not-a-boolean" not in text
    assert KEY not in text


# -- Model contract: create ------------------------------------------------------------


def test_create_ipv4_requires_the_six_contract_fields():
    assert NatRuleCreateIpv4Input.model_validate(MINIMAL_CREATE).enabled is True

    for field in (
        "name",
        "original_services_or_groups",
        "inbound_interfaces",
        "outbound_interfaces",
        "original_source_networks",
        "original_destination_networks",
    ):
        body = {key: value for key, value in MINIMAL_CREATE.items() if key != field}
        with pytest.raises(ValidationError):
            NatRuleCreateIpv4Input.model_validate(body)


def test_create_has_no_snat_dnat_discriminator():
    for extra in ({"snat": True}, {"dnat": True}, {"ruleType": "nat"}, {"masquerading": True}):
        with pytest.raises(ValidationError):
            NatRuleCreateIpv4Input.model_validate({**MINIMAL_CREATE, **extra})


def test_create_serializes_the_camel_case_wire_names():
    body = NatRuleCreateIpv4Input.model_validate(MINIMAL_CREATE).model_dump(
        by_alias=True, exclude_unset=True, exclude={"ip_family"}
    )

    assert body == {
        "name": "outbound-masq",
        "originalServicesOrGroups": {"any": True},
        "inboundInterfaces": {"any": True},
        "outboundInterfaces": {"any": True},
        "originalSourceNetworks": {"any": True},
        "originalDestinationNetworks": {"any": True},
    }


def test_create_ipv6_uses_the_ipv6_network_and_translation_shapes():
    body = NatRuleCreateIpv6Input.model_validate(
        {
            **MINIMAL_CREATE,
            "ip_family": "ipv6",
            "original_source_networks": {"ipv6_addresses": [{"name": "lan-v6"}]},
            "translated_source": {"ipv6_address": {"name": "egress-v6"}},
            "translated_destination": {"ipv6_address": {"name": "dmz-v6"}},
        }
    ).model_dump(by_alias=True, exclude_unset=True, exclude={"ip_family"})

    assert body["originalSourceNetworks"] == {"ipv6Addresses": [{"name": "lan-v6"}]}
    assert body["translatedSource"] == {"ipv6Address": {"name": "egress-v6"}}
    assert body["translatedDestination"] == {"ipv6Address": {"name": "dmz-v6"}}


def test_create_ipv4_rejects_ipv6_network_fields():
    with pytest.raises(ValidationError):
        NatRuleCreateIpv4Input.model_validate(
            {
                **MINIMAL_CREATE,
                "original_source_networks": {"ipv6_addresses": [{"name": "lan-v6"}]},
            }
        )


# -- Model contract: match selections --------------------------------------------------


def test_services_selection_is_exactly_one_variant():
    assert NatRuleServicesInput.model_validate({"any": True}).any is True
    assert (
        NatRuleServicesInput.model_validate({"services": [{"name": "https"}]}).services is not None
    )
    assert (
        NatRuleServicesInput.model_validate({"service_groups": [{"name": "web"}]}).service_groups
        is not None
    )

    for invalid in (
        {},
        {"any": False},
        {"any": True, "services": [{"name": "https"}]},
        {"services": []},
        {"services": [{"name": "a" * 51}]},
    ):
        with pytest.raises(ValidationError):
            NatRuleServicesInput.model_validate(invalid)


def test_interface_selection_is_exactly_one_variant():
    assert NatRuleInterfacesInput.model_validate({"any": True}).any is True
    assert (
        NatRuleInterfacesInput.model_validate({"interfaces": [{"name": "Port1"}]}).interfaces
        is not None
    )

    for invalid in (
        {},
        {"interfaces": []},
        {"any": True, "interfaces": [{"name": "Port1"}]},
        {"interfaces": [{"name": "P" * 59}]},
    ):
        with pytest.raises(ValidationError):
            NatRuleInterfacesInput.model_validate(invalid)


def test_ipv4_networks_selection_is_exactly_one_variant():
    assert NatRuleIpv4NetworksInput.model_validate({"any": True}).any is True
    for member in (
        "mac_addresses",
        "ipv4_addresses",
        "ipv4_groups",
        "fqdn_addresses",
        "fqdn_groups",
        "countries",
        "country_groups",
    ):
        assert NatRuleIpv4NetworksInput.model_validate({member: [{"name": "obj"}]}) is not None

    for invalid in (
        {},
        {"any": True, "ipv4_addresses": [{"name": "lan"}]},
        {"ipv4_addresses": []},
        {"ipv6_addresses": [{"name": "lan-v6"}]},
    ):
        with pytest.raises(ValidationError):
            NatRuleIpv4NetworksInput.model_validate(invalid)


def test_ipv6_networks_selection_is_exactly_one_variant():
    assert (
        NatRuleIpv6NetworksInput.model_validate(
            {"ipv6_addresses": [{"name": "lan-v6"}]}
        ).ipv6_addresses
        is not None
    )

    for invalid in ({}, {"ipv4_addresses": [{"name": "lan"}]}, {"ipv6_groups": []}):
        with pytest.raises(ValidationError):
            NatRuleIpv6NetworksInput.model_validate(invalid)


# -- Model contract: translations, enums, names ----------------------------------------


def test_ipv4_translated_source_is_masq_or_an_ipv4_address():
    assert NatRuleIpv4TranslatedSourceInput.model_validate({"masq": True}).masq is True
    assert (
        NatRuleIpv4TranslatedSourceInput.model_validate(
            {"ipv4_address": {"name": "egress"}}
        ).ipv4_address.name
        == "egress"
    )

    for invalid in (
        {},
        {"masq": False},
        {"masq": True, "ipv4_address": {"name": "egress"}},
        {"ipv6_address": {"name": "egress-v6"}},
    ):
        with pytest.raises(ValidationError):
            NatRuleIpv4TranslatedSourceInput.model_validate(invalid)


def test_ipv6_translated_source_is_masq_or_an_ipv6_address():
    assert (
        NatRuleIpv6TranslatedSourceInput.model_validate(
            {"ipv6_address": {"name": "egress-v6"}}
        ).ipv6_address.name
        == "egress-v6"
    )
    with pytest.raises(ValidationError):
        NatRuleIpv6TranslatedSourceInput.model_validate({"ipv4_address": {"name": "egress"}})


def test_ipv4_translated_destination_is_ipv4_or_fqdn():
    assert (
        NatRuleIpv4TranslatedDestinationInput.model_validate(
            {"ipv4_address": {"name": "pool"}}
        ).ipv4_address.name
        == "pool"
    )
    assert (
        NatRuleIpv4TranslatedDestinationInput.model_validate(
            {"fqdn_address": {"name": "app.example.com"}}
        ).fqdn_address.name
        == "app.example.com"
    )

    for invalid in (
        {},
        {"ipv4_address": {"name": "pool"}, "fqdn_address": {"name": "app.example.com"}},
        {"ipv6_address": {"name": "pool-v6"}},
    ):
        with pytest.raises(ValidationError):
            NatRuleIpv4TranslatedDestinationInput.model_validate(invalid)


def test_ipv6_translated_destination_requires_ipv6_address():
    assert (
        NatRuleIpv6TranslatedDestinationInput.model_validate(
            {"ipv6_address": {"name": "dmz-v6"}}
        ).ipv6_address.name
        == "dmz-v6"
    )
    with pytest.raises(ValidationError):
        NatRuleIpv6TranslatedDestinationInput.model_validate({})


def test_position_and_load_balancing_enums_are_closed():
    for position in ("top", "bottom", "after", "before"):
        payload: dict[str, Any] = {
            "ip_family": "ipv4",
            "name": "r1",
            "position": position,
        }
        if position in ("after", "before"):
            payload["reference_item"] = {"name": "anchor"}
        assert NatRuleMoveInput.model_validate(payload).position == position
    with pytest.raises(ValidationError):
        NatRuleMoveInput.model_validate({"ip_family": "ipv4", "name": "r1", "position": "middle"})

    with pytest.raises(ValidationError):
        NatRuleCreateIpv4Input.model_validate(
            {**MINIMAL_CREATE, "load_balancing_method": "leastConnections"}
        )


def test_health_check_ranges_are_enforced():
    valid = {"rule": {"protocol": "tcp", "port": 443, "interval": 10, "timeout": 3, "retry": 2}}
    assert (
        NatRuleCreateIpv4Input.model_validate(
            {**MINIMAL_CREATE, "health_check": valid}
        ).health_check
        is not None
    )

    for invalid in (
        {"rule": {"protocol": "udp", "interval": 10, "timeout": 3}},
        {"rule": {"protocol": "tcp", "interval": 4, "timeout": 3}},
        {"rule": {"protocol": "tcp", "interval": 10, "timeout": 11}},
        {"rule": {"protocol": "tcp", "port": 0, "interval": 10, "timeout": 3}},
        {"rule": {"protocol": "tcp", "interval": 10, "timeout": 3, "retry": 11}},
    ):
        with pytest.raises(ValidationError):
            NatRuleCreateIpv4Input.model_validate({**MINIMAL_CREATE, "health_check": invalid})


def test_object_names_follow_the_documented_format():
    for invalid in ("a" * 61, "a,b", "a;b", " leading", "trailing "):
        with pytest.raises(ValidationError):
            NatRuleCreateIpv4Input.model_validate({**MINIMAL_CREATE, "name": invalid})

    with pytest.raises(ValidationError):
        NatRuleCreateIpv4Input.model_validate({**MINIMAL_CREATE, "name": UUID})


def test_id_or_name_accepts_names_and_uuids_but_not_path_escapes():
    assert (
        NatRuleGetInput.model_validate({"ip_family": "ipv4", "id_or_name": "My Rule"}).id_or_name
        == "My Rule"
    )
    assert (
        NatRuleGetInput.model_validate({"ip_family": "ipv4", "id_or_name": UUID}).id_or_name == UUID
    )

    for invalid in ("..", "a?b", "a#b", "a\\b", "a://b"):
        with pytest.raises(ValidationError):
            NatRuleGetInput.model_validate({"ip_family": "ipv4", "id_or_name": invalid})


def test_list_input_validates_pagination_and_filters():
    defaults = NatRuleListInput(ip_family="ipv4")
    assert (defaults.page, defaults.page_size, defaults.page_total) == (1, 10, False)

    with pytest.raises(ValidationError):
        NatRuleListInput(ip_family="ipv4", page=0)
    with pytest.raises(ValidationError):
        NatRuleListInput(ip_family="ipv4", page_size=101)
    with pytest.raises(ValidationError):
        NatRuleListInput(ip_family="ipv4", name_contains="a", name_not_equals="b")


# -- Model contract: update and move ---------------------------------------------------


def test_update_requires_at_least_one_field():
    with pytest.raises(ValidationError):
        NatRuleUpdateIpv4Input.model_validate({"ip_family": "ipv4", "id_or_name": "outbound-masq"})


def test_update_rejects_null_name_and_enabled_but_allows_null_removal():
    for invalid in (
        {"ip_family": "ipv4", "id_or_name": "outbound-masq", "name": None},
        {"ip_family": "ipv4", "id_or_name": "outbound-masq", "enabled": None},
    ):
        with pytest.raises(ValidationError):
            NatRuleUpdateIpv4Input.model_validate(invalid)

    update = NatRuleUpdateIpv4Input.model_validate(
        {
            "ip_family": "ipv4",
            "id_or_name": "outbound-masq",
            "translated_source": None,
            "description": None,
        }
    )
    assert update.model_dump(
        by_alias=True, exclude_unset=True, exclude={"id_or_name", "ip_family"}
    ) == {
        "description": None,
        "translatedSource": None,
    }


def test_update_ipv6_accepts_partial_family_fields():
    update = NatRuleUpdateIpv6Input.model_validate(
        {
            "ip_family": "ipv6",
            "id_or_name": UUID,
            "original_destination_networks": {"ipv6_groups": [{"name": "grp-v6"}]},
        }
    )

    assert update.model_dump(
        by_alias=True, exclude_unset=True, exclude={"id_or_name", "ip_family"}
    ) == {"originalDestinationNetworks": {"ipv6Groups": [{"name": "grp-v6"}]}}


def test_move_requires_a_name_and_a_position():
    with pytest.raises(ValidationError):
        NatRuleMoveInput.model_validate({"ip_family": "ipv4", "position": "top"})
    with pytest.raises(ValidationError):
        NatRuleMoveInput.model_validate({"ip_family": "ipv4", "name": "r1"})
    with pytest.raises(ValidationError):
        NatRuleMoveInput.model_validate({"ip_family": "ipv4", "name": "r1", "position": "middle"})


def test_anchored_positions_require_a_reference_item():
    """``after``/``before`` without an anchor is rejected before any request is sent."""
    for position in ("after", "before"):
        with pytest.raises(ValidationError, match="requires referenceItem"):
            NatRuleCreateIpv4Input.model_validate({**MINIMAL_CREATE, "position": position})
        with pytest.raises(ValidationError, match="requires referenceItem"):
            NatRuleMoveInput.model_validate(
                {"ip_family": "ipv4", "name": "r1", "position": position}
            )

    anchored = NatRuleCreateIpv4Input.model_validate(
        {**MINIMAL_CREATE, "position": "before", "reference_item": {"name": "anchor"}}
    )
    assert anchored.reference_item is not None
    assert anchored.reference_item.name == "anchor"


async def test_move_refuses_an_anchored_position_without_an_anchor(router: Any):
    route = router.post(IPV4_MOVE_URL).mock(return_value=httpx.Response(200, json={}))

    result = await call_tool("nat_rule_move", {"name": "r1", "position": "after"})

    assert result.is_error is True
    assert "requires referenceItem" in result.content[0].text
    assert route.call_count == 0


# -- Output projection: naming (M2) ----------------------------------------------------


def _schema_property_names(node: Any) -> set[str]:
    """Every property name a JSON schema publishes, at every depth (``$defs`` included)."""
    names: set[str] = set()
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            names.update(properties)
        for value in node.values():
            names |= _schema_property_names(value)
    elif isinstance(node, list):
        for item in node:
            names |= _schema_property_names(item)
    return names


async def test_published_output_schema_uses_the_wire_names():
    """M2: the NAT output surface is camelCase, like the other 119 tools."""
    tools = await tools_by_name()

    for name in (
        "nat_rule_list",
        "nat_rule_get",
        "nat_rule_list",
        "nat_rule_get",
    ):
        names = _schema_property_names(tools[name].output_schema)
        assert {
            "originalServicesOrGroups",
            "translatedService",
            "inboundInterfaces",
            "outboundInterfaces",
            "loadBalancingMethod",
            "healthCheck",
            "originalSourceNetworks",
            "originalDestinationNetworks",
            "translatedSource",
            "translatedDestination",
            "overrideSnatForOutboundInterfaces",
            "linkedFirewallRule",
            "createdAt",
            "updatedAt",
            "kind",
            "position",
        } <= names
        assert not {published for published in names if "_" in published}

    assert "idOrName" in _schema_property_names(tools["nat_rule_delete"].output_schema)
    assert "referenceItem" in _schema_property_names(tools["nat_rule_move"].output_schema)


def test_project_nat_rule_uses_the_wire_names_and_ignores_unknown_fields():
    rule = project_nat_rule(IPV4_RULE)

    assert isinstance(rule, NatRuleOutput)
    assert rule.id == UUID
    assert rule.name == "outbound-masq"
    assert rule.enabled is True
    assert rule.linkedFirewallRule is not None
    assert rule.linkedFirewallRule.name == "allow-web"
    assert rule.translatedService is not None
    assert rule.translatedService.name == "https"
    assert rule.originalServicesOrGroups is not None
    assert rule.originalServicesOrGroups.any is True
    assert rule.inboundInterfaces is not None
    assert [reference.name for reference in rule.inboundInterfaces.interfaces] == ["Port1"]
    assert rule.outboundInterfaces is not None
    assert [reference.name for reference in rule.outboundInterfaces.interfaces] == ["Port2"]
    assert rule.healthCheck is not None
    assert (rule.healthCheck.protocol, rule.healthCheck.port) == ("tcp", 443)
    assert rule.originalSourceNetworks is not None
    assert [reference.name for reference in rule.originalSourceNetworks.ipv4Addresses] == [
        "lan-subnet"
    ]
    assert [reference.name for reference in rule.originalSourceNetworks.fqdnGroups] == [
        "fqdn-group"
    ]
    assert [reference.name for reference in rule.originalSourceNetworks.countries] == ["Spain"]
    assert rule.originalDestinationNetworks is not None
    assert rule.originalDestinationNetworks.any is True
    assert rule.translatedSource is not None
    assert rule.translatedSource.masq is True
    assert rule.translatedDestination is not None
    assert rule.translatedDestination.ipv4Address is not None
    assert rule.translatedDestination.ipv4Address.name == "webfarm-pool"
    override = rule.overrideSnatForOutboundInterfaces[0]
    assert override.outboundInterface.name == "Port2"
    assert override.translatedSource is not None
    assert override.translatedSource.ipv4Address is not None
    assert override.translatedSource.ipv4Address.name == "port2-egress"
    assert rule.createdAt is not None
    assert "unknownField" not in rule.model_dump()
    assert "unknown_field" not in rule.model_dump()


def test_project_nat_rule_handles_the_ipv6_translation_shape():
    rule = project_nat_rule(IPV6_RULE)

    assert rule.enabled is False
    assert rule.originalSourceNetworks is not None
    assert [reference.name for reference in rule.originalSourceNetworks.ipv6Addresses] == [
        "lan-subnet-v6"
    ]
    assert [reference.name for reference in rule.originalSourceNetworks.ipv6Groups] == [
        "lan-group-v6"
    ]
    assert rule.translatedSource is not None
    assert rule.translatedSource.ipv6Address is not None
    assert rule.translatedSource.ipv6Address.name == "port2-egress-v6"
    assert rule.translatedDestination is not None
    assert rule.translatedDestination.ipv6Address is not None
    assert rule.translatedDestination.ipv6Address.name == "dmz-ipv6-host"


# -- Output projection: object references (M14) ----------------------------------------


def test_project_nat_rule_projects_object_references():
    """M14: NAT references have the same ``{"name": …}`` shape as firewall references."""
    rule = project_nat_rule(
        {
            **IPV4_RULE,
            "originalServicesOrGroups": {
                "services": [{"name": "https"}],
                "serviceGroups": [{"name": "web"}],
            },
        }
    )

    assert rule.originalServicesOrGroups is not None
    assert rule.originalServicesOrGroups.services == [ObjectRef(name="https")]
    assert rule.originalServicesOrGroups.serviceGroups == [ObjectRef(name="web")]
    assert rule.originalServicesOrGroups.model_dump()["services"] == [{"name": "https"}]


async def test_list_projects_object_references_in_the_structured_content(router: Any):
    router.get(IPV4_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        **IPV4_RULE,
                        "originalServicesOrGroups": {
                            "services": [{"name": "https"}],
                            "serviceGroups": [{"name": "web"}],
                        },
                    }
                ]
            },
        )
    )

    result = await call_tool("nat_rule_list", {})

    assert result.is_error is False
    item = result.structured_content["items"][0]
    assert item["originalServicesOrGroups"]["services"] == [{"name": "https"}]
    assert item["originalServicesOrGroups"]["serviceGroups"] == [{"name": "web"}]
    assert item["inboundInterfaces"]["interfaces"] == [{"name": "Port1"}]
    assert item["translatedDestination"]["ipv4Address"] == {"name": "webfarm-pool"}


# -- Output projection: derived kind (M13) ---------------------------------------------


@pytest.mark.parametrize(
    ("translated_source", "translated_destination", "expected"),
    [
        ({"masq": True}, None, "snat"),
        ({"ipv4Address": {"name": "egress"}}, None, "snat"),
        (None, {"ipv4Address": {"name": "pool"}}, "dnat"),
        (None, {"fqdnAddress": {"name": "app.example.com"}}, "dnat"),
        (None, None, "unknown"),
        ({"masq": True}, {"ipv4Address": {"name": "pool"}}, "unknown"),
        ({}, None, "unknown"),
    ],
)
def test_kind_is_derived_from_the_populated_translation(
    translated_source: dict[str, Any] | None,
    translated_destination: dict[str, Any] | None,
    expected: str,
):
    """M13: ``kind`` says which translation the appliance populated, and never guesses."""
    payload = {
        key: value
        for key, value in IPV4_RULE.items()
        if key not in ("translatedSource", "translatedDestination")
    }
    payload["translatedSource"] = translated_source
    payload["translatedDestination"] = translated_destination

    assert project_nat_rule(payload).kind == expected


async def test_get_exposes_the_derived_kind(router: Any):
    snat_only = {**IPV4_RULE, "translatedDestination": None}
    router.get(f"{IPV4_URL}/outbound-masq").mock(return_value=httpx.Response(200, json=snat_only))

    result = await call_tool("nat_rule_get", {"id_or_name": "outbound-masq"})

    assert result.is_error is False
    assert result.structured_content["kind"] == "snat"


# -- Output projection: derived position (M12) -----------------------------------------


def test_project_nat_rule_page_derives_position_from_the_page_offset():
    """M12: the list projection numbers the rules across pages, in evaluation order."""
    page = project_nat_rule_page({"items": [IPV4_RULE, IPV6_RULE, IPV4_RULE]}, page=3, page_size=10)

    assert [rule.position for rule in page.items] == [21, 22, 23]


async def test_list_derives_position_from_the_page_offset_and_the_index(router: Any):
    router.get(IPV4_URL).mock(
        return_value=httpx.Response(200, json={"items": [IPV4_RULE, IPV4_RULE]})
    )

    result = await call_tool("nat_rule_list", {"page": 2, "page_size": 10})

    assert result.is_error is False
    assert [item["position"] for item in result.structured_content["items"]] == [11, 12]


async def test_get_returns_a_null_position(router: Any):
    """M12: the get operation does not return the evaluation position, so it is null."""
    router.get(f"{IPV4_URL}/outbound-masq").mock(return_value=httpx.Response(200, json=IPV4_RULE))

    result = await call_tool("nat_rule_get", {"id_or_name": "outbound-masq"})

    assert result.is_error is False
    assert result.structured_content["position"] is None
    assert "position is null" in (await tools_by_name())["nat_rule_get"].description


async def test_create_and_update_return_a_null_position(router: Any):
    router.post(IPV4_URL).mock(return_value=httpx.Response(201, json=IPV4_RULE))
    router.patch(f"{IPV4_URL}/outbound-masq").mock(return_value=httpx.Response(200, json=IPV4_RULE))

    created = await call_tool("nat_rule_create", MINIMAL_CREATE)
    updated = await call_tool("nat_rule_update", {"id_or_name": "outbound-masq", "enabled": False})

    assert created.structured_content["position"] is None
    assert updated.structured_content["position"] is None


# -- Output projection: page envelope --------------------------------------------------


def test_project_nat_rule_page_preserves_pages_exactly():
    page = project_nat_rule_page(
        {
            "items": [IPV4_RULE],
            "pages": {"current": 1, "size": 50, "maxSize": 100, "total": 1, "items": 1},
        },
        page=1,
        page_size=50,
    )

    assert isinstance(page, ListPage)
    assert len(page.items) == 1
    assert page.pages is not None
    assert (page.pages.current, page.pages.size, page.pages.maxSize) == (1, 50, 100)
    assert (page.pages.total, page.pages.items) == (1, 1)


def test_project_nat_rule_page_does_not_invent_pages():
    page = project_nat_rule_page({"items": []}, page=1, page_size=50)

    assert page.items == []
    assert page.pages is None


def test_output_models_are_object_rooted():
    assert NatRuleOutput.model_json_schema()["type"] == "object"
    assert NatRuleDeleteInput.model_json_schema()["type"] == "object"


# -- Phase-5 polish: default page size, output size and the duplicated payload ----------


def test_list_input_defaults_to_ten() -> None:
    """M11: a NAT rule is large, so the default page must stay small."""
    parsed = NatRuleListInput(ip_family="ipv4")

    assert (parsed.page, parsed.page_size, parsed.page_total) == (1, 10, False)
    description = NatRuleListInput.model_json_schema()["properties"]["page_size"]["description"]
    assert "Defaults to 10" in description
    # The bounds are unchanged: this is a default, not a schema break.
    assert NatRuleListInput(ip_family="ipv4", page_size=100).page_size == 100


async def test_list_descriptions_state_the_page_size_and_the_duplicated_payload() -> None:
    """M11/L7: the size of a full page and the SDK's double payload are documented."""
    tools = await tools_by_name()

    for name in ("nat_rule_list", "nat_rule_list"):
        description = tools[name].description
        assert "page_size defaults to 10" in description, name
        assert "~44 KB" in description, name
        assert "structuredContent" in description, name
        assert "read one of them, not both" in description, name
