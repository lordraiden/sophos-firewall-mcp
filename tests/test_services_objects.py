"""Contract, model and discovery tests for the service and service-group tools (#29).

Every test runs against RESPX: no firewall, no network, no real credentials. The contract
tests prove the exact request each tool builds (method, path, query, headers, body,
content type) and the projection it returns. Model tests prove services and service groups
keep separate schemas, that the protocol detail variants are exact and that the documented
port-range rules are enforced. Discovery tests prove the published surface, the
annotations and the read-only filter.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx
import pytest
import respx
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.models.objects import (
    ListQuery,
    Service,
    ServiceCreate,
    ServiceGroup,
    ServiceGroupCreate,
    ServiceGroupUpdateInput,
    ServiceListInput,
    ServiceMemberRef,
    ServiceUpdateInput,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.services_objects import register_service_objects_tools

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
PAGES = {"current": 2, "size": 10, "maxSize": 100, "total": 47, "items": 10}

# -- Published surface -----------------------------------------------------------------

SERVICE_READ_TOOLS = {
    "service_list",
    "service_get",
    "service_group_list",
    "service_group_get",
}

SERVICE_MUTATION_TOOLS = {
    "service_create",
    "service_update",
    "service_delete",
    "service_group_create",
    "service_group_update",
    "service_group_delete",
}

# -- Fixtures and helpers --------------------------------------------------------------


def make_settings(read_only: bool = False) -> Settings:
    return Settings(
        host=HOST,
        port=4444,
        api_key=KEY,
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=read_only,
    )


def make_server(read_only: bool = False) -> MCPServer[AppContext]:
    return create_server(make_settings(read_only), domains=[register_service_objects_tools])


@asynccontextmanager
async def open_client(read_only: bool = False) -> AsyncIterator[Client]:
    async with Client(make_server(read_only)) as client:
        yield client


async def tools_by_name(server: MCPServer[AppContext]) -> dict[str, Any]:
    return {tool.name: tool for tool in await server.list_tools()}


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


def dig(payload: Any, path: tuple[Any, ...]) -> Any:
    for key in path:
        payload = payload[key]
    return payload


def assert_authenticated(request: httpx.Request) -> None:
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["accept"] == "application/json"


def property_names(schema: dict[str, Any]) -> set[str]:
    names = set(schema.get("properties", {}))
    for definition in schema.get("$defs", {}).values():
        names |= property_names(definition)
    for key in ("anyOf", "oneOf"):
        for sub_schema in schema.get(key, []):
            names |= property_names(sub_schema)
    return names


def wire_fields(model: type[Any]) -> set[str]:
    return set(model.model_json_schema(by_alias=True)["properties"])


# -- Wire payloads ---------------------------------------------------------------------

SERVICE_ITEM = {
    "id": UUID,
    "name": "web",
    "type": "tcpOrUdp",
    "services": [{"protocol": "tcp", "destinationPort": {"to": 443}}],
}
SERVICE_GROUP_ITEM = {
    "id": UUID,
    "name": "web-group",
    "services": [{"name": "web"}],
}

LIST_CASES = [
    ("service_list", "/network/services", SERVICE_ITEM),
    ("service_group_list", "/network/service-groups", SERVICE_GROUP_ITEM),
]

GET_CASES = [
    ("service_get", "/network/services", SERVICE_ITEM, ("type",), "tcpOrUdp"),
    (
        "service_group_get",
        "/network/service-groups",
        SERVICE_GROUP_ITEM,
        ("services", 0, "name"),
        "web",
    ),
]

CREATE_CASES = [
    (
        "service_create",
        "/network/services",
        {
            "name": "web",
            "type": "tcpOrUdp",
            "services": [{"protocol": "tcp", "destinationPort": {"to": 443}}],
        },
        SERVICE_ITEM,
        ("type",),
        "tcpOrUdp",
    ),
    (
        "service_group_create",
        "/network/service-groups",
        {"name": "web-group", "services": [{"name": "web"}]},
        SERVICE_GROUP_ITEM,
        ("services", 0, "name"),
        "web",
    ),
]

UPDATE_CASES = [
    (
        "service_update",
        "/network/services",
        {
            "id_or_name": "web",
            "description": None,
            "services": [{"protocol": "tcp", "destinationPort": {"to": 8443}}],
        },
        {"description": None, "services": [{"protocol": "tcp", "destinationPort": {"to": 8443}}]},
        {
            "id": UUID,
            "name": "web",
            "type": "tcpOrUdp",
            "services": [{"protocol": "tcp", "destinationPort": {"to": 8443}}],
        },
        ("type",),
        "tcpOrUdp",
    ),
    (
        "service_group_update",
        "/network/service-groups",
        {"id_or_name": "web", "services": [{"name": "web"}, {"name": "dns"}]},
        {"services": [{"name": "web"}, {"name": "dns"}]},
        {"id": UUID, "name": "web-group", "services": [{"name": "web"}, {"name": "dns"}]},
        ("services", 1, "name"),
        "dns",
    ),
]

DELETE_CASES = [
    ("service_delete", "/network/services"),
    ("service_group_delete", "/network/service-groups"),
]


# -- Discovery and annotations ---------------------------------------------------------


async def test_write_mode_publishes_the_full_service_surface():
    names = set(await tools_by_name(make_server()))

    assert names == SERVICE_READ_TOOLS | SERVICE_MUTATION_TOOLS
    assert len(names) == 10


async def test_read_only_mode_publishes_only_read_tools():
    names = set(await tools_by_name(make_server(read_only=True)))

    assert names == SERVICE_READ_TOOLS


async def test_every_tool_has_a_title_and_a_description():
    tools = await tools_by_name(make_server())

    for tool in tools.values():
        assert tool.title
        assert len(tool.description) >= 40


async def test_read_tools_declare_only_read_annotations():
    tools = await tools_by_name(make_server())

    for name in SERVICE_READ_TOOLS:
        annotations = tools[name].annotations
        assert annotations.read_only_hint is True
        assert annotations.destructive_hint is None
        assert annotations.idempotent_hint is None


async def test_mutation_tools_declare_write_hints():
    tools = await tools_by_name(make_server())

    for name in SERVICE_MUTATION_TOOLS:
        annotations = tools[name].annotations
        assert annotations.read_only_hint is False
        assert annotations.destructive_hint is not None
        assert annotations.idempotent_hint is not None


async def test_input_schemas_are_closed_and_hide_the_context():
    tools = await tools_by_name(make_server())

    for tool in tools.values():
        schema = tool.input_schema
        assert schema["type"] == "object"
        assert schema["required"] == ["request"]
        assert "ctx" not in schema["properties"]
        for definition in schema.get("$defs", {}).values():
            assert definition.get("additionalProperties") is False


async def test_output_schemas_are_object_rooted():
    tools = await tools_by_name(make_server())

    for tool in tools.values():
        schema = tool.output_schema
        assert schema is not None
        assert schema["type"] == "object"


async def test_no_tool_accepts_a_path_url_or_header_argument():
    tools = await tools_by_name(make_server())

    for tool in tools.values():
        names = property_names(tool.input_schema)
        assert not names & {"path", "url", "headers", "method", "body"}


# -- List contract ---------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "path", "item"), LIST_CASES, ids=[case[0] for case in LIST_CASES])
async def test_list_operations_build_the_documented_request(
    router: Any, tool: str, path: str, item: dict[str, Any]
):
    body = {"items": [item], "pages": PAGES}
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=body))

    async with open_client() as client:
        result = await client.call_tool(
            tool,
            {
                "request": {
                    "page": 2,
                    "page_size": 10,
                    "page_total": True,
                    "name_contains": "web",
                }
            },
        )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.path == f"/api/firewall-config/v1{path}"
    assert dict(request.url.params) == {
        "page": "2",
        "pageSize": "10",
        "pageTotal": "true",
        "nameContains": "web",
    }
    assert_authenticated(request)
    assert "content-type" not in request.headers
    assert result.structured_content["pages"] == PAGES
    assert result.structured_content["items"][0]["name"] == item["name"]


async def test_service_list_sends_the_type_filter(router: Any):
    route = router.get(f"{BASE}/network/services").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGES})
    )

    async with open_client() as client:
        result = await client.call_tool(
            "service_list", {"request": {"type": "tcpOrUdp", "name_contains": "web"}}
        )

    assert result.is_error is False
    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "pageSize": "10",
        "pageTotal": "false",
        "nameContains": "web",
        "type": "tcpOrUdp",
    }


async def test_service_list_filters_the_returned_page_by_type(router: Any):
    """H2: the appliance ignores `type`, so the adapter filters the projected page.

    The page metadata is the appliance's metadata for the unfiltered collection and is
    preserved unchanged; only `items` is narrowed.
    """
    items = [
        {
            "id": UUID,
            "name": "ping",
            "type": "icmp",
            "services": [{"icmpType": "echoRequest", "icmpCode": "any"}],
        },
        SERVICE_ITEM,
        {
            "id": UUID,
            "name": "gre",
            "type": "ip",
            "services": [{"ipProtocol": "gre"}],
        },
    ]
    route = router.get(f"{BASE}/network/services").mock(
        return_value=httpx.Response(200, json={"items": items, "pages": PAGES})
    )

    async with open_client() as client:
        result = await client.call_tool("service_list", {"request": {"type": "icmp"}})

    assert result.is_error is False
    assert [item["name"] for item in result.structured_content["items"]] == ["ping"]
    assert result.structured_content["pages"] == PAGES
    assert dict(route.calls.last.request.url.params)["type"] == "icmp"


async def test_service_list_without_type_returns_the_whole_page(router: Any):
    items = [
        {
            "id": UUID,
            "name": "ping",
            "type": "icmp",
            "services": [{"icmpType": "echoRequest", "icmpCode": "any"}],
        },
        SERVICE_ITEM,
    ]
    router.get(f"{BASE}/network/services").mock(
        return_value=httpx.Response(200, json={"items": items, "pages": PAGES})
    )

    async with open_client() as client:
        result = await client.call_tool("service_list", {"request": {}})

    assert [item["name"] for item in result.structured_content["items"]] == ["ping", "web"]


async def test_service_list_type_filter_can_empty_the_page(router: Any):
    router.get(f"{BASE}/network/services").mock(
        return_value=httpx.Response(200, json={"items": [SERVICE_ITEM], "pages": PAGES})
    )

    async with open_client() as client:
        result = await client.call_tool("service_list", {"request": {"type": "icmpv6"}})

    assert result.is_error is False
    assert result.structured_content["items"] == []
    assert result.structured_content["pages"] == PAGES


# -- Get contract ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "path", "item", "key_path", "expected"),
    GET_CASES,
    ids=[case[0] for case in GET_CASES],
)
async def test_get_operations_build_the_documented_request(
    router: Any,
    tool: str,
    path: str,
    item: dict[str, Any],
    key_path: tuple[Any, ...],
    expected: Any,
):
    route = router.get(f"{BASE}{path}/web").mock(return_value=httpx.Response(200, json=item))

    async with open_client() as client:
        result = await client.call_tool(tool, {"request": {"id_or_name": "web"}})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.path == f"/api/firewall-config/v1{path}/web"
    assert_authenticated(request)
    assert dig(result.structured_content, key_path) == expected


async def test_get_percent_encodes_the_identifier(router: Any):
    route = router.get(f"{BASE}/network/services/web%20server").mock(
        return_value=httpx.Response(200, json={**SERVICE_ITEM, "name": "web server"})
    )

    async with open_client() as client:
        result = await client.call_tool("service_get", {"request": {"id_or_name": "web server"}})

    assert result.is_error is False
    assert (
        route.calls.last.request.url.raw_path
        == b"/api/firewall-config/v1/network/services/web%20server"
    )


# -- Create contract -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "path", "request_body", "response_body", "key_path", "expected"),
    CREATE_CASES,
    ids=[case[0] for case in CREATE_CASES],
)
async def test_create_operations_build_the_documented_request(
    router: Any,
    tool: str,
    path: str,
    request_body: dict[str, Any],
    response_body: dict[str, Any],
    key_path: tuple[Any, ...],
    expected: Any,
):
    route = router.post(f"{BASE}{path}").mock(return_value=httpx.Response(201, json=response_body))

    async with open_client() as client:
        result = await client.call_tool(tool, {"request": request_body})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "POST"
    assert request.url.path == f"/api/firewall-config/v1{path}"
    assert_authenticated(request)
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == request_body
    assert dig(result.structured_content, key_path) == expected


# -- Update contract -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "path", "request_body", "expected_body", "response_body", "key_path", "expected"),
    UPDATE_CASES,
    ids=[case[0] for case in UPDATE_CASES],
)
async def test_update_operations_build_the_documented_request(
    router: Any,
    tool: str,
    path: str,
    request_body: dict[str, Any],
    expected_body: dict[str, Any],
    response_body: dict[str, Any],
    key_path: tuple[Any, ...],
    expected: Any,
):
    route = router.patch(f"{BASE}{path}/web").mock(
        return_value=httpx.Response(200, json=response_body)
    )

    async with open_client() as client:
        result = await client.call_tool(tool, {"request": request_body})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "PATCH"
    assert request.url.path == f"/api/firewall-config/v1{path}/web"
    assert_authenticated(request)
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == expected_body
    assert dig(result.structured_content, key_path) == expected


# -- Delete contract -------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "path"), DELETE_CASES, ids=[case[0] for case in DELETE_CASES])
async def test_delete_operations_build_the_documented_request(router: Any, tool: str, path: str):
    route = router.delete(f"{BASE}{path}/web").mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )

    async with open_client() as client:
        result = await client.call_tool(tool, {"request": {"id_or_name": "web"}})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "DELETE"
    assert request.url.path == f"/api/firewall-config/v1{path}/web"
    assert_authenticated(request)
    assert "content-type" not in request.headers
    assert request.content == b""
    assert result.structured_content == {"deleted": True}


# -- Error mapping ---------------------------------------------------------------------


async def test_get_not_found_maps_to_a_clear_tool_error(router: Any):
    router.get(f"{BASE}/network/services/missing").mock(
        return_value=httpx.Response(404, json={"error": "notFound"})
    )

    async with open_client() as client:
        result = await client.call_tool("service_get", {"request": {"id_or_name": "missing"}})

    assert result.is_error is True
    assert "does not exist" in result.content[0].text


async def test_delete_in_use_conflict_maps_to_a_clear_tool_error(router: Any):
    router.delete(f"{BASE}/network/services/in-use").mock(
        return_value=httpx.Response(409, json={"error": "resourceConflict"})
    )

    async with open_client() as client:
        result = await client.call_tool("service_delete", {"request": {"id_or_name": "in-use"}})

    assert result.is_error is True
    assert "conflicts with the current firewall state" in result.content[0].text


async def test_validation_error_never_echoes_the_raw_body(router: Any):
    router.post(f"{BASE}/network/services").mock(
        return_value=httpx.Response(
            400, json={"error": "badRequest", "message": "raw appliance detail"}
        )
    )

    async with open_client() as client:
        result = await client.call_tool(
            "service_create",
            {
                "request": {
                    "name": "web",
                    "type": "tcpOrUdp",
                    "services": [{"protocol": "tcp", "destinationPort": {"to": 443}}],
                }
            },
        )

    assert result.is_error is True
    assert "rejected the request as invalid" in result.content[0].text
    assert "raw appliance detail" not in result.content[0].text


async def test_a_malformed_service_payload_is_a_sanitized_tool_error(router: Any):
    """A 200 body that does not match the output model becomes a sanitized ToolError."""
    router.get(f"{BASE}/network/services/web").mock(
        return_value=httpx.Response(200, json={**SERVICE_ITEM, "type": "not-a-service-type"})
    )

    async with open_client() as client:
        result = await client.call_tool("service_get", {"request": {"id_or_name": "web"}})

    assert result.is_error is True
    text = result.content[0].text
    assert "does not match the documented schema" in text
    assert "not-a-service-type" not in text
    assert KEY not in text


# -- Model tests: services and groups stay distinct ------------------------------------


def test_service_and_service_group_models_are_distinct():
    assert "type" in wire_fields(Service)
    assert "services" in wire_fields(ServiceGroup)
    assert "type" not in wire_fields(ServiceGroup)
    assert "type" not in wire_fields(ServiceGroupCreate)
    assert "services" in wire_fields(ServiceGroupCreate)


def test_service_update_has_no_type_field():
    assert "type" not in ServiceUpdateInput.model_fields


def test_service_create_requires_name_type_and_services():
    base = {
        "name": "web",
        "type": "tcpOrUdp",
        "services": [{"protocol": "tcp", "destinationPort": {"to": 443}}],
    }

    for missing in ("name", "type", "services"):
        payload = {key: value for key, value in base.items() if key != missing}
        with pytest.raises(ValidationError):
            ServiceCreate.model_validate(payload)


def test_service_create_requires_at_least_one_detail_entry():
    with pytest.raises(ValidationError):
        ServiceCreate(name="web", type="tcpOrUdp", services=[])


def test_service_create_accepts_each_detail_variant():
    tcp = ServiceCreate(
        name="web",
        type="tcpOrUdp",
        services=[{"protocol": "tcp", "destinationPort": {"to": 443}}],
    )
    ip = ServiceCreate(name="gre", type="ip", services=[{"ipProtocol": "gre"}])
    icmp = ServiceCreate(
        name="ping",
        type="icmp",
        services=[{"icmpType": "echoRequest", "icmpCode": "noCode"}],
    )
    icmpv6 = ServiceCreate(
        name="ping6",
        type="icmpv6",
        services=[{"icmpv6Type": "neighborSolicitation", "icmpv6Code": "noCode"}],
    )

    assert tcp.model_dump(mode="json", by_alias=True, exclude_unset=True)["services"] == [
        {"protocol": "tcp", "destinationPort": {"to": 443}}
    ]
    assert ip.model_dump(mode="json", by_alias=True, exclude_unset=True)["services"] == [
        {"ipProtocol": "gre"}
    ]
    assert icmp.model_dump(mode="json", by_alias=True, exclude_unset=True)["services"] == [
        {"icmpType": "echoRequest", "icmpCode": "noCode"}
    ]
    assert icmpv6.model_dump(mode="json", by_alias=True, exclude_unset=True)["services"] == [
        {"icmpv6Type": "neighborSolicitation", "icmpv6Code": "noCode"}
    ]


@pytest.mark.parametrize(
    "detail",
    [
        {"protocol": "sctp"},
        {"ipProtocol": "not-a-protocol"},
        {"icmpType": "bogus", "icmpCode": "noCode"},
        {"icmpv6Type": "neighborSolicitation", "icmpv6Code": "bogus"},
    ],
)
def test_service_create_rejects_unknown_protocol_values(detail: dict[str, Any]):
    with pytest.raises(ValidationError):
        ServiceCreate.model_validate({"name": "bad", "type": "tcpOrUdp", "services": [detail]})


def test_service_output_accepts_each_detail_variant():
    service = Service.model_validate(
        {
            "name": "mixed",
            "type": "ip",
            "services": [
                {"protocol": "udp", "sourcePort": {"from": 53, "to": 53}},
                {"ipProtocol": "gre"},
                {"icmpType": "echoRequest", "icmpCode": "noCode"},
                {"icmpv6Type": "echoRequest", "icmpv6Code": "noCode"},
            ],
        }
    )

    assert len(service.services) == 4


# -- Model tests: port ranges ----------------------------------------------------------


@pytest.mark.parametrize(
    "port_range",
    [
        {"from": 10},
        {"from": 100, "to": 10},
        {"to": 0},
        {"to": 65536},
        {"from": 0, "to": 10},
    ],
)
def test_service_port_range_rejects_invalid_ranges(port_range: dict[str, int]):
    with pytest.raises(ValidationError):
        ServiceCreate.model_validate(
            {
                "name": "web",
                "type": "tcpOrUdp",
                "services": [{"protocol": "tcp", "sourcePort": port_range}],
            }
        )


def test_service_port_range_accepts_a_single_port_and_a_range():
    single = ServiceCreate(
        name="web",
        type="tcpOrUdp",
        services=[{"protocol": "tcp", "destinationPort": {"to": 443}}],
    )
    ranged = ServiceCreate(
        name="high",
        type="tcpOrUdp",
        services=[{"protocol": "tcp", "destinationPort": {"from": 8000, "to": 8080}}],
    )

    single_body = single.model_dump(mode="json", by_alias=True, exclude_unset=True)
    ranged_body = ranged.model_dump(mode="json", by_alias=True, exclude_unset=True)

    assert single_body["services"][0]["destinationPort"] == {"to": 443}
    assert ranged_body["services"][0]["destinationPort"] == {"from": 8000, "to": 8080}


# -- Model tests: service groups and pagination ----------------------------------------


def test_service_group_members_are_name_references():
    member = ServiceMemberRef(name="web")

    assert member.name == "web"
    with pytest.raises(ValidationError):
        ServiceMemberRef(name="web", type="tcpOrUdp")
    with pytest.raises(ValidationError):
        ServiceMemberRef(name="x" * 51)


def test_service_group_requires_at_least_one_member():
    with pytest.raises(ValidationError):
        ServiceGroupCreate(name="group", services=[])
    with pytest.raises(ValidationError):
        ServiceGroupUpdateInput(id_or_name="group", services=[])


def test_service_group_output_keeps_member_references():
    group = ServiceGroup.model_validate(SERVICE_GROUP_ITEM)

    assert [member.name for member in group.services] == ["web"]


def test_service_list_query_rejects_both_name_filters():
    with pytest.raises(ValidationError):
        ServiceListInput(name_contains="web", name_not_equals="mail")


def test_service_list_query_rejects_an_unknown_type():
    with pytest.raises(ValidationError):
        ServiceListInput(type="sctp")


def test_service_update_body_omits_unset_fields_and_keeps_an_explicit_null():
    omitted = ServiceUpdateInput(id_or_name="web", name="renamed")
    cleared = ServiceUpdateInput(id_or_name="web", description=None)

    omitted_body = omitted.model_dump(
        mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
    )
    cleared_body = cleared.model_dump(
        mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
    )

    assert omitted_body == {"name": "renamed"}
    assert cleared_body == {"description": None}


# -- M1: nested input naming -----------------------------------------------------------


def test_nested_service_detail_models_publish_snake_case_and_serialize_to_the_wire_names():
    """M1: the service detail entries publish snake_case, dump the contract names.

    The published schema is what an agent reads, so every nested property must be
    snake_case; the wire body must still be the contract's camelCase document. The
    response projections keep the contract's camelCase names.
    """
    request = ServiceCreate(
        name="mcp-test-svc",
        type="tcpOrUdp",
        services=[
            {
                "protocol": "tcp",
                "source_port": {"from_port": 1024, "to_port": 65535},
                "destination_port": {"from_port": 80, "to_port": 80},
            },
            {"ip_protocol": "gre"},
            {"icmp_type": "echoRequest", "icmp_code": "noCode"},
            {"icmpv6_type": "echoRequest", "icmpv6_code": "noCode"},
        ],
    )

    body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)

    assert body["services"] == [
        {
            "protocol": "tcp",
            "sourcePort": {"from": 1024, "to": 65535},
            "destinationPort": {"from": 80, "to": 80},
        },
        {"ipProtocol": "gre"},
        {"icmpType": "echoRequest", "icmpCode": "noCode"},
        {"icmpv6Type": "echoRequest", "icmpv6Code": "noCode"},
    ]

    definitions = ServiceCreate.model_json_schema(by_alias=True)["$defs"]
    assert set(definitions["TcpUdpServiceDetail"]["properties"]) == {
        "protocol",
        "source_port",
        "destination_port",
    }
    assert set(definitions["IpProtocolServiceDetail"]["properties"]) == {"ip_protocol"}
    assert set(definitions["Icmpv4ServiceDetail"]["properties"]) == {"icmp_type", "icmp_code"}
    assert set(definitions["Icmpv6ServiceDetail"]["properties"]) == {"icmpv6_type", "icmpv6_code"}

    # The response projections keep the contract's camelCase names.
    output_definitions = Service.model_json_schema(by_alias=True)["$defs"]
    assert set(output_definitions["TcpUdpServiceDetailOutput"]["properties"]) == {
        "protocol",
        "sourcePort",
        "destinationPort",
    }
    assert set(output_definitions["IpProtocolServiceDetailOutput"]["properties"]) == {"ipProtocol"}
    assert set(output_definitions["Icmpv4ServiceDetailOutput"]["properties"]) == {
        "icmpType",
        "icmpCode",
    }
    assert set(output_definitions["Icmpv6ServiceDetailOutput"]["properties"]) == {
        "icmpv6Type",
        "icmpv6Code",
    }

    # The camelCase spelling is still accepted on input, so the alias is a choice.
    assert ServiceUpdateInput(
        id_or_name="web",
        services=[{"protocol": "tcp", "sourcePort": {"from": 80, "to": 80}}],
    ).model_dump(mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}) == {
        "services": [{"protocol": "tcp", "sourcePort": {"from": 80, "to": 80}}]
    }


# -- Phase-5 polish: default page size and the output size ------------------------------


def test_list_query_defaults_to_ten() -> None:
    """M11: the service list tools share the small default page size."""
    parsed = ListQuery()

    assert (parsed.page, parsed.page_size, parsed.page_total) == (1, 10, False)
    description = ListQuery.model_json_schema()["properties"]["page_size"]["description"]
    assert "Defaults to 10" in description


async def test_service_list_descriptions_state_the_page_size_and_the_output_size() -> None:
    """M11/L7: the default, the size of a full page and the double payload are documented."""
    tools = await tools_by_name(make_server())

    service = tools["service_list"].description
    assert "default 10" in service
    assert "~28 KB" in service
    assert "structuredContent" in service
    assert "read one of them, not both" in service

    group = tools["service_group_list"].description
    assert "default 10" in group
