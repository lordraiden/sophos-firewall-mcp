"""NAT-rule tools for the Sophos Firewall MCP server (IPv4 and IPv6).

Twelve tools map one-to-one to the twelve audited NAT-rule operations in
``docs/API-COVERAGE.md`` §5.2 and ADR-001 §10:

==========================================  =============================================
tool                                        operationId
==========================================  =============================================
``nat_rule_list``                           ``getAllNatRulesIpv4``/``Ipv6``
``nat_rule_get``                            ``getNatRuleIpv4ByIdOrName``/``Ipv6``
``nat_rule_create``                         ``createNatRuleIpv4``/``Ipv6``
``nat_rule_update``                         ``updateNatRuleIpv4ByIdOrName``/``Ipv6``
``nat_rule_delete``                         ``deleteNatRuleIpv4ByIdOrName``/``Ipv6``
``nat_rule_move``                           ``moveNatRuleIpv4``/``Ipv6``
==========================================  =============================================

One tool per concept: the required ``ip_family`` argument selects the IPv4 or IPv6 rule
base, and the handler picks the path. The wire body is unchanged for each family.

The two bulk-delete routes (``bulkDeleteNatRulesIpv4``/``bulkDeleteNatRulesIpv6``) are
classified in ``docs/API-COVERAGE.md`` and deliberately **not** registered: they are not
part of the v1 surface.

The adapter never builds a URL, a header or an HTTP client: it owns the ``/``-prefixed path
constants, calls the shared :class:`~sophos_firewall_mcp.client.SophosRestClient` reached
through :class:`~sophos_firewall_mcp.context.AppContext`, and projects every payload into
the bounded models in :mod:`sophos_firewall_mcp.models.nat`. Every transport failure is
mapped through :func:`~sophos_firewall_mcp.tools.tool_error` so the model receives a
sanitized, actionable message.

Update is a PATCH with JSON Merge Patch semantics and ``application/json`` (the API
declares no exception for these operations): the body is serialized with
``exclude_unset=True`` so omitted properties keep their persisted value and an explicit
``null`` removes a property.
"""

from __future__ import annotations

from typing import Any, Callable, TypeVar
from urllib.parse import quote

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import ValidationError

from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import SophosAPIError
from sophos_firewall_mcp.models.common import ListPage, ObjectRef
from sophos_firewall_mcp.models.nat import (
    NatRuleCreateInput,
    NatRuleCreateIpv4Input,
    NatRuleCreateIpv6Input,
    NatRuleDeleteInput,
    NatRuleDeleteOutput,
    NatRuleGetInput,
    NatRuleListInput,
    NatRuleMoveInput,
    NatRuleMoveOutput,
    NatRuleOutput,
    NatRuleUpdateInput,
    NatRuleUpdateIpv4Input,
    NatRuleUpdateIpv6Input,
    project_nat_rule,
    project_nat_rule_page,
)
from sophos_firewall_mcp.tools import DomainAdapter, ToolKind, register_tool, tool_error

__all__ = ["register_nat_tools"]

OutputT = TypeVar("OutputT")

#: Collection path of the IPv4 NAT rule base (``getAllNatRulesIpv4``/``createNatRuleIpv4``).
IPV4_RULES_PATH = "/nat/rules/ipv4"

#: Collection path of the IPv6 NAT rule base (``getAllNatRulesIpv6``/``createNatRuleIpv6``).
IPV6_RULES_PATH = "/nat/rules/ipv6"

#: Move path of the IPv4 rule base (``moveNatRuleIpv4``).
IPV4_MOVE_PATH = "/nat/rules/ipv4/move"

#: Move path of the IPv6 rule base (``moveNatRuleIpv6``).
IPV6_MOVE_PATH = "/nat/rules/ipv6/move"


def _rule_path(collection_path: str, id_or_name: str) -> str:
    """Build the item path for one rule, percent-encoding the identifier as one segment."""
    return f"{collection_path}/{quote(id_or_name, safe='')}"


def _schema_error(exc: ValidationError, path: str) -> ToolError:
    """Build the sanitized error for a response that does not match its output model.

    Only the field location is echoed: the rejected input may contain appliance data, and
    the raw payload must never reach the model.
    """
    first = exc.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "body"
    return ToolError(
        f"the appliance returned a response for {path} that does not match the documented "
        f"schema ({location})"
    )


def _project(payload: Any, project: Callable[[Any], OutputT], path: str) -> OutputT:
    """Project one appliance payload, with a sanitized error when it does not match."""
    try:
        return project(payload)
    except ValidationError as exc:
        raise _schema_error(exc, path) from exc


class NatAdapter(DomainAdapter):
    """Domain adapter for the IPv4 and IPv6 NAT rule bases.

    Every method takes the collection path as an argument so the two families share one
    implementation while the tools stay explicit about which rule base they address. The
    path constants are module-level and never influenced by a tool argument.
    """

    async def list_rules(
        self, collection_path: str, request: NatRuleListInput
    ) -> ListPage[NatRuleOutput]:
        """Read one page of a NAT rule base (``getAllNatRulesIpv4``/``Ipv6``).

        Each projected rule carries its 1-based evaluation ``position``, derived from the
        requested page and the item index.
        """
        params: dict[str, Any] = {}
        if request.name_contains is not None:
            params["nameContains"] = request.name_contains
        if request.name_not_equals is not None:
            params["nameNotEquals"] = request.name_not_equals
        try:
            payload = await self.client.get_page(
                collection_path,
                page=request.page,
                page_size=request.page_size,
                page_total=request.page_total,
                params=params or None,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _project(
            payload,
            lambda body: project_nat_rule_page(
                body, page=request.page, page_size=request.page_size
            ),
            collection_path,
        )

    async def get_rule(self, collection_path: str, id_or_name: str) -> NatRuleOutput:
        """Read one NAT rule by name or UUID (``getNatRule*ByIdOrName``).

        ``position`` is ``None``: the get operation does not return the rule's evaluation
        position, and the API exposes no way to obtain it for a single rule.
        """
        try:
            payload = await self.client.get(_rule_path(collection_path, id_or_name))
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _project(payload, project_nat_rule, collection_path)

    async def create_rule(
        self,
        collection_path: str,
        request: NatRuleCreateIpv4Input | NatRuleCreateIpv6Input,
    ) -> NatRuleOutput:
        """Create one NAT rule (``createNatRuleIpv4``/``Ipv6``).

        The API declares ``enabled`` with a default of ``true``; the resolved value is
        always sent so the created state is explicit rather than implied. No follow-up
        mutation (enable, move) is performed.
        """
        body = request.model_dump(
            by_alias=True, exclude_unset=True, exclude_none=True, exclude={"ip_family"}
        )
        body["enabled"] = request.enabled
        try:
            payload = await self.client.post(collection_path, json=body)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _project(payload, project_nat_rule, collection_path)

    async def update_rule(
        self,
        collection_path: str,
        request: NatRuleUpdateIpv4Input | NatRuleUpdateIpv6Input,
    ) -> NatRuleOutput:
        """Partially update one NAT rule (``updateNatRule*ByIdOrName``, JSON Merge Patch).

        Only the fields the caller set are sent; omitted properties keep their persisted
        value and an explicit ``null`` removes a property (RFC 7396).
        """
        body = request.model_dump(
            by_alias=True, exclude_unset=True, exclude={"id_or_name", "ip_family"}
        )
        try:
            payload = await self.client.patch(
                _rule_path(collection_path, request.id_or_name), json=body
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _project(payload, project_nat_rule, collection_path)

    async def delete_rule(self, collection_path: str, id_or_name: str) -> NatRuleDeleteOutput:
        """Delete one NAT rule (``deleteNatRule*ByIdOrName``).

        The shared client's ``delete`` primitive discards the response body, so success is
        the absence of a transport error: the appliance answered with a success status.
        """
        try:
            await self.client.delete(_rule_path(collection_path, id_or_name))
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return NatRuleDeleteOutput(deleted=True, idOrName=id_or_name)

    async def move_rule(self, move_path: str, request: NatRuleMoveInput) -> NatRuleMoveOutput:
        """Move one NAT rule (``moveNatRuleIpv4``/``Ipv6``).

        The operation returns an empty success object, so the applied request is echoed.
        """
        body = request.model_dump(
            by_alias=True, exclude_unset=True, exclude_none=True, exclude={"ip_family"}
        )
        try:
            await self.client.post(move_path, json=body)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return NatRuleMoveOutput(
            name=request.name,
            position=request.position,
            referenceItem=(
                ObjectRef(name=request.reference_item.name)
                if request.reference_item is not None
                else None
            ),
        )


def register_nat_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the six NAT-rule tools on ``server``.

    Args:
        server: The server built by :func:`sophos_firewall_mcp.server.create_server`.
        read_only: When true, the four mutation tools are not registered at all (the
            read-only filter lives in
            :func:`sophos_firewall_mcp.tools.register_tool`).
    """

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="nat_rule_list",
        title="List NAT rules",
        description=(
            "List one page of NAT rules (operationId getAllNatRulesIpv4 or "
            "getAllNatRulesIpv6, selected by the required ip_family). Returns the rules with "
            "their match and translation fields projected to object references, each with "
            "its 1-based evaluation position and a derived kind (snat/dnat/unknown), plus "
            "the page metadata. Use page/page_size to walk the rule base; one page per call, "
            "and page_size defaults to 10. name_contains and name_not_equals are mutually "
            "exclusive. Size: the tested appliance's 28-rule base is ~44 KB of JSON, so keep "
            "page_size small. The MCP SDK returns the payload both as a text block and as "
            "structuredContent; read one of them, not both."
        ),
    )
    async def nat_rule_list(
        request: NatRuleListInput, ctx: Context[AppContext]
    ) -> ListPage[NatRuleOutput]:
        path = IPV6_RULES_PATH if request.ip_family == "ipv6" else IPV4_RULES_PATH
        return await NatAdapter.from_context(ctx).list_rules(path, request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="nat_rule_get",
        title="Get a NAT rule",
        description=(
            "Read one NAT rule by name or UUID (operationId getNatRuleIpv4ByIdOrName or "
            "getNatRuleIpv6ByIdOrName, selected by the required ip_family). Returns the "
            "rule's match and translation fields projected to object references, plus a "
            "derived kind (snat/dnat/unknown). position is null: the get operation does not "
            "return the rule's evaluation position; use nat_rule_list to obtain it."
        ),
    )
    async def nat_rule_get(request: NatRuleGetInput, ctx: Context[AppContext]) -> NatRuleOutput:
        path = IPV6_RULES_PATH if request.ip_family == "ipv6" else IPV4_RULES_PATH
        return await NatAdapter.from_context(ctx).get_rule(path, request.id_or_name)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="nat_rule_create",
        title="Create a NAT rule",
        description=(
            "Create a NAT rule (operationId createNatRuleIpv4 or createNatRuleIpv6, selected "
            "by the required ip_family). Requires name, original_services_or_groups, "
            "inbound_interfaces, outbound_interfaces, original_source_networks and "
            "original_destination_networks; translation fields are optional because the API "
            "defines no SNAT/DNAT discriminator. enabled defaults to true and is always "
            "sent. The rule is not moved or enabled by a follow-up call."
        ),
        annotations=ToolAnnotations(destructive_hint=False, idempotent_hint=False),
    )
    async def nat_rule_create(
        request: NatRuleCreateInput, ctx: Context[AppContext]
    ) -> NatRuleOutput:
        path = IPV6_RULES_PATH if request.ip_family == "ipv6" else IPV4_RULES_PATH
        return await NatAdapter.from_context(ctx).create_rule(path, request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="nat_rule_update",
        title="Update a NAT rule",
        description=(
            "Partially update a NAT rule by name or UUID (operationId "
            "updateNatRuleIpv4ByIdOrName or updateNatRuleIpv6ByIdOrName, selected by the "
            "required ip_family). PATCH uses JSON Merge Patch: only the fields you set are "
            "sent, omitted fields keep their stored value, and an explicit null removes an "
            "optional property. Provide at least one field besides id_or_name."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def nat_rule_update(
        request: NatRuleUpdateInput, ctx: Context[AppContext]
    ) -> NatRuleOutput:
        path = IPV6_RULES_PATH if request.ip_family == "ipv6" else IPV4_RULES_PATH
        return await NatAdapter.from_context(ctx).update_rule(path, request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="nat_rule_delete",
        title="Delete a NAT rule",
        description=(
            "Delete one NAT rule by name or UUID (operationId deleteNatRuleIpv4ByIdOrName or "
            "deleteNatRuleIpv6ByIdOrName, selected by the required ip_family). Destructive "
            "and not reversible; the rule is removed from that family's rule base. Bulk "
            "delete is not exposed."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def nat_rule_delete(
        request: NatRuleDeleteInput, ctx: Context[AppContext]
    ) -> NatRuleDeleteOutput:
        path = IPV6_RULES_PATH if request.ip_family == "ipv6" else IPV4_RULES_PATH
        return await NatAdapter.from_context(ctx).delete_rule(path, request.id_or_name)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="nat_rule_move",
        title="Move a NAT rule",
        description=(
            "Move a NAT rule within the rule base (operationId moveNatRuleIpv4 or "
            "moveNatRuleIpv6, selected by the required ip_family). The rule is identified by "
            "name, not UUID. position is top, bottom, after or before; after/before are "
            "anchored by reference_item naming the reference rule. Reordering can change "
            "which rule matches first."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def nat_rule_move(
        request: NatRuleMoveInput, ctx: Context[AppContext]
    ) -> NatRuleMoveOutput:
        path = IPV6_MOVE_PATH if request.ip_family == "ipv6" else IPV4_MOVE_PATH
        return await NatAdapter.from_context(ctx).move_rule(path, request)
