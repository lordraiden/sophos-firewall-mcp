"""Firewall-rule tools for the Sophos Firewall Configuration REST API.

This module implements the twelve audited firewall-rule operations for IPv4 and IPv6 and
the four composite tools the curated scope adds on top of them:

=============================  ==========================================  =========
Tool                           Underlying operation(s)                     Kind
=============================  ==========================================  =========
``firewall_rule_list``         ``getAllFirewallRulesIpv4``/``Ipv6``        read
``firewall_rule_get``          ``getFirewallRuleIpv4``/``Ipv6``            read
``firewall_rule_create``       ``createFirewallRuleIpv4``/``Ipv6``         mutation
``firewall_rule_update``       ``updateFirewallRuleIpv4``/``Ipv6``         mutation
``firewall_rule_delete``       ``deleteFirewallRuleIpv4``/``Ipv6``         mutation
``firewall_rule_move``         ``moveFirewallRuleIpv4``/``Ipv6``           mutation
``firewall_rule_set_enabled``  ``updateFirewallRuleIpv4``/``Ipv6`` (PATCH) mutation
``firewall_rule_clone``        ``getFirewallRuleIpv4``/``Ipv6`` + create    mutation
=============================  ==========================================  =========

One tool per concept: the required ``ip_family`` argument selects the IPv4 or IPv6 rule
base, and the adapter picks the path. The wire body is unchanged for each family.

The composites add no new endpoint: they reuse the audited operations and are classified
as mutations, so they are not registered at all when the server runs in read-only mode.

Safety decisions encoded here:

* ``enabled`` is always sent explicitly on create (MCP default ``false``); the adapter never
  relies on the schema's ``true`` default, so a rule is never silently enabled.
* ``position`` is required on create; ``after``/``before`` require an anchor. ``move``
  identifies the rule by name only, as the operation requires.
* WAF rules are out of v1 scope. ``create`` only accepts ``ruleType: firewall``; ``get``
  and ``clone`` reject a WAF target; ``list`` omits WAF rules and reports how many it
  skipped instead of hiding them.
* The API returns no evaluation ``position`` on a rule object. The list tools
  derive it from the page offset and the item's index in the returned page; a single-object
  read or write reports ``position: null`` rather than inventing a value.
* PATCH sends only the fields the caller set (``exclude_unset=True``) with the API's
  ``application/json`` content type; an explicit ``null`` on an optional member is a JSON
  Merge Patch removal. Nothing is retried: the shared client never retries writes.
* Bulk delete exists in the API but is deliberately not registered: it is excluded
  from v1 because of its blast radius.

Annotation policy: read tools carry no write hints; every mutation declares
``destructive_hint`` and ``idempotent_hint`` explicitly. ``destructive_hint`` is true for
every non-additive mutation (update, delete, move, set_enabled) and false for the additive
ones (create, clone); ``idempotent_hint`` is true when repeating the same call leaves the
appliance in the same state (update, delete, move, set_enabled) and false for the two that
create a new rule each time. ``open_world_hint`` is left at the foundation default
(``true``): the appliance is external to the MCP process and its responses carry
administrator- and system-controlled values, so the conservative interaction-domain
classification applies.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, TypeVar
from urllib.parse import quote

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ValidationError

from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import SophosAPIError
from sophos_firewall_mcp.models.common import ObjectRef, Pages
from sophos_firewall_mcp.models.firewall import (
    CloneFirewallRuleInput,
    CreateFirewallRuleInput,
    CreateFirewallRuleIpv4Input,
    CreateFirewallRuleIpv6Input,
    DeleteFirewallRuleInput,
    DeleteFirewallRuleOutput,
    FirewallRuleOutput,
    GetFirewallRuleInput,
    ListFirewallRulesInput,
    ListFirewallRulesOutput,
    MoveFirewallRuleInput,
    MoveFirewallRuleOutput,
    SetFirewallRuleEnabledInput,
    UpdateFirewallRuleInput,
    UpdateFirewallRuleIpv4Input,
    UpdateFirewallRuleIpv6Input,
)
from sophos_firewall_mcp.tools import DomainAdapter, ToolKind, register_tool, tool_error

__all__ = ["register_firewall_tools"]

#: Collection path of the IPv4 rules (``getAllFirewallRulesIpv4`` / ``createFirewallRuleIpv4``).
_IPV4_COLLECTION = "/firewall/rules/ipv4"

#: Single-rule path template of the IPv4 rules (``{idOrName}``).
_IPV4_ITEM = "/firewall/rules/ipv4/{idOrName}"

#: Move path of the IPv4 rules (``moveFirewallRuleIpv4``).
_IPV4_MOVE = "/firewall/rules/ipv4/move"

#: Collection path of the IPv6 rules (``getAllFirewallRulesIpv6`` / ``createFirewallRuleIpv6``).
_IPV6_COLLECTION = "/firewall/rules/ipv6"

#: Single-rule path template of the IPv6 rules (``{idOrName}``).
_IPV6_ITEM = "/firewall/rules/ipv6/{idOrName}"

#: Move path of the IPv6 rules (``moveFirewallRuleIpv6``).
_IPV6_MOVE = "/firewall/rules/ipv6/move"

#: Members the appliance generates or the tool derives; they are never part of a create
#: body. ``ipFamily`` is derived from the collection that was read, not sent by the API.
_READ_ONLY_RULE_FIELDS = frozenset({"id", "createdAt", "updatedAt", "ipFamily"})

#: Message for every WAF rejection: WAF is a documented v1 exclusion, not a bug.
_WAF_EXCLUDED = (
    "WAF rules are out of scope for this tool: only firewall rules are supported "
    "(ruleType=firewall)"
)

#: Message for an update that would send an empty merge patch.
_NO_UPDATE_FIELDS = "no fields to update: supply at least one member to change"

RuleT = TypeVar("RuleT", bound=BaseModel)
CreateT = TypeVar("CreateT", bound=BaseModel)


def _item_path(template: str, identifier: str) -> str:
    """Build a single-rule path, percent-encoding the identifier as one path segment.

    The identifier was already validated (UUID or documented object name) by the input
    model; encoding here keeps a name with spaces, dots or other unreserved characters a
    single segment and prevents it from reaching the client's path validation as a
    traversal attempt.
    """
    return template.format(idOrName=quote(identifier, safe=""))


def _project_rule(payload: Mapping[str, Any], model: type[RuleT]) -> RuleT:
    """Validate an appliance rule payload into the bounded output projection."""
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        # Only the field location is echoed: the rejected input may contain appliance data.
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ())) or "body"
        raise ToolError(
            "the appliance returned a firewall rule that does not match the API " f"({location})"
        ) from exc


def _parse_ipv4_rule(payload: Mapping[str, Any]) -> FirewallRuleOutput | None:
    """Project an IPv4 rule, or return ``None`` when the payload is the excluded WAF variant.

    ``ipFamily`` is derived from the collection that was read, not from the payload: the
    API does not return it, and the merged output model requires it so a caller can tell
    the two families apart.
    """
    if payload.get("ruleType") == "waf":
        return None
    return _project_rule({**payload, "ipFamily": "ipv4"}, FirewallRuleOutput)


def _parse_ipv6_rule(payload: Mapping[str, Any]) -> FirewallRuleOutput:
    """Project an IPv6 rule (the IPv6 API has no WAF variant)."""
    return _project_rule({**payload, "ipFamily": "ipv6"}, FirewallRuleOutput)


def _require_firewall_rule(rule: RuleT | None) -> RuleT:
    """Reject the excluded WAF variant after a single-rule read or write."""
    if rule is None:
        raise ToolError(_WAF_EXCLUDED)
    return rule


def _rule_position(request: ListFirewallRulesInput, index: int) -> int:
    """Derive the 1-based evaluation position of the item at *index* in the returned page.

    The API returns no ``position`` on a rule object, so the list tools derive
    it from the page offset and the item's index in the page the appliance returned:
    ``(page - 1) * page_size + index + 1``. ``index`` counts every item in the page,
    including the WAF rules the projection omits, so a position can skip a number when a
    WAF rule precedes a firewall rule; the skipped rules are reported in
    ``wafRulesSkipped``. The value is exact for an unfiltered page; with
    ``name_contains``/``name_not_equals`` the appliance returns a filtered page, so the
    position is the one within the filtered sequence rather than the full rule base.
    """
    return (request.page - 1) * request.page_size + index + 1


def _clone_body(
    source: Mapping[str, Any],
    request: CloneFirewallRuleInput,
    model: type[CreateT],
    family: str,
) -> dict[str, Any]:
    """Build a validated create body from a source rule and the clone parameters.

    Read-only members are dropped, the new name/enabled/position are applied, and the
    result is validated against the family's create model so the clone cannot carry a
    member the create operation does not accept.
    """
    candidate = {key: value for key, value in source.items() if key not in _READ_ONLY_RULE_FIELDS}
    candidate["name"] = request.name
    candidate["enabled"] = request.enabled
    candidate["position"] = request.position
    candidate["ip_family"] = family
    if request.reference_item is not None:
        candidate["referenceItem"] = request.reference_item.model_dump(by_alias=True)
    try:
        validated = model.model_validate(candidate)
    except ValidationError as exc:
        raise ToolError(
            "the source rule cannot be cloned because its payload is not a valid create "
            "body for this IP family"
        ) from exc
    return validated.model_dump(by_alias=True, exclude_none=True, exclude={"ip_family"})


class FirewallRuleAdapter(DomainAdapter):
    """Adapter for the firewall-rule operations of both IP families.

    It owns the path constants, calls the shared REST client and projects payloads into the
    bounded output models. It never builds a URL, a header or an HTTP client, and it never
    accepts a path from a tool argument.
    """

    # -- Shared request helpers -------------------------------------------------

    async def _list(
        self,
        path: str,
        request: ListFirewallRulesInput,
        parse: Callable[[Mapping[str, Any]], RuleT | None],
    ) -> tuple[list[RuleT], Pages | None, int]:
        """Read one page and project it, counting the rules the projection skipped."""
        params: dict[str, str] = {}
        if request.name_contains is not None:
            params["nameContains"] = request.name_contains
        if request.name_not_equals is not None:
            params["nameNotEquals"] = request.name_not_equals
        try:
            payload = await self.client.get_page(
                path,
                page=request.page,
                page_size=request.page_size,
                page_total=request.page_total,
                params=params,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

        items: list[RuleT] = []
        skipped = 0
        for index, raw in enumerate(payload["items"]):
            if not isinstance(raw, Mapping):
                raise ToolError("the appliance returned a malformed firewall-rule item")
            projected = parse(raw)
            if projected is None:
                skipped += 1
            else:
                items.append(
                    projected.model_copy(update={"position": _rule_position(request, index)})
                )

        raw_pages = payload.get("pages")
        pages = Pages.model_validate(raw_pages) if raw_pages is not None else None
        return items, pages, skipped

    async def _get(self, template: str, identifier: str) -> Mapping[str, Any]:
        """Read one rule and return the raw object for the family-specific projection."""
        try:
            payload = await self.client.get(_item_path(template, identifier))
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        if not isinstance(payload, Mapping):
            raise ToolError("the appliance returned a non-object firewall-rule body")
        return payload

    async def _post(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        """POST a body and return the created object."""
        try:
            payload = await self.client.post(path, json=body)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        if not isinstance(payload, Mapping):
            raise ToolError("the appliance returned a non-object firewall-rule body")
        return payload

    async def _patch(
        self, template: str, identifier: str, body: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """PATCH a partial body and return the updated object."""
        try:
            payload = await self.client.patch(_item_path(template, identifier), json=body)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        if not isinstance(payload, Mapping):
            raise ToolError("the appliance returned a non-object firewall-rule body")
        return payload

    async def _delete(self, template: str, identifier: str) -> Any:
        """DELETE one rule and return the decoded body (``None`` for an empty response)."""
        try:
            return await self.client.delete(_item_path(template, identifier))
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def _move(self, path: str, body: Mapping[str, Any]) -> None:
        """POST a move request; a 200 means the appliance accepted the new position."""
        try:
            await self.client.post(path, json=body)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    # -- Operations (one method per concept; ``ip_family`` selects the path) ------

    async def list_rules(self, request: ListFirewallRulesInput) -> ListFirewallRulesOutput:
        """List one page of the IPv4 or IPv6 rule base."""
        if request.ip_family == "ipv6":
            return await self.list_ipv6(request)
        return await self.list_ipv4(request)

    async def list_ipv4(self, request: ListFirewallRulesInput) -> ListFirewallRulesOutput:
        items, pages, skipped = await self._list(_IPV4_COLLECTION, request, _parse_ipv4_rule)
        return ListFirewallRulesOutput(items=items, pages=pages, wafRulesSkipped=skipped)

    async def list_ipv6(self, request: ListFirewallRulesInput) -> ListFirewallRulesOutput:
        items, pages, _ = await self._list(_IPV6_COLLECTION, request, _parse_ipv6_rule)
        return ListFirewallRulesOutput(items=items, pages=pages)

    async def get_rule(self, request: GetFirewallRuleInput) -> FirewallRuleOutput:
        """Read one rule from the IPv4 or IPv6 rule base."""
        if request.ip_family == "ipv6":
            return await self.get_ipv6(request)
        return await self.get_ipv4(request)

    async def get_ipv4(self, request: GetFirewallRuleInput) -> FirewallRuleOutput:
        payload = await self._get(_IPV4_ITEM, request.id_or_name)
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def get_ipv6(self, request: GetFirewallRuleInput) -> FirewallRuleOutput:
        payload = await self._get(_IPV6_ITEM, request.id_or_name)
        return _parse_ipv6_rule(payload)

    async def create_rule(self, request: CreateFirewallRuleInput) -> FirewallRuleOutput:
        """Create a rule in the IPv4 or IPv6 rule base."""
        if request.ip_family == "ipv6":
            return await self.create_ipv6(request)
        return await self.create_ipv4(request)

    async def create_ipv4(self, request: CreateFirewallRuleIpv4Input) -> FirewallRuleOutput:
        body = request.model_dump(by_alias=True, exclude_none=True, exclude={"ip_family"})
        payload = await self._post(_IPV4_COLLECTION, body)
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def create_ipv6(self, request: CreateFirewallRuleIpv6Input) -> FirewallRuleOutput:
        body = request.model_dump(by_alias=True, exclude_none=True, exclude={"ip_family"})
        payload = await self._post(_IPV6_COLLECTION, body)
        return _parse_ipv6_rule(payload)

    async def update_rule(self, request: UpdateFirewallRuleInput) -> FirewallRuleOutput:
        """Partially update a rule in the IPv4 or IPv6 rule base."""
        if request.ip_family == "ipv6":
            return await self.update_ipv6(request)
        return await self.update_ipv4(request)

    async def update_ipv4(self, request: UpdateFirewallRuleIpv4Input) -> FirewallRuleOutput:
        body = request.model_dump(
            by_alias=True, exclude_unset=True, exclude={"id_or_name", "ip_family"}
        )
        if not body:
            raise ToolError(_NO_UPDATE_FIELDS)
        payload = await self._patch(_IPV4_ITEM, request.id_or_name, body)
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def update_ipv6(self, request: UpdateFirewallRuleIpv6Input) -> FirewallRuleOutput:
        body = request.model_dump(
            by_alias=True, exclude_unset=True, exclude={"id_or_name", "ip_family"}
        )
        if not body:
            raise ToolError(_NO_UPDATE_FIELDS)
        payload = await self._patch(_IPV6_ITEM, request.id_or_name, body)
        return _parse_ipv6_rule(payload)

    async def delete_rule(self, request: DeleteFirewallRuleInput) -> DeleteFirewallRuleOutput:
        """Delete one rule from the IPv4 or IPv6 rule base."""
        template = _IPV6_ITEM if request.ip_family == "ipv6" else _IPV4_ITEM
        payload = await self._delete(template, request.id_or_name)
        return _delete_output(payload, request.id_or_name)

    async def move_rule(self, request: MoveFirewallRuleInput) -> MoveFirewallRuleOutput:
        """Move one rule within the IPv4 or IPv6 rule base."""
        path = _IPV6_MOVE if request.ip_family == "ipv6" else _IPV4_MOVE
        body = request.model_dump(by_alias=True, exclude_none=True, exclude={"ip_family"})
        await self._move(path, body)
        return _move_output(request)

    async def set_enabled(self, request: SetFirewallRuleEnabledInput) -> FirewallRuleOutput:
        """Enable or disable one rule in the IPv4 or IPv6 rule base."""
        template = _IPV6_ITEM if request.ip_family == "ipv6" else _IPV4_ITEM
        payload = await self._patch(template, request.id_or_name, {"enabled": request.enabled})
        if request.ip_family == "ipv6":
            return _parse_ipv6_rule(payload)
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def clone_rule(self, request: CloneFirewallRuleInput) -> FirewallRuleOutput:
        """Clone one rule within the IPv4 or IPv6 rule base."""
        if request.ip_family == "ipv6":
            return await self.clone_ipv6(request)
        return await self.clone_ipv4(request)

    async def clone_ipv4(self, request: CloneFirewallRuleInput) -> FirewallRuleOutput:
        source = await self._get(_IPV4_ITEM, request.source)
        if source.get("ruleType") == "waf":
            raise ToolError(_WAF_EXCLUDED)
        body = _clone_body(source, request, CreateFirewallRuleIpv4Input, "ipv4")
        payload = await self._post(_IPV4_COLLECTION, body)
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def clone_ipv6(self, request: CloneFirewallRuleInput) -> FirewallRuleOutput:
        source = await self._get(_IPV6_ITEM, request.source)
        body = _clone_body(source, request, CreateFirewallRuleIpv6Input, "ipv6")
        payload = await self._post(_IPV6_COLLECTION, body)
        return _parse_ipv6_rule(payload)


def _delete_output(payload: Any, identifier: str) -> DeleteFirewallRuleOutput:
    """Project the delete response, treating a 200 without a body as a confirmed delete."""
    deleted = True
    if isinstance(payload, Mapping):
        raw = payload.get("deleted")
        if isinstance(raw, bool):
            deleted = raw
    return DeleteFirewallRuleOutput(deleted=deleted, idOrName=identifier)


def _move_output(request: MoveFirewallRuleInput) -> MoveFirewallRuleOutput:
    """Echo the accepted move request; the operation's 200 body is empty."""
    anchor = None if request.reference_item is None else ObjectRef(name=request.reference_item.name)
    return MoveFirewallRuleOutput(
        name=request.name, position=request.position, referenceItem=anchor
    )


def register_firewall_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the eight firewall-rule tools on *server*.

    In read-only mode the two read tools are registered and the six mutation tools
    (create, update, delete, move, set_enabled, clone) are not: the filter lives in
    :func:`~sophos_firewall_mcp.tools.register_tool`, so a read-only deployment does not
    merely hide them.
    """

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="firewall_rule_list",
        title="List firewall rules",
        description=(
            "List one page of firewall rules (getAllFirewallRulesIpv4 or "
            "getAllFirewallRulesIpv6, selected by the required ip_family). Returns at most "
            "pageSize rules plus the appliance's pages metadata; it never walks the "
            "collection automatically. page_size defaults to 10. Filter by name with "
            "nameContains or nameNotEquals (mutually exclusive). Each rule carries its "
            "1-based evaluation position, derived from the page offset and its index in the "
            "returned page, and its ipFamily. WAF rules are out of scope: they are omitted "
            "and counted in wafRulesSkipped (always 0 for IPv6, which has no WAF variant). "
            "Size: the tested appliance's 48-rule base is ~70 KB of JSON, so keep page_size "
            "small and page through the collection. The MCP SDK returns the payload both as "
            "a text block and as structuredContent; read one of them, not both. Read-only."
        ),
    )
    async def firewall_rule_list(
        request: ListFirewallRulesInput, ctx: Context[AppContext]
    ) -> ListFirewallRulesOutput:
        return await FirewallRuleAdapter.from_context(ctx).list_rules(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="firewall_rule_get",
        title="Get a firewall rule",
        description=(
            "Read one firewall rule by id or name (getFirewallRuleIpv4 or "
            "getFirewallRuleIpv6, selected by the required ip_family). Returns the applied "
            "enabled state, the action, the logging flag, the schedule and the match "
            "criteria. position is null: the API does not return the evaluation position on "
            "a single-object read, so use firewall_rule_list to obtain it. WAF rules are out "
            "of scope and are rejected on the IPv4 rule base. Read-only."
        ),
    )
    async def firewall_rule_get(
        request: GetFirewallRuleInput, ctx: Context[AppContext]
    ) -> FirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).get_rule(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_create",
        title="Create a firewall rule",
        description=(
            "Create a firewall rule (createFirewallRuleIpv4 or createFirewallRuleIpv6, "
            "selected by the required ip_family). enabled is always sent explicitly and "
            "defaults to false, so the rule is created disabled unless enabled=true is "
            "passed. position is required (after|before|bottom|top); after and before need a "
            "referenceItem naming the anchor rule. ruleType is always firewall: WAF rules "
            "are out of scope. Returns the created rule with its applied enabled state."
        ),
        annotations=ToolAnnotations(destructive_hint=False, idempotent_hint=False),
    )
    async def firewall_rule_create(
        request: CreateFirewallRuleInput, ctx: Context[AppContext]
    ) -> FirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).create_rule(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_update",
        title="Update a firewall rule",
        description=(
            "Partially update a firewall rule (updateFirewallRuleIpv4 or "
            "updateFirewallRuleIpv6, selected by the required ip_family; JSON Merge Patch). "
            "Only the members supplied are sent; omitted members keep their persisted value, "
            "and an explicit null on an optional member removes it. The rule is identified "
            "by idOrName. Returns the updated rule."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def firewall_rule_update(
        request: UpdateFirewallRuleInput, ctx: Context[AppContext]
    ) -> FirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).update_rule(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_delete",
        title="Delete a firewall rule",
        description=(
            "Delete one firewall rule by id or name (deleteFirewallRuleIpv4 or "
            "deleteFirewallRuleIpv6, selected by the required ip_family). Destructive and "
            "irreversible: the rule is removed from that family's rule base. Returns whether "
            "the appliance confirmed the deletion."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def firewall_rule_delete(
        request: DeleteFirewallRuleInput, ctx: Context[AppContext]
    ) -> DeleteFirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).delete_rule(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_move",
        title="Move a firewall rule",
        description=(
            "Move a firewall rule to a new position (moveFirewallRuleIpv4 or "
            "moveFirewallRuleIpv6, selected by the required ip_family). The rule is "
            "identified by name only, not by idOrName. position is after|before|bottom|top; "
            "after and before need a referenceItem naming the anchor rule. Reordering "
            "changes which rule matches first."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def firewall_rule_move(
        request: MoveFirewallRuleInput, ctx: Context[AppContext]
    ) -> MoveFirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).move_rule(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_set_enabled",
        title="Enable or disable a firewall rule",
        description=(
            "Enable or disable a firewall rule by PATCHing only enabled "
            "(updateFirewallRuleIpv4 or updateFirewallRuleIpv6, selected by the required "
            "ip_family). enabled is required: the caller must choose the target state, so a "
            "missing value can never silently disable a rule. Returns the rule with the "
            "applied enabled state."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def firewall_rule_set_enabled(
        request: SetFirewallRuleEnabledInput, ctx: Context[AppContext]
    ) -> FirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).set_enabled(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_clone",
        title="Clone a firewall rule",
        description=(
            "Clone a firewall rule: read the source (getFirewallRuleIpv4 or "
            "getFirewallRuleIpv6) and create a copy (createFirewallRuleIpv4 or "
            "createFirewallRuleIpv6) with a new name and position, selected by the required "
            "ip_family. The clone is created disabled unless enabled=true is passed; "
            "read-only members are not copied. position is required and after/before need a "
            "referenceItem. WAF sources are rejected on the IPv4 rule base."
        ),
        annotations=ToolAnnotations(destructive_hint=False, idempotent_hint=False),
    )
    async def firewall_rule_clone(
        request: CloneFirewallRuleInput, ctx: Context[AppContext]
    ) -> FirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).clone_rule(request)
