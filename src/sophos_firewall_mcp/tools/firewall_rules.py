"""Firewall-rule tools (issue #27) for the Sophos Firewall Configuration REST API.

This module implements the twelve audited firewall-rule operations for IPv4 and IPv6 and
the four composite tools the curated scope adds on top of them:

==============================  ==========================================  =========
Tool                            Underlying operation(s)                     Kind
==============================  ==========================================  =========
``firewall_rule_list_ipv4``     ``getAllFirewallRulesIpv4``                 read
``firewall_rule_list_ipv6``     ``getAllFirewallRulesIpv6``                 read
``firewall_rule_get_ipv4``      ``getFirewallRuleIpv4``                     read
``firewall_rule_get_ipv6``      ``getFirewallRuleIpv6``                     read
``firewall_rule_create_ipv4``   ``createFirewallRuleIpv4``                  mutation
``firewall_rule_create_ipv6``   ``createFirewallRuleIpv6``                  mutation
``firewall_rule_update_ipv4``   ``updateFirewallRuleIpv4``                  mutation
``firewall_rule_update_ipv6``   ``updateFirewallRuleIpv6``                  mutation
``firewall_rule_delete_ipv4``   ``deleteFirewallRuleIpv4``                  mutation
``firewall_rule_delete_ipv6``   ``deleteFirewallRuleIpv6``                  mutation
``firewall_rule_move_ipv4``     ``moveFirewallRuleIpv4``                    mutation
``firewall_rule_move_ipv6``     ``moveFirewallRuleIpv6``                    mutation
``firewall_rule_set_enabled_ipv4``  ``updateFirewallRuleIpv4`` (PATCH)      mutation
``firewall_rule_set_enabled_ipv6``  ``updateFirewallRuleIpv6`` (PATCH)      mutation
``firewall_rule_clone_ipv4``    ``getFirewallRuleIpv4`` + create            mutation
``firewall_rule_clone_ipv6``    ``getFirewallRuleIpv6`` + create            mutation
==============================  ==========================================  =========

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
* PATCH sends only the fields the caller set (``exclude_unset=True``) with the contract's
  ``application/json`` content type; an explicit ``null`` on an optional member is a JSON
  Merge Patch removal. Nothing is retried: the shared client never retries writes.
* Bulk delete exists in the contract but is deliberately not registered: it is excluded
  from v1 because of its blast radius.

Annotation policy: read tools carry no write hints; every mutation declares
``destructive_hint`` and ``idempotent_hint`` explicitly. ``destructive_hint`` is true for
every non-additive mutation (update, delete, move, set_enabled) and false for the additive
ones (create, clone); ``idempotent_hint`` is true when repeating the same call leaves the
appliance in the same state (update, delete, move, set_enabled) and false for the two that
create a new rule each time. ``open_world_hint`` is false everywhere: the appliance is a
fixed, closed endpoint.
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
    CreateFirewallRuleIpv4Input,
    CreateFirewallRuleIpv6Input,
    DeleteFirewallRuleInput,
    DeleteFirewallRuleOutput,
    FirewallRuleIpv4Output,
    FirewallRuleIpv6Output,
    GetFirewallRuleInput,
    ListFirewallRulesInput,
    ListFirewallRulesIpv4Output,
    ListFirewallRulesIpv6Output,
    MoveFirewallRuleInput,
    MoveFirewallRuleOutput,
    SetFirewallRuleEnabledInput,
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

#: Members the appliance generates; they are never part of a create body.
_READ_ONLY_RULE_FIELDS = frozenset({"id", "createdAt", "updatedAt"})

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
            "the appliance returned a firewall rule that does not match the contract "
            f"({location})"
        ) from exc


def _parse_ipv4_rule(payload: Mapping[str, Any]) -> FirewallRuleIpv4Output | None:
    """Project an IPv4 rule, or return ``None`` when the payload is the excluded WAF variant."""
    if payload.get("ruleType") == "waf":
        return None
    return _project_rule(payload, FirewallRuleIpv4Output)


def _parse_ipv6_rule(payload: Mapping[str, Any]) -> FirewallRuleIpv6Output:
    """Project an IPv6 rule (the IPv6 contract has no WAF variant)."""
    return _project_rule(payload, FirewallRuleIpv6Output)


def _require_firewall_rule(rule: RuleT | None) -> RuleT:
    """Reject the excluded WAF variant after a single-rule read or write."""
    if rule is None:
        raise ToolError(_WAF_EXCLUDED)
    return rule


def _clone_body(
    source: Mapping[str, Any],
    request: CloneFirewallRuleInput,
    model: type[CreateT],
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
    if request.referenceItem is not None:
        candidate["referenceItem"] = request.referenceItem.model_dump()
    try:
        validated = model.model_validate(candidate)
    except ValidationError as exc:
        raise ToolError(
            "the source rule cannot be cloned because its payload is not a valid create "
            "body for this IP family"
        ) from exc
    return validated.model_dump(exclude_none=True)


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
        if request.nameContains is not None:
            params["nameContains"] = request.nameContains
        if request.nameNotEquals is not None:
            params["nameNotEquals"] = request.nameNotEquals
        try:
            payload = await self.client.get_page(
                path,
                page=request.page,
                page_size=request.pageSize,
                page_total=request.pageTotal,
                params=params,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

        items: list[RuleT] = []
        skipped = 0
        for raw in payload["items"]:
            if not isinstance(raw, Mapping):
                raise ToolError("the appliance returned a malformed firewall-rule item")
            projected = parse(raw)
            if projected is None:
                skipped += 1
            else:
                items.append(projected)

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

    # -- IPv4 operations --------------------------------------------------------

    async def list_ipv4(self, request: ListFirewallRulesInput) -> ListFirewallRulesIpv4Output:
        items, pages, skipped = await self._list(_IPV4_COLLECTION, request, _parse_ipv4_rule)
        return ListFirewallRulesIpv4Output(items=items, pages=pages, wafRulesSkipped=skipped)

    async def get_ipv4(self, request: GetFirewallRuleInput) -> FirewallRuleIpv4Output:
        payload = await self._get(_IPV4_ITEM, request.idOrName)
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def create_ipv4(self, request: CreateFirewallRuleIpv4Input) -> FirewallRuleIpv4Output:
        payload = await self._post(_IPV4_COLLECTION, request.model_dump(exclude_none=True))
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def update_ipv4(self, request: UpdateFirewallRuleIpv4Input) -> FirewallRuleIpv4Output:
        body = request.model_dump(exclude_unset=True, exclude={"idOrName"})
        if not body:
            raise ToolError(_NO_UPDATE_FIELDS)
        payload = await self._patch(_IPV4_ITEM, request.idOrName, body)
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def delete_ipv4(self, request: DeleteFirewallRuleInput) -> DeleteFirewallRuleOutput:
        payload = await self._delete(_IPV4_ITEM, request.idOrName)
        return _delete_output(payload, request.idOrName)

    async def move_ipv4(self, request: MoveFirewallRuleInput) -> MoveFirewallRuleOutput:
        await self._move(_IPV4_MOVE, request.model_dump(exclude_none=True))
        return _move_output(request)

    async def set_enabled_ipv4(
        self, request: SetFirewallRuleEnabledInput
    ) -> FirewallRuleIpv4Output:
        payload = await self._patch(_IPV4_ITEM, request.idOrName, {"enabled": request.enabled})
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    async def clone_ipv4(self, request: CloneFirewallRuleInput) -> FirewallRuleIpv4Output:
        source = await self._get(_IPV4_ITEM, request.source)
        if source.get("ruleType") == "waf":
            raise ToolError(_WAF_EXCLUDED)
        body = _clone_body(source, request, CreateFirewallRuleIpv4Input)
        payload = await self._post(_IPV4_COLLECTION, body)
        return _require_firewall_rule(_parse_ipv4_rule(payload))

    # -- IPv6 operations --------------------------------------------------------

    async def list_ipv6(self, request: ListFirewallRulesInput) -> ListFirewallRulesIpv6Output:
        items, pages, _ = await self._list(_IPV6_COLLECTION, request, _parse_ipv6_rule)
        return ListFirewallRulesIpv6Output(items=items, pages=pages)

    async def get_ipv6(self, request: GetFirewallRuleInput) -> FirewallRuleIpv6Output:
        payload = await self._get(_IPV6_ITEM, request.idOrName)
        return _parse_ipv6_rule(payload)

    async def create_ipv6(self, request: CreateFirewallRuleIpv6Input) -> FirewallRuleIpv6Output:
        payload = await self._post(_IPV6_COLLECTION, request.model_dump(exclude_none=True))
        return _parse_ipv6_rule(payload)

    async def update_ipv6(self, request: UpdateFirewallRuleIpv6Input) -> FirewallRuleIpv6Output:
        body = request.model_dump(exclude_unset=True, exclude={"idOrName"})
        if not body:
            raise ToolError(_NO_UPDATE_FIELDS)
        payload = await self._patch(_IPV6_ITEM, request.idOrName, body)
        return _parse_ipv6_rule(payload)

    async def delete_ipv6(self, request: DeleteFirewallRuleInput) -> DeleteFirewallRuleOutput:
        payload = await self._delete(_IPV6_ITEM, request.idOrName)
        return _delete_output(payload, request.idOrName)

    async def move_ipv6(self, request: MoveFirewallRuleInput) -> MoveFirewallRuleOutput:
        await self._move(_IPV6_MOVE, request.model_dump(exclude_none=True))
        return _move_output(request)

    async def set_enabled_ipv6(
        self, request: SetFirewallRuleEnabledInput
    ) -> FirewallRuleIpv6Output:
        payload = await self._patch(_IPV6_ITEM, request.idOrName, {"enabled": request.enabled})
        return _parse_ipv6_rule(payload)

    async def clone_ipv6(self, request: CloneFirewallRuleInput) -> FirewallRuleIpv6Output:
        source = await self._get(_IPV6_ITEM, request.source)
        body = _clone_body(source, request, CreateFirewallRuleIpv6Input)
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
    anchor = None if request.referenceItem is None else ObjectRef(name=request.referenceItem.name)
    return MoveFirewallRuleOutput(
        name=request.name, position=request.position, referenceItem=anchor
    )


def register_firewall_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the firewall-rule tools on *server*.

    In read-only mode the four read tools are registered and the twelve mutation tools
    (create, update, delete, move, set_enabled, clone for both families) are not: the
    filter lives in :func:`~sophos_firewall_mcp.tools.register_tool`, so a read-only
    deployment does not merely hide them.
    """

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="firewall_rule_list_ipv4",
        title="List IPv4 firewall rules",
        description=(
            "List one page of IPv4 firewall rules (getAllFirewallRulesIpv4). Returns at "
            "most pageSize rules plus the appliance's pages metadata; it never walks the "
            "collection automatically. Filter by name with nameContains or nameNotEquals "
            "(mutually exclusive). WAF rules are out of scope: they are omitted and "
            "counted in wafRulesSkipped. Read-only."
        ),
        annotations=ToolAnnotations(open_world_hint=False),
    )
    async def firewall_rule_list_ipv4(
        request: ListFirewallRulesInput, ctx: Context[AppContext]
    ) -> ListFirewallRulesIpv4Output:
        return await FirewallRuleAdapter.from_context(ctx).list_ipv4(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="firewall_rule_list_ipv6",
        title="List IPv6 firewall rules",
        description=(
            "List one page of IPv6 firewall rules (getAllFirewallRulesIpv6). Returns at "
            "most pageSize rules plus the appliance's pages metadata; it never walks the "
            "collection automatically. Filter by name with nameContains or nameNotEquals "
            "(mutually exclusive). Read-only."
        ),
        annotations=ToolAnnotations(open_world_hint=False),
    )
    async def firewall_rule_list_ipv6(
        request: ListFirewallRulesInput, ctx: Context[AppContext]
    ) -> ListFirewallRulesIpv6Output:
        return await FirewallRuleAdapter.from_context(ctx).list_ipv6(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="firewall_rule_get_ipv4",
        title="Get an IPv4 firewall rule",
        description=(
            "Read one IPv4 firewall rule by id or name (getFirewallRuleIpv4). Returns the "
            "applied enabled state, the action, the logging flag, the schedule and the "
            "match criteria. WAF rules are out of scope and are rejected. Read-only."
        ),
        annotations=ToolAnnotations(open_world_hint=False),
    )
    async def firewall_rule_get_ipv4(
        request: GetFirewallRuleInput, ctx: Context[AppContext]
    ) -> FirewallRuleIpv4Output:
        return await FirewallRuleAdapter.from_context(ctx).get_ipv4(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="firewall_rule_get_ipv6",
        title="Get an IPv6 firewall rule",
        description=(
            "Read one IPv6 firewall rule by id or name (getFirewallRuleIpv6). Returns the "
            "applied enabled state, the action, the logging flag, the schedule and the "
            "match criteria. Read-only."
        ),
        annotations=ToolAnnotations(open_world_hint=False),
    )
    async def firewall_rule_get_ipv6(
        request: GetFirewallRuleInput, ctx: Context[AppContext]
    ) -> FirewallRuleIpv6Output:
        return await FirewallRuleAdapter.from_context(ctx).get_ipv6(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_create_ipv4",
        title="Create an IPv4 firewall rule",
        description=(
            "Create an IPv4 firewall rule (createFirewallRuleIpv4). enabled is always sent "
            "explicitly and defaults to false, so the rule is created disabled unless "
            "enabled=true is passed. position is required (after|before|bottom|top); after "
            "and before need a referenceItem naming the anchor rule. ruleType is always "
            "firewall: WAF rules are out of scope. Returns the created rule with its "
            "applied enabled state."
        ),
        annotations=ToolAnnotations(
            destructive_hint=False, idempotent_hint=False, open_world_hint=False
        ),
    )
    async def firewall_rule_create_ipv4(
        request: CreateFirewallRuleIpv4Input, ctx: Context[AppContext]
    ) -> FirewallRuleIpv4Output:
        return await FirewallRuleAdapter.from_context(ctx).create_ipv4(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_create_ipv6",
        title="Create an IPv6 firewall rule",
        description=(
            "Create an IPv6 firewall rule (createFirewallRuleIpv6). enabled is always sent "
            "explicitly and defaults to false, so the rule is created disabled unless "
            "enabled=true is passed. position is required (after|before|bottom|top); after "
            "and before need a referenceItem naming the anchor rule. Returns the created "
            "rule with its applied enabled state."
        ),
        annotations=ToolAnnotations(
            destructive_hint=False, idempotent_hint=False, open_world_hint=False
        ),
    )
    async def firewall_rule_create_ipv6(
        request: CreateFirewallRuleIpv6Input, ctx: Context[AppContext]
    ) -> FirewallRuleIpv6Output:
        return await FirewallRuleAdapter.from_context(ctx).create_ipv6(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_update_ipv4",
        title="Update an IPv4 firewall rule",
        description=(
            "Partially update an IPv4 firewall rule (updateFirewallRuleIpv4, JSON Merge "
            "Patch). Only the members supplied are sent; omitted members keep their "
            "persisted value, and an explicit null on an optional member removes it. The "
            "rule is identified by idOrName. Returns the updated rule."
        ),
        annotations=ToolAnnotations(
            destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def firewall_rule_update_ipv4(
        request: UpdateFirewallRuleIpv4Input, ctx: Context[AppContext]
    ) -> FirewallRuleIpv4Output:
        return await FirewallRuleAdapter.from_context(ctx).update_ipv4(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_update_ipv6",
        title="Update an IPv6 firewall rule",
        description=(
            "Partially update an IPv6 firewall rule (updateFirewallRuleIpv6, JSON Merge "
            "Patch). Only the members supplied are sent; omitted members keep their "
            "persisted value, and an explicit null on an optional member removes it. The "
            "rule is identified by idOrName. Returns the updated rule."
        ),
        annotations=ToolAnnotations(
            destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def firewall_rule_update_ipv6(
        request: UpdateFirewallRuleIpv6Input, ctx: Context[AppContext]
    ) -> FirewallRuleIpv6Output:
        return await FirewallRuleAdapter.from_context(ctx).update_ipv6(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_delete_ipv4",
        title="Delete an IPv4 firewall rule",
        description=(
            "Delete one IPv4 firewall rule by id or name (deleteFirewallRuleIpv4). "
            "Destructive and irreversible: the rule is removed from the rule base. "
            "Returns whether the appliance confirmed the deletion."
        ),
        annotations=ToolAnnotations(
            destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def firewall_rule_delete_ipv4(
        request: DeleteFirewallRuleInput, ctx: Context[AppContext]
    ) -> DeleteFirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).delete_ipv4(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_delete_ipv6",
        title="Delete an IPv6 firewall rule",
        description=(
            "Delete one IPv6 firewall rule by id or name (deleteFirewallRuleIpv6). "
            "Destructive and irreversible: the rule is removed from the rule base. "
            "Returns whether the appliance confirmed the deletion."
        ),
        annotations=ToolAnnotations(
            destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def firewall_rule_delete_ipv6(
        request: DeleteFirewallRuleInput, ctx: Context[AppContext]
    ) -> DeleteFirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).delete_ipv6(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_move_ipv4",
        title="Move an IPv4 firewall rule",
        description=(
            "Move an IPv4 firewall rule to a new position (moveFirewallRuleIpv4). The rule "
            "is identified by name only, not by idOrName. position is "
            "after|before|bottom|top; after and before need a referenceItem naming the "
            "anchor rule. Reordering changes which rule matches first."
        ),
        annotations=ToolAnnotations(
            destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def firewall_rule_move_ipv4(
        request: MoveFirewallRuleInput, ctx: Context[AppContext]
    ) -> MoveFirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).move_ipv4(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_move_ipv6",
        title="Move an IPv6 firewall rule",
        description=(
            "Move an IPv6 firewall rule to a new position (moveFirewallRuleIpv6). The rule "
            "is identified by name only, not by idOrName. position is "
            "after|before|bottom|top; after and before need a referenceItem naming the "
            "anchor rule. Reordering changes which rule matches first."
        ),
        annotations=ToolAnnotations(
            destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def firewall_rule_move_ipv6(
        request: MoveFirewallRuleInput, ctx: Context[AppContext]
    ) -> MoveFirewallRuleOutput:
        return await FirewallRuleAdapter.from_context(ctx).move_ipv6(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_set_enabled_ipv4",
        title="Enable or disable an IPv4 firewall rule",
        description=(
            "Enable or disable an IPv4 firewall rule by PATCHing only enabled "
            "(updateFirewallRuleIpv4). enabled is required: the caller must choose the "
            "target state, so a missing value can never silently disable a rule. Returns "
            "the rule with the applied enabled state."
        ),
        annotations=ToolAnnotations(
            destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def firewall_rule_set_enabled_ipv4(
        request: SetFirewallRuleEnabledInput, ctx: Context[AppContext]
    ) -> FirewallRuleIpv4Output:
        return await FirewallRuleAdapter.from_context(ctx).set_enabled_ipv4(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_set_enabled_ipv6",
        title="Enable or disable an IPv6 firewall rule",
        description=(
            "Enable or disable an IPv6 firewall rule by PATCHing only enabled "
            "(updateFirewallRuleIpv6). enabled is required: the caller must choose the "
            "target state, so a missing value can never silently disable a rule. Returns "
            "the rule with the applied enabled state."
        ),
        annotations=ToolAnnotations(
            destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def firewall_rule_set_enabled_ipv6(
        request: SetFirewallRuleEnabledInput, ctx: Context[AppContext]
    ) -> FirewallRuleIpv6Output:
        return await FirewallRuleAdapter.from_context(ctx).set_enabled_ipv6(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_clone_ipv4",
        title="Clone an IPv4 firewall rule",
        description=(
            "Clone an IPv4 firewall rule: read the source (getFirewallRuleIpv4) and create "
            "a copy (createFirewallRuleIpv4) with a new name and position. The clone is "
            "created disabled unless enabled=true is passed; read-only members are not "
            "copied. position is required and after/before need a referenceItem. WAF "
            "sources are rejected."
        ),
        annotations=ToolAnnotations(
            destructive_hint=False, idempotent_hint=False, open_world_hint=False
        ),
    )
    async def firewall_rule_clone_ipv4(
        request: CloneFirewallRuleInput, ctx: Context[AppContext]
    ) -> FirewallRuleIpv4Output:
        return await FirewallRuleAdapter.from_context(ctx).clone_ipv4(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="firewall_rule_clone_ipv6",
        title="Clone an IPv6 firewall rule",
        description=(
            "Clone an IPv6 firewall rule: read the source (getFirewallRuleIpv6) and create "
            "a copy (createFirewallRuleIpv6) with a new name and position. The clone is "
            "created disabled unless enabled=true is passed; read-only members are not "
            "copied. position is required and after/before need a referenceItem."
        ),
        annotations=ToolAnnotations(
            destructive_hint=False, idempotent_hint=False, open_world_hint=False
        ),
    )
    async def firewall_rule_clone_ipv6(
        request: CloneFirewallRuleInput, ctx: Context[AppContext]
    ) -> FirewallRuleIpv6Output:
        return await FirewallRuleAdapter.from_context(ctx).clone_ipv6(request)
