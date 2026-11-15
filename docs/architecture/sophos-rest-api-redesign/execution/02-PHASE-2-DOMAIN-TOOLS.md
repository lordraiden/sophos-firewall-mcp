# 02 — Phase 2: Domain tools (#27–#31, #35)

> **Before starting:** read and apply [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md). **Precondition:** phase 1 is merged (PR #36 on `main`): `AppContext`, the `register_<domain>_tools(...)` signature, the REST client, the error hierarchy, `DomainAdapter` and `register_tool`/`tool_error` are available.
>
> **Scope revision (15 Nov 2026).** This phase implements the **145-operation / 152-tool / 11-domain** surface in [ADR-001 §10](../ADR-001-rest-client-strategy.md) and [API-COVERAGE.md §4](../../API-COVERAGE.md), not the original 96-operation table. The differences that matter here: **MAC addresses are full CRUD**, **country groups are read-only**, **interface writes are VLAN-only**, the **network-architecture domain** exists, firewall gains **enable/disable + clone**, and the **#35 audit domain** is part of this phase.

## Phase objective

Implement the six domain tool families on top of the phase 1 foundation, with typed contracts, tests and coverage, **without touching the foundation**.

**Issues:** [#27](https://github.com/lordraiden/sophos-firewall-mcp/issues/27) firewall rules, [#28](https://github.com/lordraiden/sophos-firewall-mcp/issues/28) NAT rules, [#29](https://github.com/lordraiden/sophos-firewall-mcp/issues/29) objects and services, [#30](https://github.com/lordraiden/sophos-firewall-mcp/issues/30) users and sessions, [#31](https://github.com/lordraiden/sophos-firewall-mcp/issues/31) network architecture, VPN read-only and status, [#35](https://github.com/lordraiden/sophos-firewall-mcp/issues/35) audit and explanation.

**Out of scope:** changes to `client.py`, `config.py`, `context.py`, `tools/__init__.py`, `pyproject.toml`, CI, Docker or release. `server.py` is touched **only by the Lead**, at integration, to wire `DEFAULT_DOMAINS`. If a domain needs a foundation change, ask the Lead and it becomes a separate task.

## Preflight (Lead)

1. Verify on `main` that `AppContext`, the `register_<domain>_tools(server, *, read_only)` signature, `SophosRestClient`, `SophosAPIError`, `DomainAdapter`, `register_tool` and `tool_error` exist and are documented. If not, **stop**: phase 1 is not ready.
2. Create branch `migration/phase-2-domain-tools`.
3. Create the **shared models layer** before the domains start (the Lead owns it): `models/common.py` with `Pages`, `ListPage[T]`, `ObjectRef` and the `sfos-object-name` validator. Domains read it; if they need a change, they ask the Lead. This prevents six divergent copies of the same primitives.
4. Create tasks T27–T31, T35 and T-review with disjoint `write_scopes`. T35 is `blocked_by` T27/T28/T29/T31 (it composes their adapters); T-review is blocked by all six.
5. Create `firewall`, `nat`, `objects`, `users`, `network`, `audit`, `reviewer`.
6. Assign one task per agent and send the work prompt. The first five run in parallel (disjoint files); `audit` starts when its blockers complete.

## Write ownership (disjoint)

| Member | Issue | Writes (exclusive) |
|---|---|---|
| `firewall` | #27 | `src/sophos_firewall_mcp/tools/firewall_rules.py`, `models/firewall.py`, `tests/test_firewall_rules.py` |
| `nat` | #28 | `tools/nat_rules.py`, `models/nat.py`, `tests/test_nat_rules.py` |
| `objects` | #29 | `tools/hosts_objects.py`, `tools/services_objects.py`, `models/objects.py`, `tests/test_hosts_objects.py`, `tests/test_services_objects.py` |
| `users` | #30 | `tools/users_auth.py`, `models/users.py`, `tests/test_users_auth.py` |
| `network` | #31 | `tools/network.py`, `tools/vpn.py`, `tools/system.py`, `models/network.py`, `models/vpn.py`, `tests/test_network.py`, `tests/test_vpn.py`, `tests/test_system.py` |
| `audit` | #35 | `tools/audit.py`, `models/audit.py`, `tests/test_audit.py` |
| `reviewer` | — | nothing (report only) |
| Lead | integration | `server.py` (`DEFAULT_DOMAINS`), `models/common.py`, `scripts/coverage_curated.yaml` + regenerated `docs/API-COVERAGE.md`, branch, integration commits, PR |

**`API-COVERAGE.md` rule:** the document is **generated** from `firewall_config_openapi.yaml` + `scripts/coverage_curated.yaml`; nobody hand-edits it and there are no per-domain fragments. If an implementation must deviate from the curated decision, the agent reports it to the Lead; the Lead updates `coverage_curated.yaml` and regenerates.

## Common pattern for every domain

1. Read the full issue, the domain section of `docs/API-COVERAGE.md`, and the exact operations in the YAML (parse it; never read it by eye).
2. Implement **only** the v1 scope operations from the issue; document the rest as deferred/excluded in the completion report.
3. Use the shared REST client through `AppContext` / `DomainAdapter`; **never** build URLs, headers or an HTTP client.
4. Typed Pydantic input/output DTOs; `extra="forbid"` on closed inputs; object-rooted, bounded outputs; never return raw Sophos payloads.
5. Register through `register_tool(..., kind=ToolKind.READ|MUTATION, ...)`: `title`, `read_only_hint`, and `destructive_hint`/`idempotent_hint` only for writes; `open_world_hint` decided per tool.
6. Map `SophosAPIError` to `tool_error()`; no raw bodies, no stack traces, no secrets.
7. Paginate only where the contract declares it; one page per call; no auto-pagination; preserve `pages` metadata.
8. RESPX contract tests (method, path, query, headers, body, content-type, status), model tests, discovery/annotation tests. Run only your own test files while the other domains are in flight.
9. No writes against the lab; `pytest -m live` is read-only and recorded in `docs/live-evidence/` or explicitly deferred.
10. Commit with explicit paths and `feat(<domain>): ...` / `test(<domain>): ...` messages; never `git add -A`; never switch branches.
11. Expose `register_<domain>_tools(server: MCPServer[AppContext], *, read_only: bool) -> None`; do not edit `server.py`.
12. Composite tools declare their `kind`; `firewall_rule_set_enabled_*`/`firewall_rule_clone_*` are **mutations**, the three audit tools are **reads**.

## Tasks per domain

### T27 — Firewall rules (`firewall`)

- IPv4/IPv6: list, get, create, update, delete, move, **enable/disable** (PATCH `enabled`) and **clone** (get + create).
- **`enabled` is required and the schema default is `true`**: the MCP input requires it explicitly with default `false`, always sends it, and returns the applied state.
- `position` is required on create (`after|before|bottom|top` + optional `referenceItem`); `move` identifies the rule by **name**, not `idOrName`.
- **WAF excluded in v1**: reject `ruleType: waf`; IPv6 has no discriminator.
- Bulk delete: documented, **not exposed**.
- `nameContains`/`nameNotEquals` filters and documented pagination.

### T28 — NAT rules (`nat`)

- IPv4/IPv6: list, get, create, update, delete, move.
- **There is no SNAT/DNAT discriminator**: model the real fields (`originalServicesOrGroups`, `inboundInterfaces`, `outboundInterfaces`, `originalSourceNetworks`, `originalDestinationNetworks`, `translatedSource`, `translatedDestination`, `overrideSnatForOutboundInterfaces`, …).
- Bulk delete documented, not exposed.
- PATCH with JSON Merge Patch semantics; preserve omitted fields.

### T29 — Objects and services (`objects`)

- IPv4/IPv6/FQDN addresses and their groups; services and service groups: full CRUD.
- **MAC addresses: full CRUD** (`/network/addresses/mac`).
- **Country groups: read-only** (list/get); mutations excluded.
- Do not mix families or reuse a generic model; exact membership and references.
- No cascade delete; in-use conflicts → clear error.

### T30 — Users and sessions (`users`)

- `getUsers` (paginated, filters), network-user CRUD, `getLiveUsers`, `disconnectLiveUser`.
- `updateNetworkUser` is **PATCH**: merge patch, `application/json`, preserve omitted fields.
- `disconnectLiveUser`: `liveUserId` and `message` required (`message` 1–600); destructive.
- Network-user login/logout: classified, **not registered**.
- Administrators and user groups: out of scope.
- Credentials: write-only, never in output or logs.

### T31 — Network architecture, VPN read-only and status (`network`)

- **Network architecture, read-only:** interfaces, zones, routing gateways (IPv4/IPv6, WAN and custom), static unicast routes, SD-WAN routes, DHCP servers, DHCP leases, DHCP relays, DNS settings, DNS host entries, DNS request routes, static neighbors.
- **Interfaces: read-only except VLANs.** `createNetworkInterface`, `updateNetworkInterface` and `deleteNetworkInterface` are exposed **only** for `type: vlan`. Each write must first read the interface with `getNetworkInterface` and refuse any type other than `vlan`; `deleteNetworkInterface` has no body, so the pre-read is the only enforcement. Physical, bridge, LAG and XFRM interfaces stay read-only.
- **VPN read-only in v1**: profiles, failover groups, policy/route-based IPv4 connections, live connections, remote-access settings, SSL VPN policies/bookmarks/global settings (the 20 operationIds in ADR §10).
- Status: `getDnsProtectionStatus`, `getCellularWanStatus`; do **not** create a generic "firewall health" tool.
- No IPv6 site-to-site (it does not exist in the contract).
- Do not infer start/stop/reconnect from the UI.

### T35 — Audit and explanation (`audit`)

- Three **composite, read-only** tools: `audit_firewall_rules`, `explain_connectivity`, `find_object_usage`. They add no Sophos operation; they call the audited list/get operations through the domain adapters and reason over the results.
- Bounded findings (max 100 per call, explicit `truncated`), evidence per finding (rule name/id, position, field), and `not-verifiable` instead of guessing when the configuration is insufficient.
- `explain_connectivity` reports `method: "config-analysis"`: it is not a packet test.
- Read-only annotations; no mutation.

## Review (T-review)

1. An independent `reviewer` (new, not a fork) runs [`04-REVIEW-PROTOCOL.md`](./04-REVIEW-PROTOCOL.md) against the phase PR.
2. For depth, the Lead may run an adversarial `workflow` review per domain, but the final verdict is signed by `reviewer`.
3. Findings by severity; criticals block integration.
4. The Lead fixes or reassigns; a critical is not ignored.

## Integration and close (Lead)

1. Wire the six `register_<domain>_tools` functions into `DEFAULT_DOMAINS` in `server.py` (the only foundation touch, declared).
2. Update `scripts/coverage_curated.yaml` if an implementation deviated; regenerate `docs/API-COVERAGE.md` and check for drift.
3. Run the full suite and linters.
4. Check that no agent touched the foundation or another domain's files (`git log --stat` per commit).
5. Open **one phase PR** `migration/phase-2-domain-tools` → `main`.
6. Do not merge without approval.
7. Report per master §9.

## Exit criteria

- [ ] Six domains implemented with the exact v1 scope (145 operations / 152 tools).
- [ ] Every tool maps to audited operationIds and has contract tests; composites have no invented endpoints.
- [ ] Annotations and schemas verified on the wire (`tools/list`).
- [ ] VLAN writes pre-read the interface type and reject non-VLAN; mutation composites are not registered in read-only mode.
- [ ] `API-COVERAGE.md` regenerable and without drift.
- [ ] `pytest`, `mypy`, `flake8`, `black` green.
- [ ] Independent review with no open criticals.
- [ ] PR open, not merged.
- [ ] No writes against the lab; read-only live evidence recorded or deferred.

## Phase-specific escalation

- If a domain needs a product decision (WAF, VPN mutations, interfaces), **ask**; do not decide on the agent's behalf.
- If the contract does not allow a safe DTO, document the limitation and expose only what is verifiable.
- If two domains need the same helper, the Lead decides where it lives (shared layer) before duplicating it.
