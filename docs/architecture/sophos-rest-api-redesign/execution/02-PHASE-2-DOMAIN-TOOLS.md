# 02 — Phase 2: Domain tools (#27–#31)

> **Before starting:** read and apply [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md). **Precondition:** phase 1 is merged (or at least `AppContext`, the registration signature, and the REST client are available on `main`).

## Phase objective

Implement the five domain tool families on top of the phase 1 foundation, with typed contracts, tests, and coverage, **without touching the foundation**.

**Issues:** [#27](https://github.com/lordraiden/sophos-firewall-mcp/issues/27) firewall rules (maximum surface), [#28](https://github.com/lordraiden/sophos-firewall-mcp/issues/28) NAT rules, [#29](https://github.com/lordraiden/sophos-firewall-mcp/issues/29) objects and services, [#30](https://github.com/lordraiden/sophos-firewall-mcp/issues/30) users and sessions, [#31](https://github.com/lordraiden/sophos-firewall-mcp/issues/31) network architecture + VPN read-only + status, [#35](https://github.com/lordraiden/sophos-firewall-mcp/issues/35) rule audit, connectivity explanation and object usage.

**Out of scope:** changes to `client.py`, `config.py`, `server.py`, `context.py`, `pyproject.toml`, CI, Docker, or release. If one is needed, ask the Lead and handle it as a separate task.

## Preflight (Lead)

1. Verify on `main` (or the base branch) that the following exist and are documented: `AppContext`, the `register_<domain>_tools(...)` signature, the REST client, and the error hierarchy. If not, **stop**: phase 1 is not ready.
2. Create branch `migration/phase-2-domain-tools`.
3. Create tasks T27–T31 + T32 (review) with disjoint `write_scopes` and no `blocked_by` (the foundation is already there).
4. Create `firewall`, `nat`, `objects`, `users`, `network`, `audit`, and `reviewer`.
5. Assign one task per agent and send the work prompt. All five can work in parallel because their files are disjoint.

## Write ownership (disjoint)

| Member | Issue | Writes (exclusive) | Does not touch |
|---|---|---|---|
| `firewall` | #27 | `src/sophos_firewall_mcp/tools/firewall_rules.py`, `tests/test_firewall_rules.py`, `docs/api-coverage/firewall.md` | foundation, other tools, `API-COVERAGE.md` |
| `nat` | #28 | `tools/nat_rules.py`, `tests/test_nat_rules.py`, `docs/api-coverage/nat.md` | idem |
| `objects` | #29 | `tools/hosts_objects.py`, `tools/services_objects.py`, `tests/test_hosts_objects.py`, `tests/test_services_objects.py`, `docs/api-coverage/objects.md` | idem |
| `users` | #30 | `tools/users_auth.py`, `tests/test_users_auth.py`, `docs/api-coverage/users.md` | idem |
| `network` | #31 | `tools/network.py`, `tools/vpn.py`, `tools/system.py`, `tests/test_network.py`, `tests/test_vpn.py`, `tests/test_system.py`, `docs/api-coverage/network.md` | idem |
| `audit` | #35 | `tools/audit.py`, `tests/test_audit.py`, `docs/api-coverage/audit.md` | idem |
| `reviewer` | — | nothing (report) | everything |
| Lead | integration | `docs/API-COVERAGE.md` (assembly), branch, integration commits | domain code |

**`API-COVERAGE.md` rule:** if it is a single file, **nobody edits it in parallel**. Each domain writes its fragment to `docs/api-coverage/<domain>.md`; the Lead (or the #24 generator) assembles them at the end. If the generator already supports fragments, use it.

## Common pattern for every domain

Each agent must:

1. Read its full issue, its domain coverage section, and the OpenAPI contract for the operations it will implement.
2. Implement **only** the v1 scope operations from the issue; document the rest as deferred/excluded.
3. Use the shared REST client via `AppContext`; **never** build URLs, headers, or its own HTTP client.
4. Define typed input/output DTOs (Pydantic), with `extra="forbid"` when the contract is closed; do not return raw Sophos payloads.
5. Annotate each tool: `title`, `read_only_hint`, and `destructive_hint`/`idempotent_hint` only for writes; `open_world_hint` decided per tool (not in bulk).
6. Map errors to `ToolError` with sanitized messages; no raw bodies or stack traces.
7. Paginate only where the contract declares it; one page per call; no auto-pagination.
8. Write RESPX contract tests (method, path, query, headers, body, content-type, status), model tests, and annotation/discovery tests.
9. Do not perform writes against the lab; `pytest -m live` is read-only and recorded in `docs/live-evidence/`.
10. Commit with explicit paths and `feat(<domain>): ...` / `test(<domain>): ...` messages.

## Tasks per domain

### T27 — Firewall rules (`firewall`)

- IPv4/IPv6: list, get, create, update, delete, move.
- **`enabled` is required and the schema default is `true`**: the MCP input must require it explicitly with default `false` (or force the caller to choose), always send it, and return the real state.
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

- IPv4/IPv6/FQDN addresses and their groups; services and service groups.
- MAC and country groups: classified and **deferred**.
- Do not mix families or reuse a generic model; exact membership and references.
- No cascade delete; in-use conflicts → clear error.

### T30 — Users and sessions (`users`)

- `getUsers` (paginated, filters), network-user CRUD, `getLiveUsers`, `disconnectLiveUser`.
- `updateNetworkUser` is **PATCH**: merge patch, `application/json`, preserve omitted fields.
- `disconnectLiveUser`: `liveUserId` and `message` required (`message` 1–600); destructive.
- Network-user login/logout: classified, **not registered**.
- Administrators and user groups: out of scope.
- Credentials: write-only, never in output or logs.

### T31 — Network architecture, VPN read-only, and status (`network`)

- **Network architecture (read-only):** interfaces, zones, routing gateways (IPv4/IPv6, WAN and custom), static unicast routes, SD-WAN routes, DHCP servers, DHCP leases, DHCP relays, DNS settings, DNS host entries, DNS request routes, static neighbors.
- **Interfaces: read-only except VLANs.** `createNetworkInterface`, `updateNetworkInterface`, `deleteNetworkInterface` are exposed **only** for `type: vlan`; physical, bridge, LAG and XFRM stay read-only. A VLAN write must never alter a physical interface.
- **VPN read-only:** profiles, failover groups, policy/route-based IPv4 connections, live connections, remote-access settings, SSL VPN policies/bookmarks/global settings. No VPN mutations.
- Status: `getDnsProtectionStatus`, `getCellularWanStatus`; do **not** create a generic "firewall health" tool.
- No IPv6 site-to-site (it does not exist in the contract).
- Logs are out: the contract has no log query endpoint. System info/service status are an accepted regression.
- Do not infer start/stop/reconnect from the UI.

### T35 — Rule audit and connectivity explanation (`audit`)

- `audit_firewall_rules`: any-any, disabled, shadowed/duplicate, no-logging, unused-object, NAT-without-rule, unrestricted-service. Evidence-based, bounded, read-only.
- `explain_connectivity`: source/destination/service → interfaces, zones, ordered rules, NAT, routing, verdict; explicitly configuration analysis, not a packet test; `not-verifiable` instead of guessing.
- `find_object_usage`: scan rules, NAT and groups for references; bounded, with explicit truncation.
- No mutations; no invented fields.

## Review (T32)

1. An independent `reviewer` (new, not a fork) reviews the five diffs against the issues and the plan.
2. For depth, the Lead may run an adversarial `workflow` review per domain (one agent per domain, `pipeline`), but the final verdict is signed by `reviewer`.
3. Findings by severity; criticals block integration.
4. The Lead fixes or reassigns; a critical is not ignored.

## Integration and close (Lead)

1. Assemble `docs/API-COVERAGE.md` from the fragments; regenerate and check for drift.
2. Run the full suite and linters.
3. Check that no agent touched foundation or another domain's files (`git log --stat` per commit).
4. Open **one phase PR** `migration/phase-2-domain-tools` → `main` (or several per-domain PRs if the owner asks; with a single worktree, the phase PR is the safe option).
5. Do not merge without approval.
6. Report per master §9.

## Exit criteria

- [ ] Six domains implemented with the exact v1 scope (firewall, NAT, objects, users, network, audit).
- [ ] Every tool maps to audited operationIds and has contract tests.
- [ ] Annotations and schemas verified on the wire (tools/list).
- [ ] `API-COVERAGE.md` assembled and regenerable.
- [ ] `pytest`, `mypy`, `flake8`, `black` green.
- [ ] Independent review with no open criticals.
- [ ] PR open, not merged.
- [ ] No writes against the lab; read-only live evidence recorded or deferred.

## Phase-specific escalation

- If a domain needs a product decision (WAF, VPN mutations, interfaces), **ask**; do not decide on the agent's behalf.
- If the contract does not allow a safe DTO, document the limitation and expose only what is verifiable.
- If two domains need the same helper, the Lead decides where it lives (shared layer) before duplicating it.
