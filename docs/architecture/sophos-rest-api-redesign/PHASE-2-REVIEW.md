# Independent review — Phase 2 (domain tools)

| Field | Value |
|---|---|
| **Reviewer** | `reviewer2` (independent; did not write the code) |
| **Date** | 2026-11-15 |
| **Branch** | `migration/phase-2-domain-tools` |
| **Reviewed HEAD** | `26df771` — *feat(audit): register the audit domain and expose the shared network paths* |
| **Base** | `origin/main` |
| **Diff** | 34 files, +23,098 / −67, 13 commits |
| **PR** | [#37](https://github.com/lordraiden/sophos-firewall-mcp/pull/37) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](./execution/04-REVIEW-PROTOCOL.md) |
| **Inputs** | full diff; issues #27–#32, #35 and the 15 Nov scope revision; PLAN.md; ADR-001 (all of it); `INDEPENDENT_REVIEW_REPORT.md`; `REFERENCES.md`; `API-COVERAGE.md`; `coverage_curated.yaml`; `generate_coverage.py`; the YAML parsed with Python; the test suite; `.github/workflows/`; `Dockerfile`; `docker-compose.yml`; `README.md`; `.env.example`; phase-1 review and protocol review (context only) |

---

## Verdict

**APPROVE** — with **3 Medium** and **7 Low** findings. **No Critical and no High finding.**

The phase-2 exit criteria are met on the code side: the 152-tool surface is exactly the curated
`tool_map` (145 audited operationIds, all present and unique in the parsed YAML) plus 7 declared
composites whose underlying operationIds are all audited and in `tool_map`; every excluded family
(bulk delete, WAF, administrator CRUD, user groups, login/logout, VPN mutations, non-VLAN interface
mutations, country mutations, logs) is absent from the registry; VLAN writes pre-read the interface
type and refuse a non-VLAN target before any write request; mutation composites are not registered in
`SOPHOS_READ_ONLY_MODE` (98 tools, 0 mutations); and `pytest`, `mypy`, `flake8`, `black` and
`generate_coverage.py --check` are green when run independently.

The Medium findings are a public-surface consistency defect (finding 1), an incomplete live-evidence
record (finding 2) and an inconsistent error mapping for malformed appliance payloads (finding 3).
None of them is a safety or correctness defect in a mutation path, so none blocks integration. Finding
1 should be fixed **before the surface is published or released**, because MCP input parameter names
are the public contract and renaming them afterwards is a breaking change.

---

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | **Medium** | `src/sophos_firewall_mcp/models/objects.py:193-197`; `models/nat.py:488-496`; `models/users.py:234`; `models/audit.py:263` vs `models/firewall.py:582`; `models/network.py:226`; `models/vpn.py:215` | The published MCP input parameters use **two naming conventions**. At least 51 tools publish snake_case names (`page_size`, `page_total`, `name_contains`, `name_not_equals`, `id_or_name`), while the firewall, network and VPN families (66 tools) publish camelCase names (`pageSize`, `pageTotal`, `nameContains`, `nameNotEquals`, `idOrName`, `parentInterface`, `vlanId`). The split is per-domain and undocumented. | `list_tools()` schema dump: `firewall_rule_list_ipv4.request.pageSize` vs `nat_rule_list_ipv4.request.page_size`; `network_interface_get.request.idOrName` vs `address_get_ipv4.request.id_or_name`; `user_list.request.name_contains` vs `zone_list.request.nameContains`. The models differ only in whether they set `alias=` (published in the JSON schema) or `serialization_alias=` (wire only): `objects.ListQuery` uses bare field names, `network.PageInput` uses `alias="pageSize"`. No document records the split as a decision. | Pick one convention for the whole surface (camelCase, matching the contract, is the natural choice) or record the split as an explicit per-domain decision. Do it before release: MCP input names are the public contract. |
| 2 | **Medium** | `docs/live-evidence/README.md:10`; `docs/architecture/sophos-rest-api-redesign/execution/02-PHASE-2-DOMAIN-TOOLS.md:132` | The exit criterion *"read-only live evidence recorded or deferred"* is only partly met. No per-domain record file was created for the six phase-2 domains, and the only live evidence is the pre-phase-2 endpoint smoke. No explicit deferral covers the read-only evidence for NAT, VPN, gateways, routes, DHCP, DNS host entries, MAC, country or the IPv6 families. | `ls docs/live-evidence/` → `README.md`, `api-smoke-2026-11-15.md` only, while the README says *"one record file per domain, created by the domain issues (#27–#32)"*. `api-smoke-2026-11-15.md:34-41` covers `/firewall/rules/ipv4`, `/authentication/users*`, `/authentication/live-users`, `/network/interfaces/network-interfaces`, `/network/services`, `/network/service-groups`, `/network/addresses/ipv4`, `/network/address-groups/ipv4` and the two status endpoints — not the rest. The PR text defers **write** validation only. | Add a read-only per-domain record for the surfaces the 15 Nov smoke did not touch, or an explicit deferral with reason, owner and prerequisite. |
| 3 | **Medium** | `tools/hosts_objects.py:174`; `tools/network.py:320`; `tools/vpn.py:180`; `tools/services_objects.py:122`; `models/nat.py:1142`; `models/users.py:855` vs `tools/firewall_rules.py:137-148`; `tools/audit.py:719-730` | A contract-mismatched appliance payload is mapped to a sanitized `ToolError` **only** in the firewall and audit domains. In the other five domains pydantic's `ValidationError` escapes, so the SDK reports the opaque `Error executing tool <name>` with no field hint. | `grep "except ValidationError" src/` → only `firewall_rules.py:141,189` and `audit.py:723`. The other adapters call `model_validate` directly (23 sites in `hosts_objects.py`, 43 in `network.py`, 20 in `vpn.py`, 7 in `services_objects.py`, plus `project_nat_rule`/`project_network_user`). `test_firewall_rules.py:300` proves the good path; there is no equivalent test in the other domains. | Route every projection through one shared helper that converts `ValidationError` into a `ToolError` naming the field path (the `_project_rule` pattern), or record the deliberate difference in the foundation docs. |
| 4 | **Low** | `src/sophos_firewall_mcp/models/network.py:954-975` | `DhcpServerIpv4` omits the documented `bootNextServer` member, so `dhcp_server_get_ipv4` and `dhcp_server_list_ipv4` silently drop it (`extra="ignore"`). | Parsed YAML: both `getDhcpServerIpv4` and the `listDhcpServersIpv4` item schema declare `bootNextServer` (`oneOf` `{ipv4Address}` / `{fqdn}`). The model has `bootFile` (line 974) but no `bootNextServer`, and the tool output schema has no such property. | Add a `bootNextServer` union field and a projection test. |
| 5 | **Low** | `src/sophos_firewall_mcp/models/nat.py:558-565` | NAT create accepts `position: after\|before` without requiring `referenceItem`, so a doomed request reaches the appliance; the firewall create/move models reject the same combination. | `models/firewall.py:217-222,460-462` implement `_require_anchor` for create, move and clone. `_NatRuleCreateBase` (line 558) and `NatRuleMoveInput` have no equivalent validator, although the contract's `moveNatRuleIpv4` body declares the same `position` enum plus `referenceItem`. | Add the same anchor validator to the NAT create and move models. |
| 6 | **Low** | `src/sophos_firewall_mcp/models/network.py:239-261`; `models/vpn.py:224-250` | The network and VPN page inputs do not reject `nameContains` + `nameNotEquals` together, while firewall, objects and users do; the contract documents the two filters as mutually exclusive. | `objects.py:199-203`, `users.py:226-231` and the firewall list model reject both; `network.FilteredPageInput` and `vpn.VpnFilteredPageInput` only build the filter dict. The network/VPN tool descriptions therefore do not claim exclusivity, so the surface is internally consistent but inconsistent with the documented contract semantic. | Add the same `model_validator` to both base classes. |
| 7 | **Low** | `src/sophos_firewall_mcp/tools/network.py:377`; `tools/users_auth.py:369` | `idempotent_hint=False` on `network_interface_delete_vlan` and `network_user_delete` contradicts every other single-object delete and the MCP meaning of idempotence; only the network-user description justifies it (name reuse). | Annotation dump: `address_delete_*`, `service_delete`, `mac_address_delete`, `nat_rule_delete_*`, `firewall_rule_delete_*` → `idempotent_hint: true`; the two above → `false`. | Use one rule for deletes and document it, or add the name-reuse rationale to the VLAN delete description. |
| 8 | **Low** | `tests/test_network.py:694`; `tests/test_server.py:222` | No test asserts the **global** surface invariant (152 tools, 98 in read-only mode, 0 mutations). Only per-domain subsets are asserted, and the network test uses `<=` rather than `==`, so a duplicate or stray tool would pass CI. | `grep list_tools tests/` shows per-domain assertions only; `test_network.py:694` is `EXPECTED_NETWORK_TOOLS <= set(tools)`; `test_firewall_rules.py:876-891` counts 16 / 4 per domain. The exact 152/98 counts in the PR text are not reproducible from a test. | Add one test that builds the server and asserts the exact name set equals `tool_map ∪ composite_tools` (and the 98-name read-only set). |
| 9 | **Low** | commit `26df771`, `src/sophos_firewall_mcp/tools/network.py` | The audit integration commit renames the network adapter's private path constants to public ones — a cross-domain edit to another domain's file, which the phase doc's "no cross-domain edits" rule forbids for agents. | `git show 26df771 -- src/sophos_firewall_mcp/tools/network.py` renames `_INTERFACES`→`INTERFACES_PATH`, `_ZONES`→`ZONES_PATH`, etc. The same commit wires `server.py` and the curated YAML, so it is the Lead's integration commit; the change is mechanical and covered by the suite. | None required; record the exception in the integration notes, or move shared path constants into a shared module. |
| 10 | **Low** | `src/sophos_firewall_mcp/models/network.py:784-797` | `UnicastRouteIpv4/Ipv6` expose `name` and `interface`, which the contract's 200 response does not declare; list outputs also render `pages` where the contract declares none (`getAllDhcpRelayIpv4/Ipv6`, `listDhcpServersIpv4/Ipv6`). | Parsed YAML: `getUnicastRouteIPv4` 200 properties are `administrativeDistance, cidr, createdAt, description, destinationAddressIpv4, gatewayIpv4, id, metric, updatedAt`; the model adds `name`/`interface` (always `null` in the output). `getAllDhcpRelayIpv4` 200 is `{items}` only, while `ListPage` renders `pages: null`. | Drop the undeclared members, or document them as live-observation fields. |

---

## Verified

All commands were run in the reviewed worktree at HEAD `26df771`; the author's report was not trusted.
`UV_CACHE_DIR=/tmp/dsh-uv-cache` was required because `~/.cache/uv` is read-only.

### 1. Quality gates (run independently)

| Gate | Command | Result |
|---|---|---|
| Tests | `uv run --no-sync pytest -q` | **915 passed**, 1 warning (`PytestRemovedIn10Warning` from anyio), 119.84 s |
| Types | `uv run --no-sync mypy src/sophos_firewall_mcp` | `Success: no issues found in 26 source files` |
| Lint | `uv run --no-sync flake8 src/sophos_firewall_mcp tests scripts` | clean (no output) |
| Format | `uv run --no-sync black --check src tests scripts` | `44 files would be left unchanged` |
| Coverage drift | `uv run --no-sync python scripts/generate_coverage.py --check` | `docs/API-COVERAGE.md is up to date` |

### 2. Surface and scope (built the server and inspected `list_tools()`)

- `create_server(Settings(...))` → **152 tools, 152 unique names**; `read_only_mode=True` → **98 tools,
  0 mutations** (54 mutations in full mode, matching the PR text).
- The registered set is **exactly** `tool_map` (145) ∪ `composite_tools` (7): zero registered-but-not-curated
  and zero curated-but-not-registered.
- All 145 `tool_map` operationIds are present in the parsed YAML (700 operations), all tool names unique,
  no duplicate mapping.
- All 7 composite `operation_ids` are in `tool_map`; the audit implementation reads exactly the declared
  operations (`_interfaces`, `_zones`, `_rules`, `_nat_rules`, `_gateways`, `_routes`, `_addresses`,
  `_address_groups`, `_services`, `_service_groups`) and adds no HTTP call of its own.
- **No `tool_map` entry is matched by any curated exclusion rule** (evaluated programmatically against
  the parsed paths/methods). VPN: 20 operations, all `GET`. Interfaces: only the 5 interface operations,
  of which 3 are the VLAN writes. Country: only the 2 `GET`s. `bulkDelete*`, WAF, administrators, user
  groups, `networkUserLiveLogin/Logout` and `importTrustedMacs` are absent from the registry.
- Every one of the 145 mapped path prefixes appears in `src/` (no typo'd path). For every read tool, the
  published query parameters are exactly the operation's declared query parameters: **0 undeclared, 0
  missing** (`page`/`pageSize`/`pageTotal`/`nameContains`/`nameNotEquals`/`type`/`filter`/`sort`).
  `getDhcpLeasesIpv4/Ipv6` (no declared parameters) and `getLiveUsers` (no declared parameters) expose
  none.
- `list_prompts()`, `list_resources()`, `list_resource_templates()` are all empty: no router, no
  prompts, no resources.

### 3. Annotations and schemas on the wire

- All 152 tools have annotations; all 152 output schemas are object-rooted; all 152 have a non-empty
  input schema.
- Read tools carry **no** `destructiveHint`/`idempotentHint`; every mutation declares both explicitly;
  `readOnlyHint` is correct per kind; `openWorldHint` is `true` on all 152 (the foundation default).
- `Context[AppContext]` never appears in an input schema: every tool publishes a single closed
  `request` object (`additionalProperties: false`), e.g. `network_interface_create_vlan` exposes only
  `name`, `vlanId`, `parentInterface`, `zone`, `ipv4`, `ipv6`.
- Firewall create models cover exactly the contract's `FirewallRuleIpv4/Ipv6CreateFirewall` property
  set (checked against the parsed `allOf`); `enabled` defaults to `false` and is always sent;
  `position` is required; `ruleType` is `Literal["firewall"]`, so WAF cannot be requested. The
  firewall tests also assert model-vs-YAML equality for create, update, list and move
  (`tests/test_firewall_rules.py:1205-1251`).
- `moveFirewallRuleIpv4/Ipv6` is modelled by **name** only and posts to `/firewall/rules/{family}/move`
  with `position` + optional `referenceItem`, matching the parsed body.
- `disconnectLiveUser` requires `liveUserId` (integer ≥ 1) and `message` (1–600) and serializes
  `liveUserId` through `serialization_alias`; the body sent is `{"liveUserId": …, "message": …}`.
- Passwords are `SecretStr`, extracted only at the transport boundary, absent from every output model,
  and covered by redaction tests (`tests/test_users_auth.py:955,977`).

### 4. VLAN-only enforcement (read the code and the tests)

- `update_vlan` and `delete_vlan` `await self.object(INTERFACES_PATH, id_or_name)` and call
  `_refuse_non_vlan` **before** the PATCH/DELETE; the refusal is a `ToolError`.
- `create_vlan` pre-reads the **parent**, refuses a type outside `{physical, vlan, bridge, lag}`, and
  always sends `"type": "vlan"`. `cellularWan` and `xfrm` parents are refused.
- Tests prove **zero** write requests on refusal: `patch.call_count == 0`
  (`tests/test_network.py:453-468`), `delete.call_count == 0` (`:508-521`), `post.call_count == 0`
  (`:575-608`). The create body is asserted field-by-field (`:540-573`).
- The update/create models cannot express `type`, `bridgeDetails`, `lagDetails` or `vlanDetails` on
  PATCH, so no tool can turn a VLAN into a bridge/LAG or reparent it. The PATCH property set of
  `updateNetworkInterface` (`bridgeDetails, description, ipv4, ipv6, lagDetails, macAddress, mss, mtu,
  name, overrideMac, zone`) contains no `type`, matching the model.

### 5. Security

- TLS verification comes from `Settings.verify_ssl` (default `true`); `ca_bundle` is supported;
  `verify=false` is documented in `.env.example` as lab-only.
- `httpx.AsyncClient(..., follow_redirects=False, trust_env=False)`; 3xx is not a success status, so a
  redirect becomes a `SophosAPIError` and the Bearer is never forwarded. No proxy env vars are used.
- The API key lives in `SecretStr`, is read once into the `Authorization` header, and never appears in
  logs, error messages or tool output (`tool_error` builds messages from the exception type, status,
  method, path and a sanitized error code only; `_sanitize` bounds to 300 chars and drops `<>`).
- No model-controlled URL, path, header or content type: paths are module constants; the only
  model-controlled path element is a validated `ObjectNameOrId` (rejects `/`, `\`, `..`, `?`, `#`,
  `%2e`, control characters) that is then percent-encoded and re-validated by
  `SophosRestClient._validate_path`. Query values go through httpx `params`.
- `SOPHOS_READ_ONLY_MODE=true` registers zero mutations (98 tools, all `readOnlyHint: true`), including
  the four mutation composites.

### 6. MCP semantics

- One client per process: created in the lifespan, yielded through `AppContext`, closed in `finally`
  (`server.py:121-141`); `tests/test_server.py:352` asserts exactly one instance.
- `subscriptions=False`; `tests/test_server.py:254` asserts `subscriptions/listen` is unregistered.
- STDIO: `main()` configures logging to `stderr`, stdout is protocol only; the official-client STDIO
  test now asserts the phase-2 tools arrive over the wire (`tests/test_server.py:756-761`).
- Cancellation propagates (`tests/test_server.py:635-644`); no `BaseException`, no bare `except`, no
  `except Exception` and no `print()` anywhere in `src/`.
- `MCPError` is used only in a synthetic test tool, never in `src/`; anticipated transport failures map
  to `ToolError` through `tool_error()`.

### 7. Tests

- 915 tests; every one of the 152 tool names appears in the suite.
- Contract tests assert method, path, query, `Authorization`, `Accept`, absence of `Content-Type` on
  reads, and the exact body on writes (e.g. `tests/test_network.py:396-432`).
- Model tests, discovery/annotation tests, read-only-mode tests and VLAN pre-read tests exist per
  domain; the coverage matrix is tested for full parse, one row per operation, deterministic
  regeneration, the SHA gate, the composite `kind` classification and the 145/152/11 counts
  (`tests/test_coverage.py:159-345,498-560`).
- Error cases 401/403/404/409 are exercised per domain and 400/timeout/malformed-JSON/network at the
  client level (`tests/test_client.py:275-360,447-515`).
- No test performs network I/O: 10 of 16 test modules use `respx`; the rest are pure model/config/
  coverage/server tests. No `pytest.mark.live` test is registered, so CI passes with everything mocked.

### 8. Quality and git

- 13 commits, each scoped to one domain or one shared-model step; no `git add -A`; explicit paths in
  every commit.
- The only foundation file touched is `server.py` (imports + `DEFAULT_DOMAINS` + comment) — the declared
  exception. `client.py`, `config.py`, `context.py`, `tools/__init__.py`, `pyproject.toml`, CI, Docker
  and release files are untouched.
- `docs/API-COVERAGE.md` is generated: the diff is exactly the curated `composite_tools` operation lists
  and the curated caveat text, and `--check` reports no drift.
- ADR-001 §10, `API-COVERAGE.md` §4 and `coverage_curated.yaml` agree on **145 operations / 152 tools /
  11 domains**, and the per-domain rows sum to both totals (12+12+37+10+6+2+11+9+2+44+0 = 145;
  16+12+37+10+6+2+11+9+2+44+3 = 152).
- PLAN.md §4 carries the explicit 15 Nov supersession note and points to ADR-001 §10 and
  API-COVERAGE §4, so the stale "initial decision" table is not a live contradiction.
- The README's XML-era sections are covered by a migration banner that names #32; the `router` extra and
  the Dockerfile FastEmbed step carry the same deferral comment. Neither is a phase-2 defect.

---

## Not verified

- **Live appliance behaviour.** No phase-2 tool was executed against the appliance; every response
  shape, status code and PATCH semantic is contract-derived and mock-verified. Firmware/build remains
  unknown (the contract exposes no version endpoint).
- **CI on the declared matrix.** I ran the suite on Python 3.14 (the local interpreter); CI runs
  3.11–3.13. I did not run the workflows themselves, so the GitHub-side result is unverified.
- **Every test body.** I verified that every tool name appears in the suite, sampled the contract-test
  structure in each domain and read the firewall, network and audit suites in detail; I did not read all
  915 test functions line by line.
- **Audit semantics against a real rule base.** I read `_covers`/`_zones_cover`/`_networks_cover`/
  `_services_cover`/`_schedule_covers` and confirmed the comparison is conservative (a name-set
  superset that can miss a shadow but cannot invent one), but I could not validate the findings against
  a real 47-rule configuration.
- **The PR's "every tool has RESPX contract tests" claim** is consistent with what I sampled and with
  the case tables (110 tools in parametrised tables, the remaining 42 covered by individual tests), but
  I did not audit each assertion.
- **`INDEPENDENT_REVIEW_REPORT.md` and `REFERENCES.md`** were read for context; I did not re-verify their
  external source claims.

---

## Residual risks

- **Firmware compatibility is unproven.** The whole surface is contract-derived. PATCH-over-array
  semantics, 409 conflict behaviour, the create defaults and the VLAN parent-type rule are not
  lab-proven. This is the largest residual risk and it is correctly stated in the PR.
- **No live write evidence, by owner decision.** VLAN writes, enable/disable, clone, disconnect and every
  CRUD mutation have never run against an appliance. A read-only smoke of the new GET tools would
  reduce the risk cheaply and is still possible with the current lab key.
- **VLAN pre-read is a time-of-check/time-of-use window.** Between `getNetworkInterface` and the
  PATCH/DELETE the interface type could change on the appliance. The window is small and requires a
  concurrent administrator, but the enforcement is client-side only; the appliance profile remains the
  real authorization boundary.
- **Audit output is advisory.** `audit_firewall_rules` shadowing findings are candidates (the projection
  omits `userAuthentication` and `exclusions`), `explain_connectivity` is configuration analysis and
  cannot resolve object membership or FQDNs, and routing is static-configuration only. The tool
  descriptions say so, but a consumer could still read a `denied` verdict as a packet-test result.
- **`LAB-ACCESS.md` still contains the lab API key in clear** (owner decision recorded in the PR). It
  must be rotated before the repository is made public.
- **Phase-3 deferrals** (`README`/Compose rewrite, `router` extra, Dockerfile FastEmbed step, CI matrix
  3.14, `asyncio_default_fixture_loop_scope`) are tracked by #32 and are not regressions of this PR.
- **Finding 1 becomes a breaking change after release.** If the naming split is not resolved now, every
  consumer that learned `page_size` or `idOrName` will have to change when it is unified.
