# Independent review — Phase 4 (feedback-driven refinement)

| Field | Value |
|---|---|
| **Reviewer** | `reviewer4` (independent; did not write the code) |
| **Date** | 2026-11-15 |
| **Branch** | `migration/phase-4-refinement` |
| **Reviewed HEAD** | `1992d99` — *chore(release): prepare 0.5.0 with the phase-4 fixes* |
| **Base** | `origin/main` |
| **Diff** | 31 files, +3,280 / −306, 12 commits |
| **PR** | [#39](https://github.com/lordraiden/sophos-firewall-mcp/pull/39) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](./execution/04-REVIEW-PROTOCOL.md) |
| **Inputs** | full diff; PR description; `PHASE-4-PLAN.md`; `docs/live-evidence/phase-4-feedback.md` (including §10 Resolution); `docs/live-evidence/phase-4-write-validation.md`; issue #32 body and its 15 Nov pre-release comment; the 15 Nov scope comment on #24; `ADR-001`; `docs/API-COVERAGE.md`; `scripts/coverage_curated.yaml`; `firewall_config_openapi.yaml` parsed with Python; the test suite; `.github/workflows/`; `README.md`; `CHANGELOG.md`; `pyproject.toml`; `uv.lock` |

---

## Verdict

**CHANGES REQUIRED** — **2 Medium**, **8 Low**. No Critical and no High finding.

The code side of phase 4 is in good shape and I could not break it. The blocker fix (B1) is correct
and the 48-case regression matrix fails on the pre-fix `src` exactly as claimed; the same guard is
applied to NAT. H1–H4, D1, M3–M8, L2, L4 and L5 each match the recorded finding and each has a test.
The wire body is still the exact camelCase contract shape (`model_dump(by_alias=True)`), the published
top-level input parameters are uniformly snake_case, the surface is 152 tools (98 read-only, 54
mutations) and read-only mode removes exactly the mutations. `pytest`, `mypy`, `flake8`, `black`,
`generate_coverage.py --check` and `uv lock --check` are green when I run them. The live write
validation respected every owner constraint I could check from the record (only `mcp-test-*` objects,
rules created `enabled: false` and read back disabled, no existing object touched, baseline == final,
zero leftovers).

The two Medium findings are not in the runtime behaviour: they are the **M1 claim/test scope** (the
published input surface is still split one level down, and the surface test cannot see it) and the
**stale README** (it still says the naming is not unified and that no live write has ever run). Both
are cheap, concrete fixes. The Low findings are documentation accuracy, a private-SDK dependency, and
three bounded-analysis limitations.

---

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | **Medium** | `tests/test_tool_surface.py:160-193`; `src/sophos_firewall_mcp/models/firewall.py:267`; `src/sophos_firewall_mcp/models/network.py:390` | **M1 is verified only for the top-level `request` properties.** Nine tools still publish camelCase properties in their nested request-body schemas, and the three union-request tools are skipped entirely, so the published input surface is still split: the network/VPN nested models were renamed to snake_case, the firewall/objects/services nested models were not. The test docstring claims "every published input property must be snake_case" and "no exception list", which the test does not verify; the `scanned > 0` guard cannot catch a regression that skips most tools. | Enumerated `tools/list` with the real server: **0** camelCase top-level `request` properties, but **9** tools with camelCase nested properties — `firewall_rule_create_ipv4` (32), `firewall_rule_create_ipv6` (26), `firewall_rule_update_ipv4` (32), `firewall_rule_update_ipv6` (26), `address_create_ipv4` (5), `address_create_ipv6` (6), `mac_address_create` (2), `service_create` (7), `service_update` (7). `network_interface_create_vlan`, `network_interface_update_vlan` and the VPN tools publish **0**. `tests/test_tool_surface.py:184-186` skips a union `request`; `:192` asserts only `scanned > 0`. `CHANGELOG.md:11` and the PR body claim "all 152 now publish snake_case". | Either rename the remaining input-only nested models with serialization aliases and extend the surface test to nested properties and union variants, or state the scope explicitly in the CHANGELOG/PR and correct the test docstring; assert the exact scanned count (141) instead of `> 0`. |
| 2 | **Medium** | `README.md:311-322` | **The README's "Known limitations" section is stale for 0.5.0.** It says input naming "is not yet uniform … scheduled to be unified in 0.5.0" and "**No live write validation.** The shared lab credential is read-only, so no POST, PATCH or DELETE has been executed against a real appliance." Both are contradicted by this PR: the naming is unified (top level) and the write validation records live create/update/delete. | `README.md:311-315` (74/55/5/6/12 naming split, "scheduled to be unified in **0.5.0**"); `README.md:322-326` ("No live write validation"); `CHANGELOG.md:8-20` (0.5.0 naming breaking change); `docs/live-evidence/phase-4-write-validation.md:1-21` (live create/update/delete, baseline == final). | Update the known-limitations section for 0.5.0: naming unified (with the nested caveat from finding 1), live write validation recorded, and the 0.5.0 breaking change. |
| 3 | Low | `docs/live-evidence/phase-4-feedback.md:822` | The resolution table says M3 was "verified live", but no live record (date, tool, input, output) exists in the evidence docs; the write-validation §11 covers D1/D2/L2 only. The unit tests prove the percent-encoding, not the live acceptance. | `grep -rn "##ALL_RW" docs/live-evidence/` → only the pre-fix rejection in `phase-3-live-matrix.md:287` and the claim at `phase-4-feedback.md:822`; `phase-4-write-validation.md:395-466` has no M3 section. | Record the live read-only call in the feedback or write-validation doc, or downgrade the claim to "unit-tested; live verification pending". |
| 4 | Low | `src/sophos_firewall_mcp/tools/__init__.py:371-390` | `_close_argument_model` depends on the SDK's private `server._tool_manager` and mutates `tool.fn_metadata.arg_model` and `tool.parameters`. The docstring says it is pinned by tests, but a future SDK change breaks argument validation for every tool. | `src/sophos_firewall_mcp/tools/__init__.py:384` (`server._tool_manager.get_tool(name)`); the behaviour is pinned by `tests/test_server.py:786-850`. | Keep the pin test and record the private-API dependency as a known risk (or use a public seam if the SDK exposes one). |
| 5 | Low | `src/sophos_firewall_mcp/tools/services_objects.py:140-150` | The H2 client-side `type` filter only filters the returned page; `pages` still describes the unfiltered collection. A caller asking for `type=icmp` with `page_size=50` gets only the ICMP services on that page, not all ICMP services. The description says so, but the tool cannot answer "list all ICMP services" without paging through the whole collection. | `src/sophos_firewall_mcp/tools/services_objects.py:147-150`; the description at `:271-280`. | Document the page-level limitation more prominently, or filter across pages (bounded). |
| 6 | Low | `src/sophos_firewall_mcp/tools/audit.py:2326-2356` | The M7 fix reports only the first indeterminate rule: the `unresolved` branch appends one candidate and returns immediately, so later candidate rules the scan examined are not included. The feedback asked for "the candidate rules the scan examined". | `src/sophos_firewall_mcp/tools/audit.py:2326-2356`; the test `tests/test_audit.py:1320-1356` asserts a single candidate. | Continue scanning and collect all candidates (bounded), or state that only the first indeterminate rule is reported. |
| 7 | Low | `src/sophos_firewall_mcp/tools/audit.py:392-405` | The M5 built-in exclusion is a heuristic: a name starting with `#` or an epoch timestamp. The feedback's 36 built-in services (`AH`, `AOL`, …) are only excluded if they carry the epoch timestamp; the live evidence does not confirm that for services. | `src/sophos_firewall_mcp/tools/audit.py:400-405`; `docs/live-evidence/phase-4-feedback.md:478-496` (M5) and `:699-706` (L6). | Re-run the audit live and confirm the 36 services are excluded, or add a name-based built-in list. |
| 8 | Low | `src/sophos_firewall_mcp/tools/audit.py:1407` | `_routing_for` is called with the collected gateways/routes without checking `budget.truncated_collections`; a truncated gateway scan could produce a false `no-route` with the note "no WAN gateway is configured". | `src/sophos_firewall_mcp/tools/audit.py:1407`; `_Budget` limit 500 items per collection. | Report `not-verified` when the gateway or route collection is truncated. |
| 9 | Low | `CHANGELOG.md:11` | The 0.5.0 entry says "79 tools used the Sophos wire names, 61 used snake_case", while the README says "74 camelCase-only, 55 snake_case-only, 5 mixed, 6 single-word, 12 no-parameter". The 79/61 is a reclassification (74+5, 55+6) but the counting method is not stated. | `CHANGELOG.md:11`; `README.md:311-315`. | State the counting method or use the same numbers. |
| 10 | Low | `docs/live-evidence/phase-4-feedback.md:29`; `docs/live-evidence/phase-4-write-validation.md:376` | The live drivers are not committed, so the runs are not exactly reproducible; the docs record the method but not the exact commands/scripts. | `docs/live-evidence/phase-4-feedback.md:29` ("Ad-hoc STDIO driver scripts … not committed"); `docs/live-evidence/phase-4-write-validation.md:376` ("The driver is not committed"). | Commit a minimal driver or record the exact commands. |

---

## Verified

- **Gates, run by me on `1992d99`:** `UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync pytest -q` → **1058 passed, 100 skipped**; `mypy src/sophos_firewall_mcp` → clean (26 files); `flake8 src/sophos_firewall_mcp tests scripts` → clean; `black --check src tests scripts` → 50 files unchanged; `python scripts/generate_coverage.py --check` → up to date; `uv lock --check` → 55 packages.
- **B1 regression proof, reproduced independently:** I extracted `origin/main`'s `src` to a temporary tree, copied the PR's `tests/test_audit.py` over it and ran it: **13 failed, 111 passed**. Twelve of the failures are the new tests (the 48-case matrix's SSH/HTTPS/NoSuchService LAN→WAN cases, the accept-rule case, the NAT case, the candidate-rule case, the WAN-default-route case, the family-inference case, the both-families unused-object case, the built-in exclusion, the rule-name narrowing and the severity sort); the thirteenth is the existing transport-error test updated for the 401 wording. The PR's "12 failed / 45 passed, exactly the new tests" is accurate for the new tests.
- **B1 code:** `_evaluate_rules` (`src/sophos_firewall_mcp/tools/audit.py:2313-2323`) builds a criteria tuple and skips a rule when **any** criterion is `False`; `_evaluate_nat` (`:2426-2451`) applies the same guard. A rule is decisive only when every projected criterion matches.
- **M1 wire body:** constructed `CreateFirewallRuleIpv4Input` with snake_case fields and dumped `model_dump(by_alias=True, exclude_none=True)` → `ruleType`, `sourceZones`, `destinationZones`, `sourceNetworks`, `destinationNetworks`, `servicesOrGroups`, `logTraffic`, `referenceItem` — the exact camelCase contract shape. Query parameters are built with the wire names (`pageSize`, `pageTotal`, `nameContains`, `nameNotEquals`) in `client.get_page` and the adapters.
- **M1 published surface:** enumerated `tools/list` with the real server: 152 tools, **0** camelCase top-level `request` properties, all 152 input schemas carry `additionalProperties: false`, and every `request` model is closed. The 8 no-argument tools publish no `request` property.
- **Surface invariants:** 152 tools = 145 curated `tool_map` entries + 7 composites; 54 mutations; read-only mode leaves 98 tools and 0 mutations; every tool publishes an object-rooted output schema and `openWorldHint=true`.
- **H1:** `reference_families` is widened to both families when `unused-object` is requested with `ip_family` set (`src/sophos_firewall_mcp/tools/audit.py:1195-1205`), the NAT scan follows, and `rules_examined`/`nat_rules_examined` still count only the requested family. The test `test_unused_object_scans_both_families_when_ip_family_is_set` fails on the pre-fix code.
- **H2:** `service_list` filters the projected page client-side and the description says the appliance ignores `type` (`src/sophos_firewall_mcp/tools/services_objects.py:140-150`, `:271-280`); three tests cover the filter, the no-filter path and the empty page.
- **H3:** `tool_error` branches on `exc.status` (`src/sophos_firewall_mcp/tools/__init__.py:326-329`); 401 renders the authentication message, 403 the authorization message, and an unknown status a neutral message. Tests in `tests/test_server.py:735-780` and `tests/test_client.py:958-996`.
- **H4:** `_wan_gateway` selects the first `type: "wan"` gateway and `_routing_for` returns `default-route` with the gateway name, address and interface (`src/sophos_firewall_mcp/tools/audit.py:2217-2275`); the test asserts the decision, gateway, address and interface.
- **D1:** `group` is a `UserGroupRefInput` (`{"name": …}`) on both create and update (`src/sophos_firewall_mcp/models/users.py:268-280`, `:429-434`, `:471-475`); a bare string is rejected; the wire body is `{"group": {"name": …}}`; the live re-validation is recorded in `docs/live-evidence/phase-4-write-validation.md:395-416`.
- **M3:** `validate_object_name_or_id` accepts `##ALL_RW`, names with `/`, `?`, `#`, `\` and rejects only `..` and `%2e` (`src/sophos_firewall_mcp/models/common.py:113-145`); every adapter percent-encodes the path segment with `quote(value, safe="")`; tests cover the accepted and rejected values and the encoded URL.
- **M4:** `_Findings.finalize` sorts by severity, then canonical check order, then insertion order before applying `max_findings` (`src/sophos_firewall_mcp/tools/audit.py:264-283`); the test proves a medium `shadowed` finding survives while low `disabled` findings are dropped.
- **M5:** `_is_built_in` excludes `#`-prefixed and epoch-timestamped objects (`src/sophos_firewall_mcp/tools/audit.py:392-405`); the test covers `##ALL_RW`, `#Port2` and an epoch-stamped service.
- **M6:** `rule_name_contains` narrows `checks` to the rule-scoped set and records the skipped checks in `notes` (`src/sophos_firewall_mcp/tools/audit.py:1173-1188`); the test asserts `unused-object` and `nat-without-rule` are not run.
- **M7:** the indeterminate rule is appended as a structured `RuleEvaluation` with `matched_fields` and `unresolved_fields` (`src/sophos_firewall_mcp/tools/audit.py:2326-2356`); the test asserts the candidate's name, position, `decisive`, `applied`, `matched_fields` and `unresolved_fields`.
- **M8:** when both endpoints are zones and exactly one rule base is populated, the family is inferred and a note records it (`src/sophos_firewall_mcp/tools/audit.py:1433-1445`); the test asserts `ip_families == ["ipv4"]` and the note.
- **L2:** the `live_user_list` description is conditional on read-only mode (`src/sophos_firewall_mcp/tools/users_auth.py:425-435`); the test asserts the read-only description does not name `live_user_disconnect` and the writable one does.
- **L4:** argument-validation failures are rendered as one sanitized line (field path + rule, no internal model name, no pydantic URL, no rejected input) via `_close_argument_model`/`_sanitized_argument_model` (`src/sophos_firewall_mcp/tools/__init__.py:353-470`); tests assert the message and the absence of the raw dump.
- **L5:** the argument model is closed (`extra="forbid"`) and the published schema carries `additionalProperties: false`; a no-argument tool rejects an unknown argument with "this tool accepts no arguments".
- **Read-only guarantee:** `SOPHOS_READ_ONLY_MODE=true` removes exactly the 54 mutations (including the four firewall composites) and leaves 98 tools; the surface test proves it.
- **Sanitized-error guarantee:** the 401/403 split and the argument sanitization do not expose the API key, the raw remote body, the internal model name or a pydantic URL; the existing redaction tests still pass.
- **Live write validation, checked against the owner's constraints:** only `mcp-test-p4w24049e-*` / `mcp-test-p4wr62cc8e-*` / `mcp-test-p4wu2ea9` names were created; the firewall and NAT rules were created `enabled: false` and the **applied** state was read back `false` before and after the PATCH (`docs/live-evidence/phase-4-write-validation.md:148-177`); `firewall_rule_move_*`, `nat_rule_move_*`, `firewall_rule_clone_*` and `firewall_rule_set_enabled_*` were not called; every created object was deleted and a follow-up `GET` returned 404; the final sweep of 14 collections found 0 `mcp-test` matches; baseline == final on all seven collections (`:307-341`). The D1 re-validation used the fixed source and repeated the cleanup check (`:395-416`).
- **Read-only dogfooding:** the feedback doc records only `GET` requests, `SOPHOS_READ_ONLY_MODE=true`, 98 read-only tools and 0 mutations (`docs/live-evidence/phase-4-feedback.md:8-11`, `:27`); the 3 FAILs are content/UX defects, not HTTP failures, and the 24 SKIPs are deferrals, not passes.
- **Deferred items:** M2, M9, M10, M11, M12–M16, L1, L3, L6–L10 are recorded with a reason in `docs/live-evidence/phase-4-feedback.md:828-837`; workstream D (HTTP transport) is cancelled with the owner's reason in `PHASE-4-PLAN.md:19`.
- **Scope counts:** `ADR-001` §10, `docs/API-COVERAGE.md` §4 and `scripts/coverage_curated.yaml` agree on **145 operations / 152 tools / 11 domains**; the 7 composites carry `kind: read|mutation` (4 firewall mutations, 3 audit reads).
- **Git hygiene:** 12 commits, each with explicit paths; no `add -A`; no changes outside the phase-4 scope (docs, `src/`, `tests/`, `pyproject.toml`, `uv.lock`, `CHANGELOG.md`); `pyproject.toml` and `uv.lock` are 0.5.0; the CHANGELOG records the 0.5.0 breaking change.

---

## Not verified

- **The live runs themselves.** I did not re-run the dogfooding or the write validation against the appliance: I have no appliance access in this session and the drivers are not committed. I verified the records' internal consistency, the safety constraints they describe, and the code paths they exercise, not the network traffic. In particular I cannot prove from the repository that the read-only run sent no `POST`/`PATCH`/`DELETE`; the evidence is the doc's statement plus the read-only registration mechanism.
- **The 36 built-in services' timestamps.** The M5 fix excludes them only if they carry the epoch timestamp; the live evidence does not record their `createdAt`/`updatedAt`. Finding 7.
- **The M3 live acceptance.** The resolution table claims it; no live record exists. Finding 3.
- **Firmware build, appliance model and API allowlist source.** Still unknown (workstreams F/G are owner tasks); no firmware compatibility is claimed.
- **A real `403` denial.** The write key is write-capable, so the permission-denied path was not exercised live; the 403 message is unit-tested only.
- **The `dhcp_relay_get_ipv4` happy path.** No relay object exists on the appliance; M9 is deferred.
- **The `_close_argument_model` behaviour on a future SDK.** The private `_tool_manager` seam is pinned by the current tests only. Finding 4.

---

## Residual risks

- **The M1 breaking change is only half-visible.** The top-level parameters are snake_case, but the nested request-body properties are still camelCase for the firewall/objects/services create and update tools. An agent that reads the schema will use `source_zones` at the top level and `ipv4Addresses` one level down; the inconsistency is exactly the class of problem M1 was meant to remove, and the surface test cannot catch a regression there (finding 1).
- **The README is the first thing a user reads and it is wrong about 0.5.0** (finding 2). A user who reads "no live write validation" will not trust the write tools; a user who reads "scheduled to be unified in 0.5.0" will not know the 0.5.0 surface changed.
- **The argument-model swap is a private-SDK dependency.** It works on the pinned SDK and is tested, but a dependency bump can break every tool's argument validation at once (finding 4).
- **The audit fixes are unit-tested, not live-revalidated.** B1, H1, H4 and M4–M8 were proven against RESPX fixtures and the pre-fix code, not against the appliance. The live re-validation covered D1 and L2 only. The M5 epoch heuristic and the M7 single-candidate behaviour are the most likely to differ on a real appliance (findings 6, 7).
- **The `service_list` `type` filter is page-local.** It is honest in the description, but a caller can still conclude "there are N ICMP services" from one page (finding 5).
- **The routing decision ignores a truncated gateway/route scan.** The budget is 500 items per collection, so this is unlikely on a real appliance, but a false `no-route` is the kind of confident wrong answer the audit tools exist to avoid (finding 8).
- **The live evidence is not exactly reproducible** because the drivers are not committed (finding 10).
- **The 0.5.0 release pack is incomplete.** The CHANGELOG and `pyproject.toml` are 0.5.0, but there is no `docs/release/RELEASE-0.5.0.md` and the README is not updated. The PR says the release is "prepared, not published"; the publication checklist will need the release notes and the README fix before the tag.

---

## Re-check after fixes

**Re-checked HEAD:** `5bec690` (4 commits after the reviewed `d0e6c67`). **Date:** 2026-11-15.
**Scope:** focused re-check of the 10 findings, not a second full review. The original verdict
section above is unchanged.

### Status of the findings

| # | Severity | Status | Evidence |
|---|---|---|---|
| 1 | Medium | **Closed** | `models/firewall.py` and `models/objects.py` now publish snake_case at every depth; the surface test walks the whole schema recursively (`$ref`, `items`, `allOf`/`oneOf`/`anyOf`, cycle-safe), covers the union-request tools, and pins 144 tools / 1,495 occurrences / 167 distinct names / 0 non-snake_case (`tests/test_tool_surface.py:160-250`). I independently enumerated `tools/list`: 0 camelCase properties at any depth, 144 tools with a request, 167 distinct names. The wire body is identical to `d0e6c67` for a firewall rule, a service, all 8 address-create and 2 MAC-create bodies (constructed the same models in both trees and compared `model_dump(by_alias=True)`). The only output schema that changed is `explain_connectivity` (`routing.truncated`, the L8 fix); the firewall/objects/services output schemas are unchanged. |
| 2 | Medium | **Closed** | `README.md:311-326` now says the naming is uniform as of 0.5.0 (breaking from 0.4.0, wire aliases unchanged, `additionalProperties: false`) and describes the live write validation and what remains unverified. |
| 3 | Low | **Closed** | `docs/live-evidence/phase-4-feedback.md:822` now records the M3 live evidence: `address_get_ipv4` accepted `##ALL_RW`, `##ALL_IPSEC_RW` and `FQDN Group - Pipeline/parsing errors`, `find_object_usage` resolved both, and 0.4.0 rejected all five. |
| 4 | Low | **Closed** | The private seam is confined to `_registered_tool` (`src/sophos_firewall_mcp/tools/__init__.py:393-410`), pinned to mcp 2.3.0, raises if `_tool_manager` is missing, and three tests cover the mutation, the single accessor (AST) and the failure mode (`tests/test_server.py:863-904`). |
| 5 | Low | **Closed** | The `service_list` description states the filter is client-side over the returned page (`src/sophos_firewall_mcp/tools/services_objects.py:272-280`); the page-level limitation is documented. |
| 6 | Low | **Closed** | `_evaluate_rules` now collects every indeterminate rule (`_IndeterminateRule`), continues the scan, and reports a later fully-resolved rule as non-decisive when an earlier rule may preempt it (`src/sophos_firewall_mcp/tools/audit.py:2358-2500`); the evidence line is bounded to `MAX_TEXT`; tests cover the multi-candidate case and the bound. |
| 7 | Low | **Closed** | The `_is_built_in` docstring records the live confirmation (93 services, all epoch) and the false-negative limit (user-created services also carry the epoch); the `unused-object` note states the heuristic and the excluded count; a test pins the note. |
| 8 | Low | **Closed** | `_routing_for` takes `truncated`/`item_limit`, marks the decision `truncated`, and downgrades `no-route` to `not-verified`; `missing_evidence` records the truncation; three tests cover the no-route, static-route and default-route cases. |
| 9 | Low | **Closed** | `CHANGELOG.md:11` now uses the measured counts (74 camelCase-only, 55 snake_case-only, 5 mixed, 6 single-word-only, 12 parameterless). |
| 10 | Low | **Closed** | `scripts/mcp_smoke_test.py` is committed and reproducible; the feedback doc documents it (`docs/live-evidence/phase-4-feedback.md:846-858`). |

### Gates (re-run on `5bec690`)

| Gate | Command | Result |
|---|---|---|
| Tests | `UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync pytest -q` | **1070 passed, 100 skipped** |
| Types | `uv run --no-sync mypy src/sophos_firewall_mcp` | clean (26 files) |
| Lint | `uv run --no-sync flake8 src/sophos_firewall_mcp tests scripts` | clean |
| Format | `uv run --no-sync black --check src tests scripts` | 51 files unchanged |
| Coverage drift | `uv run --no-sync python scripts/generate_coverage.py --check` | up to date |
| Lock | `uv lock --check` | 55 packages |

### New findings

- **Low (new):** `tests/test_tool_surface.py:222` says the walk reaches "a maximum depth of five",
  but the test does not assert the depth. The 1,495-occurrence pin would catch a flattening, so the
  risk is low; the docstring should either assert the depth or drop the claim.

### Verdict after re-check

**APPROVE.** All 10 findings are closed. The only new item is a Low documentation/test-quality gap
(the max-depth claim is not asserted), which does not block integration. The gates are green, the
wire body is unchanged, the output schemas are unchanged except for the intentional
`explain_connectivity` addition, and the live evidence is now recorded and reproducible.
