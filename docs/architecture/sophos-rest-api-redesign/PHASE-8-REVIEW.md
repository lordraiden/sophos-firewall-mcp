# Independent review — Phase 8 (0.7.0 breaking release, issue #47, PR #50)

| Field | Value |
|---|---|
| **Reviewer** | `reviewer8` (independent; did not write the code) |
| **Branch / HEAD** | `feat/mcp-0.7-breaking` @ `12124e7` (base `origin/main` @ `cce6bd0`) |
| **PR** | [#50](https://github.com/lordraiden/sophos-firewall-mcp/pull/50) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](execution/04-REVIEW-PROTOCOL.md) |
| **Date** | 2026-11-16 |

## Verdict

**CHANGES REQUIRED**

The runtime surface is sound: the IPv4/IPv6 collapse is faithful (the wire body is byte-identical
per family), the flat-argument seam works and keeps the closed model and sanitized errors, the
elicitation gate is correct and additive, and every gate is green. One **High** finding blocks
integration: the opt-in live test suite — the repository's only firmware-compatibility evidence
path — was not migrated and fails on its first assertion, and the failure is hidden by the `live`
skip marker. One **Medium** documentation inconsistency (ADR-001 §10 still publishes the pre-0.7
tool counts) and five **Low** accuracy findings follow.

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | **High** | `tests/live/conftest.py:36`, `:77-78`; `tests/live/test_live_reads.py:208,242,285,301`; `tests/live/conftest.py:11`; `.github/workflows/live.yml:6` | **The live test suite was not migrated to 0.7.0 and fails on its first assertion; the `live` skip marker hides it.** `EXPECTED_LIVE_TOOL_COUNT` is still `98` (the read-only surface is `74`), so `assert_read_only_surface` — the first call in every live test — fails. The four `call_tool` sites still wrap arguments in `{"request": ...}`, which the flat-argument model now rejects. Two comments still say "54 mutation tools" (38). | `pytest -m live -q` → `100 skipped, 1231 deselected` (no credentials). With the in-memory read-only server: `EXPECTED_LIVE_TOOL_COUNT = 98 actual = 74`; `assert_read_only_surface FAILED: the read-only server must publish 98 tools, got 74`. `call_tool("zone_list", {"request": {}})` → `Error executing tool zone_list: invalid arguments: request is not an accepted argument; accepted arguments are page, page_size, page_total, name_contains, name_not_equals`. The flatten commit `760a663` updated `tests/test_vpn.py` and `tests/test_live_deviations.py` but not `tests/live/`; `tests/live/conftest.py` was never touched by the PR. | Set `EXPECTED_LIVE_TOOL_COUNT = 74`; drop the `request` wrapper at the four call sites (`{"request": request}` → `request`, `{"request": {}}` → `{}`, `{"request": args}` → `args`, and the pagination call); change "54 mutation tools" to 38 in `conftest.py:11` and `live.yml:6`. Add a non-`live` test that runs `assert_read_only_surface` against the in-memory server so this drift cannot hide behind the skip marker again. |
| 2 | **Medium** | `docs/architecture/ADR-001-rest-client-strategy.md:433-434`, `:455` (and `:183`, `:298`) | **ADR-001 §10 still publishes the pre-0.7 tool counts.** It says "145 operations / 152 MCP tools across 11 domains" and its per-domain table sums to 152 tools (Firewall 16, NAT 12, Addresses 37, Network 44). The 0.7.0 surface is 112 tools (Firewall 8, NAT 6, Addresses 27, Network 28). `API-COVERAGE.md` §4 and `coverage_curated.yaml` both say 112, so the three documents the protocol requires to agree do not. | `ADR-001:433-434` "145 operations / 152 MCP tools across 11 domains"; `ADR-001:455` Total row = 145 ops / 152 tools; `API-COVERAGE.md:105` "145 operations and 112 MCP tools"; `API-COVERAGE.md:122` Total row = 145 ops / 112 tools; measured `create_server(...).list_tools()` → 112, and per-domain 8/6/27/28. | Update ADR §10 to 145 operations / 112 tools with the per-domain tool counts from `API-COVERAGE.md` §4, and add a one-line note that the 0.7.0 IPv4/IPv6 collapse reduced the tool count from 152 to 112 without changing the operation scope. |
| 3 | Low | `src/sophos_firewall_mcp/server.py:147`; `CHANGELOG.md:34` | **The published `INSTRUCTIONS` and the CHANGELOG say a union-request tool publishes a root `oneOf`, but `mac_address_create` publishes `anyOf`.** The README, the `sophos://conventions` resource and the release notes do state the exception; the server-level instructions (the one string every client shows the model) and the CHANGELOG do not. | `server.py:147` "whose request is a union of shapes publishes a root `oneOf` instead"; `CHANGELOG.md:34` "publishes a root `oneOf` of the closed variants"; measured `mac_address_create` input schema root key is `anyOf` (2 variants). `README.md:180`, `resources.py:375`, `RELEASE-0.7.0.md:175` carry the exception. | Add "(`mac_address_create` publishes `anyOf` because the API declares no discriminator)" to `INSTRUCTIONS` and the CHANGELOG sentence, matching the README. |
| 4 | Low | `src/sophos_firewall_mcp/tools/__init__.py:796-830`, `:177`, `:918` | **Union-request tools produce confusing and truncated argument errors.** A discriminated-union failure enumerates every variant's errors, so the model sees contradictory rules, and the 300-character cap truncates the message mid-sentence. Flat tools are clean. | `firewall_rule_create` with `{"ip_family": "ipv9", "name": "x"}` → `invalid arguments: ip_family must be one of 'ipv4'; source_zones is required; … ip_family must be one of 'ipv6'`. `address_create` with `{"ip_family": "ipv4", "type": "bogus", "name": "x"}` → 24 errors, truncated at 300 chars (`… ipv4_address_end is required; t`). `firewall_rule_list` with `{"bogus": 1}` → `bogus is not an accepted argument; accepted arguments are ip_family, page, page_size, page_total, name_contains, name_not_equals` (good). | For a discriminated union, report the discriminator failure once with the accepted values (`ip_family must be one of 'ipv4', 'ipv6'`) and suppress the per-variant required-field noise; keep the existing flat-tool rendering. |
| 5 | Low | `tests/test_tool_surface.py:5` | **The module docstring is stale and arithmetically wrong.** It says "the curated `tool_map` (145 operationIds) plus the seven declared composites -- 112 tools"; there are five composites (145 + 7 = 152, not 112). The constant `EXPECTED_COMPOSITE_COUNT = 5` at `:53` is correct. | `tests/test_tool_surface.py:5`; `:53` `EXPECTED_COMPOSITE_COUNT = 5`; `scripts/coverage_curated.yaml` `composite_tools` has 5 entries. | Change "seven" to "five" and "145 operationIds" to "145 operationIds mapped to 107 one-to-one tools". |
| 6 | Low | `CHANGELOG.md:60-61`; `README.md:263` | **The intermediate catalog size `655,479` does not reproduce.** Measured over STDIO at `b22731a` (the direct parent of the flatten commit) the `tools/list` line is **655,034** bytes, not 655,479. The pre-0.7 `807,900` measures **807,920** (20 bytes off). The final `622,787` reproduces exactly. The derived "152,421 bytes removed" is therefore approximate. | `git archive b22731a` + STDIO `tools/list` → `655034`; `git archive origin/main` + STDIO `tools/list` → `807920`; current HEAD → `622787` (exact). `CHANGELOG.md:60-61`, `README.md:263`. | Re-measure the intermediate point and use the reproducible numbers, or state the exact commit and serialization each number came from. |
| 7 | Low | `docs/release/RELEASE-0.7.0.md:28-31`, `:260`; `CHANGELOG.md:28` | **"The output shape is unchanged" is imprecise for a breaking release.** The published output *schema* changed for 40 of the 80 merged pairs because the merged output models carry the union of both families (e.g. `address_get` now publishes 8 address variants instead of 4). The output *payload* for a given family is unchanged. | Old `address_get_ipv4` output `$defs` = 4 IPv4 variants; new `address_get` output `$defs` = 8 (both families). 40/80 pairs differ byte-for-byte in `output_schema`. `RELEASE-0.7.0.md:28-31` "The output shape is unchanged: a merged output model carries the union of the two family projections" (self-contradictory); `:260` "the wire body and the output shape are the same in both releases". | Say "the output payload for a given family is unchanged; the published output schema is the union of both families" and note it in the rollback section. |

## Verified

All commands were run in this worktree at `12124e7`; nothing below is taken from the PR text.

- **Gates green.** `pytest -q` → **1231 passed, 100 skipped** (193 s). `mypy src` → 28 files, no
  issues. `flake8 src tests scripts` → clean. `black --check src tests scripts` → 54 files
  unchanged. `python scripts/generate_coverage.py --check` → "up to date". `uv lock --check` → 55
  packages. `pyproject.toml:3` and `uv.lock:1228` both say `0.7.0`.
- **Surface count.** `create_server(Settings(...)).list_tools()` → **112 tools, 112 unique names**;
  read-only mode → **74 tools, 0 mutations**; **0 tools publish a `request` property**; 96 flat +
  9 union + 7 no-argument = 112.
- **IPv4/IPv6 collapse.** 80 removed names and 40 added names, exactly the 40 merged tools; the
  migration table in `MIGRATION-0.7.md` has 80 rows and covers **every** removed name with the
  correct `ip_family` (programmatic set comparison against the pre-0.7 `tool_map`). The
  `RELEASE-0.7.0.md` table is byte-identical to it. The 6 IPv4-only IPsec tools are present and
  `tools/vpn.py` / `models/vpn.py` are untouched.
- **Wire body byte-identical per family.** For all 80 pairs I compared the old per-family request
  model's field metadata (name, alias, serialization alias, annotation, required, default) with the
  new merged variant's, excluding `ip_family`: **0 differences**. Every adapter strips `ip_family`
  (`exclude={"ip_family"}`) before the body is built, and the merged network tools are all reads.
  `ip_family` is required on all 40 merged tools (32 flat + 8 union) and optional only on the 3
  audit composites.
- **Flat arguments.** The seam (`_flatten_arguments`, `_flat_argument_model`,
  `_union_argument_model`) replaces both `fn_metadata.arg_model` and `tool.parameters`; the
  handler still receives the request model (`Flat` is a subclass, `model_fields_set` exact,
  `model_dump_one_level` → `{"request": self}`). `populate_by_name` survives (a camelCase alias is
  still accepted). 9 union tools publish a root union of closed variants: 8 `oneOf` and
  `mac_address_create` `anyOf` (correct for an undiscriminated union). The private SDK seam is
  confined to one accessor and pinned by three tests.
- **Elicitation.** The four gated deletes (`firewall_rule_delete`, `nat_rule_delete`,
  `network_user_delete`, `network_interface_delete_vlan`) call `confirm_destructive` **before** the
  adapter, so a declined/cancelled answer sends zero HTTP requests (proven by
  `tests/test_destructive_confirmation.py` with `router.calls == []`). A client with no
  `elicitation` capability, no `form` mode, or a transport without a back-channel keeps the previous
  behaviour (`NoBackChannelError` is an `MCPError`, caught before the `ValueError` branch). The
  modern-transport limitation is documented accurately against `mcp` 2.3.0.
- **`openWorldHint`.** 6 `true` / 106 `false`, exactly `OPEN_WORLD_TOOLS`; pinned by three tests
  (per-tool verdict, exact set, set ⊆ registered names). The mapping is defensible: the six are the
  results produced by entities the appliance does not own (DHCP clients, live users, live IPsec
  peers, the carrier, the vendor DNS verdict).
- **Scope and exclusions.** 145 operationIds in `tool_map` → 107 distinct one-to-one tools + 5
  composites = 112. No `bulk*`, `login`/`logout`, `admin*` or `waf*` tool. 20 VPN tools, read-only.
  VLAN-only writes pre-read the target/parent and refuse any non-`vlan` type. All composite
  `operation_ids` are present in `tool_map`.
- **Coverage matrix.** `COVERAGE_DOMAINS` tool counts match the live registry exactly (8/6/27/10/6/2/
  11/9/28/2/3/0/0 = 112) and `api_operations` sums to 700. `API-COVERAGE.md` §4 says 145/112/11 and
  the generated document regenerates without drift.
- **Release pack.** `622,787` bytes reproduces exactly over STDIO (including the newline).
  `222,419 → 199,114` input-surface bytes reproduce exactly at `b22731a` → HEAD. The migration
  table matches the code. The publication checklist correctly leaves the review/CI/tag items
  unchecked and the approval record says "Not approved yet".
- **Git hygiene.** 7 commits, each with explicit scoped paths; no `add -A` evidence; no out-of-scope
  files (42 changed files, all in the release scope, including the CI count fix in `12124e7`).

## Not verified

- **The live suite against a real appliance.** No lab credentials in this session, so the 100 live
  tests were skipped. I proved the two independent breakages statically and against the in-memory
  server (finding 1), but I did not observe the live run itself.
- **The intermediate `655,479` measurement point.** I reproduced `655,034` at `b22731a` (the direct
  parent of the flatten commit) and `622,787` at HEAD, but I could not reproduce `655,479` from any
  committed tree; the author's exact working-tree state is unknown (finding 6).
- **Firmware behaviour.** No appliance was contacted; every runtime claim above is contract-level
  (respx/in-memory), not firmware compatibility.
- **CI on the merge commit.** The workflows were read, not executed; the image smoke test now
  expects 112 (`docker-build.yml:69`), but the CI run itself is outside this session.

## Residual risks

- **A 2025-06-18 client that declares the legacy empty `elicitation: {}` capability is treated as
  not supporting elicitation** (`_client_can_elicit` requires `capability.form`), so the
  confirmation is silently skipped for it. This is a safe fallback (the delete proceeds) and the
  module docstring documents "carries no form mode", but the affordance does not fire for that
  client generation. Worth a sentence in the release notes.
- **The flatten seam depends on three private SDK attributes** (`MCPServer._tool_manager`,
  `Tool.fn_metadata.arg_model`, `Tool.parameters`). The seam is confined to one accessor and pinned
  by tests, but an `mcp` 2.3.x patch that changes `Tool.run`'s validation path would break every
  tool's argument handling at once. The `mcp>=2.3.0,<3` range allows that.
- **The output schema is now a union of both families for 40 pairs.** Clients that generate types
  from `outputSchema` will see a wider type; clients that validate payloads are unaffected. This is
  a schema-level breaking change that the release notes currently understate (finding 7).
- **The live suite is the only firmware-compatibility evidence path and it is currently broken.**
  Until finding 1 is fixed, the next live run cannot produce evidence, and the "100 skipped" in the
  PR evidence masks that.
