# Independent review — Phase 6 (MCP quick wins, issue #45)

| Field | Value |
|---|---|
| **Reviewer** | `reviewer6` (independent; did not write the code) |
| **Date** | 2026-11-15 |
| **Branch** | `feat/mcp-quick-wins` |
| **Reviewed HEAD** | `4b810cc` — *fix(mcp): strip internal planning markers from the published surface (M4)* |
| **Base** | `origin/main` (`15a342b`) |
| **Diff** | 24 files, +800 / −213, 4 commits |
| **PR** | [#48](https://github.com/lordraiden/sophos-firewall-mcp/pull/48) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](./execution/04-REVIEW-PROTOCOL.md) |
| **Inputs** | full diff; PR #48 description; issue #45; `MCP-STANDARDS-REVIEW.md` (H1, H2, M1, M2, M4, M7, M8, §4) read from `d986235` because it is not on `main` or the PR branch; `README.md`; `tests/test_tool_surface.py`; `tests/test_server.py`; `tests/test_models_common.py`; the installed `mcp` 2.3.0 (`MCPServer` signature, `mcp/server/caching.py`, `mcp_types.methods`); the live `tools/list`, `server/discover` and `initialize` surfaces |

---

## Verdict

**CHANGES REQUIRED** — **2 Medium**, **6 Low**. No Critical and no High finding.

The seven "Do first" items are implemented and the core mechanics are correct. I re-ran every gate
(`pytest -q` 1148 passed / 100 skipped, `mypy` 26 files, `flake8` clean, `black --check` 49 files,
`generate_coverage.py --check` up to date, `uv lock --check` 55 packages) and independently enumerated
the live surface: the wrapper example is neutral and names no rejected field on any of the 144 wrapped
tools; `INSTRUCTIONS` carries both conventions in `initialize` and `server/discover`; `tools/list` and
`server/discover` both advertise `ttlMs: 3600000` / `cacheScope: private`; all 41 paginated tools publish
the same two `page`/`page_total` texts with the defaults and bounds unchanged; the marker guard sweeps
457 blobs, reports 0 of the five markers, and fails on a synthetic one; and an AST comparison of all 19
changed `src/` files shows only `description=` additions plus two error strings, so the wire body is
unchanged.

The two Medium findings are not in the wire behaviour. The first is the **`serverInfo.version`
acceptance criterion**: issue #45 item 3 requires the version to equal the package version, but the
delivered server reports `0.4.0` while `pyproject.toml` is `0.6.0`, and the test that is supposed to
prove the property compares the metadata to itself, so it cannot catch the drift. The second is that the
**PR's stated basis is not in the repository**: `MCP-STANDARDS-REVIEW.md` is absent from `main` and from
the PR branch, so the "Do first" list the PR implements cannot be read from the PR. Both are cheap,
concrete fixes.

The Low findings are a behaviour change beyond descriptions (two sanitized error strings), a stale
`tools/list` size in the README, the `content`/`structuredContent` guidance being duplicated rather than
moved, a marker guard narrower than its stated goal, a `server/discover` cache hint tested only as a
dict, and one commit that mixes scopes.

---

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | **Medium** | `src/sophos_firewall_mcp/server.py:159-160`; `tests/test_server.py:333-350` | **The `serverInfo.version` acceptance criterion is not met as delivered, and the test that should prove it is tautological.** Issue #45 item 3 requires "`serverInfo` carries a non-empty version equal to the package version". The delivered server reports `version: "0.4.0"` and the 0.4.0 summary, while `pyproject.toml` is `0.6.0` with a different description. The docstring claims "Nothing is duplicated in code, so a release bump cannot leave `serverInfo` reporting a stale version"; the delivered value is the counterexample. The test compares `info.version` to `importlib.metadata.version(...)` — the same source the code reads — so it cannot detect pyproject/metadata drift. | `initialize` probe over STDIO: `serverInfo: {"description": "MCP server for the Sophos Firewall Configuration REST API (SFOS): typed, bounded administration tools over STDIO", "name": "Sophos Firewall MCP Server", "title": "Sophos Firewall MCP", "version": "0.4.0", "websiteUrl": "https://github.com/lordraiden/sophos-firewall-mcp"}`. `importlib.metadata.version("sophos-firewall-mcp-server")` → `0.4.0`; `pyproject.toml:3` → `0.6.0`; `pyproject.toml:4` description differs. `tests/test_server.py:348` `assert info.version == installed_version`. The installed dist-info is `sophos_firewall_mcp_server-0.4.0.dist-info`. | Re-sync the environment (`uv sync --locked`) so the installed metadata is 0.6.0, and make the test compare against `pyproject.toml`'s `project.version` (or assert the version is not `_UNKNOWN_VERSION` and equals the project metadata) so a stale install fails loudly. Correct the docstring claim. |
| 2 | **Medium** | `README.md:218`; PR #48 description; issue #45 | **The PR's stated basis is not in the repository: the `MCP-STANDARDS-REVIEW.md` link is dead.** The PR description and issue #45 both link to `docs/architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW.md`, but the file is absent from `origin/main`, from `HEAD` and from `origin/feat/mcp-quick-wins`; it exists only on the unmerged `origin/migration/phase-5-output-contract` branch (commit `d986235`, one commit ahead of `main`). The "Do first" list the PR implements cannot be read from the PR. | `git cat-file -e origin/main:docs/architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW.md` → ABSENT; `HEAD` → ABSENT; `origin/feat/mcp-quick-wins` → ABSENT; `origin/migration/phase-5-output-contract` → PRESENT. `git rev-list --count origin/main..origin/migration/phase-5-output-contract` → 1 (`d986235`). | Merge `d986235` (or the document) into `main`/the PR branch before the PR is reviewed/merged, or link to the branch/commit that contains it. |
| 3 | Low | `src/sophos_firewall_mcp/tools/firewall_rules.py:149`; `src/sophos_firewall_mcp/tools/audit.py:780`; `tests/test_firewall_rules.py:360` | **A behaviour change beyond descriptions/metadata: two sanitized error messages changed.** Commit `4b810cc` says "no behaviour, field name, schema or wire body changes", but the malformed-payload `ToolError` text changed from "does not match the contract" to "does not match the API" in two tools, and a test was updated to match. The task's requirement is "no tool name, schema or behaviour changed beyond the descriptions/metadata". | `git diff origin/main...HEAD -- src/sophos_firewall_mcp/tools/firewall_rules.py` shows `- "the appliance returned a firewall rule that does not match the contract "` / `+ "... does not match the API "`; `tools/audit.py:780` the same for the audit page; `tests/test_firewall_rules.py:360` `assert "does not match the API"`. | Either revert the two error strings to the original text (the M4 goal was the published surface, not the error text) or state the change explicitly in the PR/commit as a behaviour change. |
| 4 | Low | `README.md:218` | **The README's headline `tools/list` size is stale.** It says 950,591 bytes / ~238k tokens; the measured wire response is 894,137 bytes (~223k tokens) and the PR's own evidence says 895,339 bytes. The number is the pre-change measurement from the standards review, not a measurement of this branch. The other numbers in the section (598 KB output schemas, ~75 KB titles, 308 KB pairs) still match. | Raw JSON-RPC `tools/list` over STDIO: 894,137 bytes including the newline; `json.dumps` compact 893,742; PR #48 "Evidence": "`tools/list`: 895,339 bytes". `README.md:218`. | Replace 950,591 with the measured wire size (894,137) and recompute the token estimate, or state the serialization used. |
| 5 | Low | `src/sophos_firewall_mcp/tools/firewall_rules.py:441,464`; `src/sophos_firewall_mcp/tools/nat_rules.py:261,381`; `src/sophos_firewall_mcp/tools/services_objects.py:282` | **The "read one of `content`/`structuredContent`" guidance was added to `INSTRUCTIONS` but not removed from the five tool descriptions, so it is now stated six times.** Commit `a2402bb` says "instead of leaving the second one in five tool descriptions", which implies a move; it was an addition. The M1 recommendation was to move it. | `grep -rn "read one of them, not" src/` → `server.py:128` plus the five tool lines above. | Remove the five description sentences (the server instructions now carry the rule) or correct the commit/PR wording to "also stated in INSTRUCTIONS". |
| 6 | Low | `tests/test_tool_surface.py:81-88,355-404` | **The marker guard is narrower than its stated goal.** It scans `description`, `inputSchema`, `outputSchema` and `instructions` (457 blobs) but not the tool `title` or `annotations`; and its "the contract" pattern is the exact phrase, so 10 published strings still reference the checked-in OpenAPI file in variant forms ("whose contract declares", "Query contract of", "query contract", "contract default: true", "the REST contract", "the IPv6 contract"). The five named markers are 0, so the guard passes. | Independent sweep of 761 blobs (description/title/inputSchema/outputSchema/annotations + instructions): 0 for `M\d+`, `the contract`, `lab appliance`, `issue #`, `live observation`; 10 for `\bcontract`. Examples: `models/network.py:244`, `models/nat.py:496`, `models/nat.py:600`, `models/users.py:196`, `models/firewall.py:1205`, `tools/audit.py:2942,2964`. | Decide whether "contract" is an internal marker; if so, widen the pattern and finish the cleanup. Add `title`/`annotations` to the sweep (cheap) so the guard covers the whole published tool object. |
| 7 | Low | `tests/test_server.py:366-373` | **The `server/discover` cache hint is tested only as a module dict, not on the wire.** `test_both_static_catalog_methods_carry_the_hint` asserts `_CATALOG_CACHE_HINTS` contents; no test asserts that a `server/discover` response carries `ttlMs`. I verified it does (3600000), but a regression in the SDK's application of the hint to that method would not be caught. | `tests/test_server.py:366-373`; raw `server/discover` with the modern envelope → `ttlMs: 3600000`, `cacheScope: "private"`. | Add a wire-level assertion for `server/discover` (the SDK's `Client` has no `discover()` in 2.3.0, so use the raw JSON-RPC path the standards review used). |
| 8 | Low | `e6c0b42`; PR #48 "Attribution note" | **Commit hygiene: the M7 commit carries an unrelated change, and the PR misdescribes it.** `e6c0b42` ("document page and page_total") also rewrites the marker test's failure path in `tests/test_tool_surface.py` (`assert offenders == []` → `if offenders: raise AssertionError`). The PR calls it "9 lines of `mcp-docs`' black formatting fix"; it is a semantic rewrite, not formatting. | `git show e6c0b42 -- tests/test_tool_surface.py`; `git show --name-only e6c0b42` includes `tests/test_tool_surface.py`. | Correct the attribution note (it is a semantic change, not black formatting) and, going forward, keep the M7 commit to the six models + `tests/test_models_common.py`. |

---

## Verified

- **Wrapper example (item 1).** Enumerated the live surface: 144 tools publish a `request` property, 8
  publish none (`dns_settings_get`, `dhcp_lease_list_ipv4/ipv6`, `ipsec_live_connection_list_ipv4`,
  `ipsec_remote_access_settings_get`, `sslvpn_global_settings_get`, `network_status_dns_protection`,
  `network_status_cellular_wan`). `_REQUEST_WRAPPER_NOTE` is `{"request": {...}}` and names no field, so
  no tool is told to send a field it rejects. `tests/test_server.py:1073` sweeps all 144 and asserts the
  count; it fails if the example ever names a field outside `{"request"} ∪ request-model properties`.
- **`INSTRUCTIONS` (item 2).** The string carries both conventions (`request` wrapper with the neutral
  example; "read one of them, not both"). Verified in the live `initialize` response and in
  `server/discover` (`instructions` contains both sentences). `tests/test_server.py:292` asserts the
  substrings.
- **`serverInfo` (item 3).** `title` = "Sophos Firewall MCP", `description` and `website_url` come from
  the distribution metadata, `version` is non-empty. The mechanism is correct; the delivered value is
  stale (finding 1).
- **Cache hints (item 4).** `mcp` 2.3.0 accepts `cache_hints: Mapping[CacheableMethod, CacheHint]`;
  `server/discover` is in `CACHEABLE_METHODS`; `mcp/server/runner.py:359` applies the hint. Live
  `tools/list` and `server/discover` both return `ttlMs: 3600000`, `cacheScope: "private"`.
- **`page`/`page_total` (item 5).** 41 paginated tools; exactly two distinct texts (one for `page`, one
  for `page_total`), uniform across all 41; `page` default 1 / minimum 1, `page_total` default false on
  every tool. `tests/test_models_common.py` pins the six models and the 41-tool sweep.
- **Marker guard (item 7).** The test sweeps 152 × 3 published strings + the instructions = 457 blobs,
  with no allowlist. Independent sweep of 761 blobs (adding `title` and `annotations`) found 0 of the
  five markers. I proved the guard fails on a synthetic marker by injecting `"see M11 and the contract"`
  into a tool description: it raised `2 internal marker(s) reached the published surface`.
- **Wire body.** AST comparison of all 19 changed `src/` files against `origin/main` (string constants
  normalised) shows structural identity except the intended `description=` keyword additions in
  `models/firewall.py` and `models/objects.py` and the new identity/cache-hint code in `server.py`. No
  field name, alias, default, validator or serialization changed. The two error strings (finding 3) are
  the only non-description text changes.
- **Gates.** `pytest -q` → 1148 passed, 100 skipped (168.34 s); `mypy src` → success, 26 files;
  `flake8 src tests` → clean; `black --check src tests` → 49 files unchanged;
  `generate_coverage.py --check` → up to date; `uv lock --check` → 55 packages.
- **README call shapes.** Verified against the real schemas: `firewall_rule_list_ipv4` request fields are
  `page`, `page_size`, `page_total`, `name_contains`, `name_not_equals`; `firewall_rule_delete_ipv4` is
  `id_or_name`; the flat-argument rejection message matches the README example; `page: 0` is rejected
  before any I/O.
- **Scope.** 24 files, all within the seven items plus the M4 cleanup: `README.md`,
  `src/sophos_firewall_mcp/{server.py,tools/__init__.py,models/*.py,tools/*.py}` and the four test files.
  No `pyproject.toml`, `uv.lock`, workflow, script or generated-file change.
- **Commits.** Four commits, each with an explicit file list; no unrelated file outside the admitted
  `e6c0b42` mix (finding 8). Branch is in sync with `origin/feat/mcp-quick-wins` (0 ahead / 0 behind).

## Not verified

- **A live appliance.** No `SOPHOS_HOST`/API key in this environment, so no successful tool call was
  exercised end-to-end. The wire body and the tool behaviour were verified statically (AST comparison)
  and through the SDK's in-memory client, not against SFOS 23.0.0 GA-Build371.
- **CI.** I ran the gates locally, not in GitHub Actions. The `uv sync --locked` step in
  `.github/workflows/test.yml:41` is what would make `serverInfo.version` correct in CI; I did not run
  the workflow.
- **`serverInfo` in `server/discover`.** The installed SDK's `DiscoverResult` has no `serverInfo` field
  (`mcp_types/_types.py:594`), so the identity is observable only through `initialize`. The standards
  review's `server/discover` `serverInfo.version: ""` observation does not reproduce on `mcp` 2.3.0.
- **The exact `tools/list` byte count.** It depends on serialization: 894,137 bytes on the wire
  (compact), 893,742 compact `json.dumps`, 953,579 default `json.dumps`. I report the wire value.
- **The `MCP-STANDARDS-REVIEW.md` content as an input.** I read it from `d986235` on
  `origin/migration/phase-5-output-contract`; it is not in the PR (finding 2).
- **The `mcp` 2.3.0 private seam** (`tools/__init__.py` `_close_argument_model`) — unchanged by this PR
  and out of scope.

## Residual risks

- The stale local venv will keep reporting `0.4.0` until `uv sync`; CI's `uv sync --locked` prevents it
  in CI, but a developer running the server from a stale checkout sees the wrong identity.
- The marker guard's patterns are phrase-specific; a future internal reference in a variant form
  ("whose contract", "REST contract") passes. The guard also does not scan `title`/`annotations`.
- The `server/discover` cache hint relies on the SDK's generic application; no wire test pins it.
- The `request` wrapper remains a non-standard calling convention (H2's structural recommendation is
  out of scope; issue #47).
- `tools/list` is still ~894 KB with no pagination (H1's structural recommendation is out of scope;
  issue #46).
- The two error-message changes are the only behaviour delta; if a client asserts on the old text, it
  will see a different string.
