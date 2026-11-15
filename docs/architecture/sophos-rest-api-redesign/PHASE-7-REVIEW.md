# Independent review — Phase 7 (MCP catalog and runtime, issue #46)

| Field | Value |
|---|---|
| **Reviewer** | `reviewer7` (independent; did not write the code) |
| **Date** | 2026-11-15 |
| **Branch** | `feat/mcp-catalog-runtime` |
| **Reviewed HEAD** | `1b00f42` — *docs: document the resources/prompts, the trimmed catalog and SOPHOS_MAX_CONCURRENCY* |
| **Base** | `origin/main` (`3768792`) |
| **Diff** | 23 files, +2040 / −83, 5 commits |
| **PR** | [#49](https://github.com/lordraiden/sophos-firewall-mcp/pull/49) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](./execution/04-REVIEW-PROTOCOL.md) |
| **Inputs** | full diff; PR #49 description; `MCP-STANDARDS-REVIEW.md` (H1, L2, L3, L6, M3, M6, §4); `resources.py`, `prompts.py`, `server.py`, `client.py`, `config.py`, `_env_guard.py`, `models/common.py`, `tools/audit.py`; the tests; the installed `mcp` 2.3.0 (`Context.report_progress`, `Session.report_progress`, `server/discover`); `firewall_config_openapi.yaml` parsed; `docs/API-COVERAGE.md`; the live `tools/list`, `resources/list`, `prompts/list` and `server/discover` surfaces |

---

## Verdict

**CHANGES REQUIRED** — **1 High**, **1 Medium**, **8 Low**. No Critical finding.

The five "Do next" items are implemented and the two mechanical claims that matter most hold under
independent measurement. The catalog trim is genuinely lossless: all 152 input schemas are
byte-identical, the multiset of every published output annotation (`default`, `description`,
`minimum`/`maximum`, `minLength`/`maxLength`, `pattern`, `format`, `enum`, `required`, `minItems`/
`maxItems`, `uniqueItems`, `multipleOf`) is identical before and after, the only schema keys that
change are `title` (2,783 removed), `anyOf` (1,646 folded) and `type` (1,646 arrays added), a
differential validator over 4,330 probe instances finds **0** verdict mismatches between the old and
new output schemas, and four real tool results validate against the trimmed schemas end-to-end. The
measured wire reduction is real: `tools/list` is **893,690 → 807,743 bytes (−9.62 %)** over STDIO.
The semaphore, the env-guard downgrade and the per-page progress all behave as claimed, and the new
tests fail on the pre-fix code (11 of 14 selected tests fail against `origin/main`).

The High finding is in the new **prompt** surface, not in the catalog or the runtime: the
`explain_flow` prompt renders an `explain_connectivity` call that the server rejects whenever the
user omits the optional `service` argument — which is the prompt's documented minimal usage and the
exact shape its own test renders. The Medium finding is the sibling defect in `find_unused_objects`:
it forwards `ip_family="fqdn"` to `audit_firewall_rules`, whose enum is `ipv4|ipv6`. Both passed CI
because no test validates a rendered prompt's tool call against the tool's input schema.

The Low findings are documentation drift in the README section this PR edited (the headline
`tools/list` size is still the pre-trim number, the env-var count is stale, the IPv4/IPv6 pair size
is pre-trim, and the trim is attributed to an unreleased 0.7.0), two inaccurate sentences in the new
resources, a stale module docstring in `_env_guard.py`, progress reporting wired for only one of the
three long-running composites, and the test gap above.

---

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | **High** | `src/sophos_firewall_mcp/prompts.py:119-131`; `src/sophos_firewall_mcp/models/audit.py:388` | **The `explain_flow` prompt renders an invalid `explain_connectivity` call when `service` is omitted.** `_explain_message` adds `service` to the payload only when `service`, `protocol` or `port` is set (`if service_payload:`), but `ExplainConnectivityInput.service` is a **required** field. The prompt's own `service` argument is optional (`str \| None = None`, `prompts.py:271-275`) and its text reads as optional ("A service is a `name`, a `protocol`/`port` pair, or both", `prompts.py:140`). A user who selects the prompt and supplies only the two required prompt arguments gets an instruction that the server rejects. | Rendered `get_prompt("explain_flow", {"source": "10.0.0.5", "destination": "8.8.8.8"})` → `{"request": {"source": {"ip": "10.0.0.5"}, "destination": {"ip": "8.8.8.8"}}}`. Calling `explain_connectivity` with that payload → `isError: true`, `Error executing tool explain_connectivity: invalid arguments: request.service is required`. `explain_connectivity` input schema `$defs.ExplainConnectivityInput.required == ["source", "destination", "service"]`. `tests/test_server.py:1267` renders exactly this minimal shape and `:1469-1476` asserts only that `{"request":` appears, so CI cannot catch it. | Make `service` required on the prompt (and say so in the description), or always emit `"service": {}` when no service is given, or make `ExplainConnectivityInput.service` optional. Add a test that validates every rendered `{"request": …}` against the named tool's `inputSchema`. |
| 2 | **Medium** | `src/sophos_firewall_mcp/prompts.py:160-170`; `src/sophos_firewall_mcp/models/audit.py:92,251` | **`find_unused_objects` forwards `ip_family="fqdn"` to `audit_firewall_rules`, which only accepts `ipv4`/`ipv6`.** The prompt's `ip_family` argument is documented as "'ipv4', 'ipv6' or 'fqdn'" (`prompts.py:305-311`) and is copied into **both** the `audit_firewall_rules` payload and the `find_object_usage` payload. `AuditFirewallRulesInput.ip_family` is `IpFamily = Literal["ipv4", "ipv6"]`; only `FindObjectUsageInput.ip_family` is `AddressFamily = Literal["ipv4", "ipv6", "fqdn"]`. | Rendered `get_prompt("find_unused_objects", {"ip_family": "fqdn"})` → step 1 is `{"request": {"checks": ["unused-object"], "max_findings": 100, "ip_family": "fqdn"}}`; validating that against `audit_firewall_rules.inputSchema` → `'fqdn' is not one of ['ipv4', 'ipv6']`. The step-2 `find_object_usage` call is valid. `tests/test_server.py:1268` renders the prompt with no arguments and `:1508-1512` exercises only `ip_family="ipv4"`, so CI cannot catch it. | Drop `ip_family` from the `audit_firewall_rules` payload (the `unused-object` check does not need it), or map `fqdn` to "no audit filter", or split the prompt into `ip_family` (ipv4/ipv6) and `address_family` (adds fqdn). Add the schema-validation test from finding 1. |
| 3 | Low | `README.md:218` | **The README's headline `tools/list` size is the pre-trim number.** It still says **894,142 bytes / ~223k tokens**; the measured post-trim wire response is **807,743 bytes** (~202k tokens). The PR edited this very section (it added the "471 KB after the 0.7.0 trim" sentence at `:237`) and its own description states `894,116 → 807,786`, so the headline was known to be stale. | Raw JSON-RPC `tools/list` over STDIO on `HEAD`: 807,743 bytes without the newline (807,744 with). Same probe on `origin/main`'s tree: 893,690 bytes. `README.md:218`. | Replace 894,142 with the measured 807,743 and recompute the token estimate (~202k), stating the serialization/era used. |
| 4 | Low | `README.md:243` | **The README says "exactly these eight environment variables" but the table now lists nine.** This PR added the `SOPHOS_MAX_CONCURRENCY` row (`README.md:254`) without updating the count; `config.py:15` was updated to "nine". | `README.md:243` "eight"; the table at `:247-255` has 9 rows (`SOPHOS_HOST`, `SOPHOS_PORT`, `SOPHOS_API_KEY`, `SOPHOS_API_KEY_FILE`, `SOPHOS_VERIFY_SSL`, `SOPHOS_CA_BUNDLE`, `SOPHOS_TIMEOUT`, `SOPHOS_MAX_CONCURRENCY`, `SOPHOS_READ_ONLY_MODE`). `grep -rn "eight environment"` finds only this line. | Change "eight" to "nine". |
| 5 | Low | `README.md:237-239` | **Two stale facts in the sentence this PR rewrote.** (a) "the 40 IPv4/IPv6 tool pairs account for 308 KB between them" is the pre-trim figure; post-trim the 40 pairs are **243,179 bytes** (287,491 pre-trim by the same measure). (b) "after the 0.7.0 trim" attributes the change to a release that does not exist: `pyproject.toml` is `0.6.0` and `CHANGELOG.md` has no `0.7.0` section. | Measured paired output-schema bytes: base 287,491 → head 243,179 (40 pairs, 12 still byte-identical). `grep -n "0.7.0" CHANGELOG.md` → no match; `pyproject.toml:3` → `0.6.0`. | Use the post-trim pair figure (243 KB) and either name the release this actually ships in or say "in this change" instead of "0.7.0". |
| 6 | Low | `src/sophos_firewall_mcp/_env_guard.py:1` | **The module docstring summary still says the guard refuses to start on a shadowed `mcp`.** The body was rewritten to describe the warning, but the first line still reads "Refuse to start when `mcp` resolves outside this server's own environment", contradicting the new behaviour and the L6 fix. | `_env_guard.py:1`; `verify_local_mcp()` calls `_warn(...)` for the prefix mismatch (`:107-108`) and only `_fail(...)` for the missing `mcp.server.mcpserver` (`:110-115`). | Reword the summary to "Warn when `mcp` resolves outside this server's environment, and refuse to start when `mcp.server.mcpserver` is missing." |
| 7 | Low | `src/sophos_firewall_mcp/resources.py:196` | **`sophos://api/surface` says every tool wraps one audited operation, contradicting the seven composites it describes later in the same document.** | `resources.py:196` "Every tool is a typed wrapper over one audited operation of that API; the server adds no endpoint of its own." vs `resources.py:244-252` "Seven composite tools compose audited operations and add no endpoint". | Say "Every tool wraps one or more audited operations; the server adds no endpoint of its own." |
| 8 | Low | `src/sophos_firewall_mcp/resources.py:391-397` | **`sophos://conventions` says a failed call "names the failed operation and the HTTP status", but the example it gives is a transport error with no HTTP status.** | `resources.py:391-392`; the example at `:396` is `the firewall could not be reached or did not answer in time; retry the read [GET /network/dns/settings]` — no status. The HTTP-status form is `GET /path failed with HTTP 401` (`client.py:_response_error`). | Either add an HTTP-status example or soften the sentence to "names the failed operation, and the HTTP status when there is one". |
| 9 | Low | `src/sophos_firewall_mcp/tools/audit.py:2995,3020` | **Progress reporting is wired for only one of the three long-running composites.** `audit_firewall_rules` passes `progress=ctx.report_progress` (`:2962-2964`), but `explain_connectivity` and `find_object_usage` call the adapter without a reporter, so the two composites M6 named alongside it still emit no `notifications/progress` even though they share the same bounded walk (up to 50 and ~65 pages). | `grep -n "progress" src/sophos_firewall_mcp/tools/audit.py` → the only `progress=` call site is `:2963`. `_Budget.report_page` returns early when `progress is None` (`:262-263`). | Pass `progress=ctx.report_progress` from both handlers (the mechanism already exists in `_walk`), or state in the PR that only the audit tool reports progress. |
| 10 | Low | `tests/test_server.py:1469-1476,1480-1512` | **No test validates a rendered prompt's tool call against the tool's input schema, which is why findings 1 and 2 passed CI.** The prompt tests assert that `{"request":` appears and that individual argument values are echoed; none parses the emitted `{"request": …}` and validates it against the named tool's `inputSchema`. | `tests/test_server.py:1469-1476` (`test_each_prompt_renders_a_self_contained_instruction`) and `:1480-1512` (`test_prompt_arguments_reach_the_tool_call`, only `ipv4`). Both findings reproduce with a 20-line `jsonschema.validate` over the rendered text. | Add one test that extracts every `{"request": …}` from each rendered prompt (for each documented argument value, including `fqdn`) and validates it against the corresponding tool's published `inputSchema`. |

---

## Verified

- **Full diff read** (`git diff origin/main...HEAD`): 23 files, +2040 / −83, 5 commits (`bd83e34`, `128e55e`, `ea99c1d`, `d7f9223`, `1b00f42`). Every commit touches only its own scope; no `git add -A`; no out-of-scope path (`pyproject.toml`, `uv.lock`, `.github/`, `scripts/` untouched).
- **Gates, run independently**: `pytest -q` → **1192 passed, 100 skipped** (232 s); `mypy src` → *Success: no issues found in 28 source files*; `flake8 src tests` → clean; `black --check src tests` → 51 files unchanged; `black --check scripts` → 2 files unchanged; `python scripts/generate_coverage.py --check` → *docs/API-COVERAGE.md is up to date*; `uv lock --check` → 55 packages.
- **Catalog trim is lossless** (measured on the live surface of both trees, `create_server(...).list_tools()`):
  - **Input schemas byte-identical**: 0 of 152 tools differ (`json.dumps(..., sort_keys=True)`).
  - **Output annotations preserved**: the multiset of `default`, `description`, `minimum`, `maximum`, `exclusiveMinimum`/`exclusiveMaximum`, `minLength`, `maxLength`, `pattern`, `format`, `enum`, `const`, `required`, `minItems`, `maxItems`, `uniqueItems`, `multipleOf` is identical — **0 of 152** tools differ.
  - **No other key changed**: a census of every JSON-Schema key in the output schemas shows no key type lost or gained and no count change for any key except `title` (3,486 → 703), `anyOf` (2,324 → 678) and `type` (arrays 0 → 1,646).
  - **The documented exclusions are exactly what remains**: the 678 remaining `anyOf`-with-null nodes are 552 `$ref` branches and 126 `enum` branches — precisely the two cases the code documents as unfoldable (`models/common.py:39-45`).
  - **Results still validate**: a differential validator over **4,330 probe instances** (valid, invalid, null, boundary, extra-property, per-property) finds **0** verdict mismatches between the base and trimmed output schemas; and four real results (`firewall_rule_list_ipv4`, `firewall_rule_get_ipv4`, `network_interface_list`, `dns_settings_get`, including the epoch-sentinel → `null` case) validate against the published trimmed `outputSchema` with `jsonschema` 4.26.0.
  - **The reduction is real**: output schemas 557,423 → 471,093 bytes (−15.49 %); `tools/list` wire 893,690 → 807,743 bytes (−9.62 %); 2,783 property titles removed; 1,646 nullable unions compacted. These match the PR's numbers (557,423 → 471,093; 2,783; 1,646) within measurement noise.
- **Progress is per page and does not change the output**: `_Budget.report_page` is called after each page in the shared `_walk` (`tools/audit.py:838-841`), `current` is the global pages-read counter and `total` is `MAX_PAGES_TOTAL` (80); `ctx.report_progress` is a no-op without a progress token (`mcp/server/session.py:426-433`). The three new tests assert one notification per page, a global counter across collections, and byte-identical `structuredContent` with and without a callback.
- **Resources and prompts are non-empty and accurate**: 4 resources and 3 prompts are published and readable; `server/discover` advertises `prompts` and `resources` with `ttlMs: 3600000`, `cacheScope: private`, `serverInfo.version: 0.6.0`, title, description and `websiteUrl`. The inventory constants were checked against the parsed YAML: **384 paths, 700 operations (GET 263 / POST 210 / PATCH 134 / DELETE 93), 32 component schemas, 83 paginated GETs** — all exact. The coverage matrix was checked against `docs/API-COVERAGE.md` §5 (13 section counts, sum 700) and against the live registry (**152 tools, 98 read-only / 54 mutations, 144 wrapped / 8 no-argument, 11 domains partitioning all 152 names with no overlap and no orphan**). Every backticked snake_case token in the resource and prompt text is either a registered tool or a documented argument name (the only non-tool tokens are `page_size`, `page_total`, `object_type`, `max_references`).
- **Semaphore bounds concurrency and is released correctly**: one `asyncio.Semaphore` per client, default 4, `SOPHOS_MAX_CONCURRENCY` validated to 1–64 (`config.py:48-58,229-236`), acquired per attempt in the single `_send` choke point (`client.py:342-345`), released by `async with` on the error path, and not held during the `_read` backoff (the sleep happens outside `_send`). The four new tests cover the bound (peak 4/2/1), the shared read/write bound, the error-path release and the backoff release.
- **Env guard warns instead of aborting for a shadowed `mcp`, and still exits for a missing `mcp.server.mcpserver`**: `_warn` then `_fail` (`_env_guard.py:104-115`); the new tests cover the warning, the actionable text, the combined warn+exit case and the silent normal path.
- **The wire body is unchanged**: input schemas are byte-identical, so every request body built from them is unchanged; tool names, titles and annotations are identical for all 152 tools; the only description changes are the three documented latency sentences on the audit composites.
- **The new tests prove the new behaviour**: running the head test files against the `origin/main` tree (a copy with `pythonpath = ["src"]` resolving to the base source) fails **11 of 14** selected tests — the trim tests, the semaphore-bound tests, the env-guard warning tests, the progress tests and the latency-description test all fail on the pre-fix code. The three that pass are regression guards that are trivially true without the feature.
- **No security regression**: no new secret, URL, header or network path; the resources embed no credential; the API key remains a `SecretStr` and is absent from the new text; the env-guard warning goes to stderr, not stdout.
- **No critical `TODO`/`FIXME` added** (`git diff | grep '^+.*TODO\|FIXME'` → none).

## Not verified

- **Live appliance behaviour.** This environment has no `SOPHOS_HOST`/API key, so I could not measure the real per-page latency behind the new "a few seconds … up to a minute" sentences, nor observe `notifications/progress` against a real client. The progress tests use the SDK's in-process client.
- **The modern-era `tools/list` byte size.** My raw STDIO probe used the legacy `initialize` handshake (807,743 bytes); the 2026-07-28 era adds `resultType`/`ttlMs`/`cacheScope`, so the modern figure is a few dozen bytes larger. The PR's 807,786 is consistent with that, but I did not reproduce it exactly.
- **Client-side handling of `type: [X, "null"]`.** The form is valid JSON Schema (draft-07 and later) and the SDK does not validate against the published schema, but I could not test how Claude Desktop, VS Code, Cursor or Antigravity IDE parse a `type` array.
- **The Docker image and the CI workflows.** Not changed by this PR; not built or run.
- **The `mcp` 2.3.0 private seam** (`tools/__init__.py` argument-model replacement). Unchanged by this PR; the standards review already records it as a residual risk.

## Residual risks

- **The latency sentences are expectations, not bounds.** "Reads up to 80 pages; expect … up to a minute on a large one" is a typical-case statement. With a 30 s per-request timeout and two read attempts, the true worst case is far longer than a minute; a client that implements a per-call timeout can still abandon the call. The sentence is exactly what M6 recommended, but it should not be read as a guarantee.
- **`type: [X, "null"]` is a compatibility bet.** It is correct JSON Schema and shrinks the catalog, but a client with a naive single-string `type` parser would mis-handle 1,646 published nodes. The alternative (`anyOf`) is more verbose but more universally parsed.
- **The resource inventory constants are hardcoded.** `API_PATHS=384`, `API_OPERATIONS=700`, `API_COMPONENT_SCHEMAS=32` and `API_PAGINATED_GET_OPERATIONS=83` are literals in `resources.py`; the drift test only checks the per-domain counts against `docs/API-COVERAGE.md`, and the surface test only checks that the digits appear. A YAML regeneration would be caught by the coverage SHA gate, but the resource's own numbers would not fail a test.
- **Two of the three long-running composites still report no progress** (finding 9), so the M6 "opaque hang" concern is only half closed.
- **Model-level `$defs` titles remain published** (703 class names such as `FirewallRuleIpv4Output`). This is deliberate and documented, but it is still an internal Python identifier in the public schema.
- **`explain_connectivity` requires a `service` object whose members are all optional.** The prompt defect in finding 1 is a symptom of that asymmetry; making `service` optional (or always emitting `{}`) would remove the class of error rather than one instance of it.

---

## Re-check after fixes

| Field | Value |
|---|---|
| **Re-checked HEAD** | `0d22c45` — *fix(mcp): close the phase-7 review findings* |
| **Delta since review** | 1 commit, 7 files, +278 / −44 (`README.md`, `_env_guard.py`, `prompts.py`, `resources.py`, `tools/audit.py`, `tests/test_server.py`, `tests/test_audit.py`) |
| **Scope** | focused re-check of the ten findings, not a second full review; the verdict above is unchanged and superseded only by the status below |

### Status of the ten findings

| # | Severity | Status | Evidence on `0d22c45` |
|---|---|---|---|
| 1 | High | **Closed** | `explain_flow.service` is now a required `str` with `min_length=1` (`prompts.py:274-282`), and `_explain_message` always emits `"service": {"name": …}` (`prompts.py:126-134`). Every rendered `explain_connectivity` call validates against the tool's `inputSchema` for `ip`, `zone` and `fqdn` endpoints, with and without `protocol`/`port`. `port` without `protocol` `tcp`/`udp` raises (`prompts.py:124-125`); a missing or empty `service` raises. The two new tests (`tests/test_server.py:1602,1623`) fail on `e65fffe`. |
| 2 | Medium | **Closed** | `_unused_message` forwards `ip_family` to `audit_firewall_rules` only when it is in `AUDIT_IP_FAMILIES = ("ipv4","ipv6")` (`prompts.py:49,168`); `fqdn` still reaches `find_object_usage` (`prompts.py:174-175`) and the prompt text explains why (`prompts.py:183-188,197`). Rendered `fqdn` → audit call without `ip_family` (valid) and usage call with `ip_family: "fqdn"` (valid). The matrix test covers `fqdn` (`tests/test_server.py:1276,1315-1316`). |
| 3 | Low | **Closed, with a 157-byte drift** | `README.md:218` now says 807,743 B / ~202k tokens and states the measurement method. Measured on `0d22c45`: **807,900 B including the newline** (807,899 without). The 157-byte delta (156 in the compact form) is the two 78-character progress sentences added to `explain_connectivity`/`find_object_usage` in the same commit. See new finding 11. |
| 4 | Low | **Closed** | `README.md:244` "nine environment variables"; the table at `:248-256` has 9 rows. |
| 5 | Low | **Closed** | `README.md:238` "after the catalog trim" (no unreleased version); `README.md:240` "243 KB"; measured paired output schemas on `0d22c45`: **243,179 B**. |
| 6 | Low | **Closed** | `_env_guard.py:1-2` now reads "Warn when `mcp` resolves outside this server's environment, and refuse to start when `mcp.server.mcpserver` is missing." |
| 7 | Low | **Closed** | `resources.py:196` now reads "Every tool wraps one or more audited operations of that API". |
| 8 | Low | **Closed** | `resources.py:391-399` now says "and the HTTP status when there is one", keeps the transport example and adds an appliance-answered example. The 400 example matches `tools/__init__.py:366` plus `(HTTP 400) [POST /firewall/rules/ipv4]`. |
| 9 | Low | **Closed** | `explain_connectivity` and `find_object_usage` now take `progress` and pass `ctx.report_progress` (`tools/audit.py:1369-1378,1627-1636,3005-3009,3033-3037`); all three composite descriptions carry the progress sentence. The two new progress tests (`tests/test_audit.py:1166,1199`) fail on `e65fffe`. |
| 10 | Low | **Closed** | `tests/test_server.py:1276` adds `PROMPT_ARGUMENT_MATRIX` (every documented argument value, including `fqdn`), `:1585` adds `rendered_tool_calls`, and `:1602` validates each rendered `{"request": …}` against the named tool's published `input_schema` with `jsonschema`. It fails on `e65fffe`. |

### Gates re-run on `0d22c45`

| Gate | Result |
|---|---|
| `pytest -q` | **1196 passed, 100 skipped** (188.91 s) — +4 tests vs the reviewed HEAD |
| `mypy src` | *Success: no issues found in 28 source files* |
| `flake8 src tests` | clean |
| `black --check src tests` | 51 files unchanged |
| `python scripts/generate_coverage.py --check` | *docs/API-COVERAGE.md is up to date* |
| `uv lock --check` | 55 packages |

The catalog trim is unchanged by the fix commit: 0 of 152 input schemas differ, 0 of 152 output schemas differ, output schemas still 471,093 B, and the only description changes are the two progress sentences.

### New findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 11 | Low | `README.md:218` | **The headline `tools/list` size is 157 bytes low.** The README states 807,743 B "including the trailing newline"; the measured response on this HEAD is 807,900 B including the newline (807,899 without). The number was taken before the same commit added the progress sentence to two tool descriptions. | Raw JSON-RPC `tools/list` over STDIO on `0d22c45`: 807,900 B incl. newline. Compact `json.dumps` of the tool list: 807,752 B (807,596 B on `1b00f42`). The two added sentences are 78 characters each (156 bytes of description text). | Update to 807,900 (or "~808 KB") and keep the ~202k token estimate, which is still correct. |
| 12 | Low | `tests/test_server.py:28` | **`jsonschema` is imported directly by a test but is not declared in the `dev` dependency group.** It is a transitive dependency of `mcp` (`jsonschema>=4.20.0`), so it is always installed today, but the test's direct dependency is undeclared and would break if `mcp` ever dropped it. | `pyproject.toml` `[dependency-groups] dev` lists pytest, pytest-asyncio, respx, mypy, flake8, black, pyyaml — no `jsonschema`. `importlib.metadata.requires("mcp")` → `jsonschema>=4.20.0`. `grep -rn "import jsonschema" tests/` → only `tests/test_server.py:28`. | Add `jsonschema>=4.20.0` to the `dev` group (and regenerate the lock), or use the project's own dependency-free validator helper. |
| 13 | Low | `src/sophos_firewall_mcp/prompts.py:144-145` | **The new prompt sentence says `protocol`/`port` "refine" the service, but they do not affect the analysis.** `_service_match` uses only `service.name` (`tools/audit.py:615-628`); `protocol`/`port` are echoed into `ServiceSummary` (`tools/audit.py:1395-1397`, `models/audit.py:419-424`) and never used to decide a match. | `grep -n "service.name\|service.protocol\|service.port" tools/audit.py` → the only matching use is `service.name`; `ServiceSummary` is documented as "echoed from the request". | Say "`protocol`/`port` are recorded with the service" instead of "refine it", or make the matcher use them. |

### Re-check verdict

All ten findings are **closed**. The High and Medium are genuinely fixed, and each is covered by a test that fails on the pre-fix code (`e65fffe`): the four new tests fail there and pass on `0d22c45`. The three new findings are Low and non-blocking. From this reviewer's perspective the two blocking findings are resolved and the PR is ready to merge; the original **CHANGES REQUIRED** verdict is superseded by this re-check.
