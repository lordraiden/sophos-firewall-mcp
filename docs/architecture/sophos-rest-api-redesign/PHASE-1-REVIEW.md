# Independent review — Phase 1 (REST foundation)

| Field | Value |
|---|---|
| **Reviewer** | `reviewer` (independent; did not write the code) |
| **Date** | 2026-11-15 |
| **Branch** | `migration/phase-1-foundation` |
| **Reviewed HEAD** | `8c91210` — *ci: install the dev toolchain so the coverage validation test can run* |
| **Base** | `origin/main` @ `a67492c` |
| **Diff** | 52 files, +9,321 / −4,140 (the branch gained `8c91210` at 11:48:24 during the review; the PR text and the task brief say 51 files) |
| **PR** | [#36](https://github.com/lordraiden/sophos-firewall-mcp/pull/36) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](./execution/04-REVIEW-PROTOCOL.md) |
| **Inputs** | full diff; issues #24, #25, #26, #35; #24 15 Nov scope comment; PLAN.md; ADR-001; API-COVERAGE.md; `coverage_curated.yaml`; `generate_coverage.py`; YAML parsed with Python; tests; workflows |

---

## Verdict

**APPROVE** — with **3 Medium** and **9 Low** findings. **No Critical or High finding.**

The phase-1 exit criteria are met: the XML transport is gone, the REST client is typed and secure by
default, the MCP runtime has one lifespan-owned client with correct error/cancellation semantics, the
read-only mode does not register mutations, the coverage matrix is complete (700/700 operations, 145
operations / 152 tools / 11 domains) and regenerates without drift, and `pytest`, `mypy`, `flake8`,
`black` and `generate_coverage.py --check` are green when run independently.

The Medium findings are documentation/contract issues, not code defects. They should be fixed before
phase 2 consumes the matrix (finding 1) and before the PR is described as complete (finding 3); none of
them blocks integration.

---

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | **Medium** | `docs/API-COVERAGE.md:128` (generated from `scripts/generate_coverage.py:1296-1298`) | §4.2 states that **all** composite tools are read-only. Four of the seven are mutations: `firewall_rule_set_enabled_ipv4/ipv6` (PATCH `enabled`) and `firewall_rule_clone_ipv4/ipv6` (get + create). Only the three audit composites are read-only. The curated `composite_tools` entries carry no `kind`/`read_only` field, so the generator cannot distinguish them and hardcodes the sentence. | The §4.2 table itself says "Enable or disable … by PATCHing `enabled`" and "read the source … then create a copy"; ADR-001 §10 says the same ("is a `PATCH enabled` … is a `get` + `create` composition"); `docs/API-COVERAGE.md:105,121` correctly says "three read-only audit/composite tools". A phase-2 implementer following §4.2 could register `firewall_rule_set_enabled_*`/`firewall_rule_clone_*` in `SOPHOS_READ_ONLY_MODE`, defeating the read-only control. | Add `kind: read\|mutation` to every `composite_tools` entry in `coverage_curated.yaml`, render it in §4.2, and replace the hardcoded "They are read-only" sentence with the per-tool kind. |
| 2 | **Medium** | `docs/architecture/ADR-001-rest-client-strategy.md:58,63,68-70` | ADR §2.2 has measurable baseline inaccuracies: (a) "Tags 133 distinct tag names" — the YAML has **132**; (b) the counting note says the independent audit's "4,265 inline schemas / 162,760 schema nodes" are "not reproducible" — they reproduce **exactly** as the request-body + response media-type schema sites and the nodes under them; (c) the "3,936 response media types" figure actually includes **10 `Location` response-header schemas**; the media-type count is **3,926**. | Parsed YAML: `len(doc["tags"]) == 132`, 132 distinct tags used by the 700 operations; 4,265 = 339 request-body schema sites + 3,926 response media-type schema sites; 162,760 = nodes under those 4,265 schemas; 10 `Location` header schemas exist (`createDecryptionProfile`, `createSslTlsInspectionRule`, `createWebFilterException`, `createUploadedCertificate`, `createTrafficShapingPolicy`, `createWebFilterUrlGroup`, `createWebFilterCategory`, `createContentFilter`, `createWebFilterPolicy`, `createUserActivity`). 339 + 3,926 + 706 + 10 = 4,981, which is the ADR's own total. | Correct the tag count to 132; correct the breakdown to 339 request bodies + 3,926 response media types + 706 parameters + 10 response headers = 4,981; remove the "not reproducible" claim (the audit report's figures reproduce exactly under the media-type-schema definition). |
| 3 | **Medium** | `README.md:14,53,63,71-77,100-115,142-188`; `docker-compose.yml:9-14` | The user-facing setup docs still describe the **removed XML API** and its environment variables, and Compose passes no API key. Following the README cannot start the new server and instructs users to disable TLS verification. #32 owns the README/Compose rewrite, but the PR description does not list this deferral (it only mentions the `router` extra and the Dockerfile FastEmbed step). | README documents `SOPHOS_USERNAME`, `SOPHOS_PASSWORD`, `SOPHOS_API_VERSION` and `SOPHOS_VERIFY_SSL=false`; `Settings.from_env` requires exactly one of `SOPHOS_API_KEY`/`SOPHOS_API_KEY_FILE` and defaults `verify_ssl=True`. `docker-compose.yml` passes `SOPHOS_USERNAME`/`SOPHOS_PASSWORD`/`SOPHOS_API_VERSION` and no `SOPHOS_API_KEY`, so `docker compose up` fails with "one of SOPHOS_API_KEY or SOPHOS_API_KEY_FILE is required". | Add a short REST-only note to README/Compose now (or list the deferral explicitly in the PR); #32 performs the full rewrite. |
| 4 | **Low** | `docs/live-evidence/README.md:94-97` | The domain-key list is wrong: it lists `interfaces` and omits `network` and `audit`. | The canonical mapping is `docs/API-COVERAGE.md:93-99`: `firewall_rules, nat_rules, addresses, services, auth_users, live_users, ipsec_vpn, ssl_vpn, network_status, network, audit, admin_system, other`. `tests/test_coverage.py:244-261` asserts `"interfaces" not in curated["domains"]`. | Use the canonical 13 keys from API-COVERAGE §3. |
| 5 | **Low** | `docs/live-evidence/README.md:41-43` | Says the `live` marker "is not registered yet" and may emit `PytestUnknownMarkWarning`; the marker is registered. | `pyproject.toml:71-75` declares the `live` marker; the test run shows no `PytestUnknownMarkWarning`. | State that the marker is registered and remove the stale caveat. |
| 6 | **Low** | `src/sophos_firewall_mcp/config.py:82-87` | `_optional` returns the raw value without stripping, so `SOPHOS_VERIFY_SSL=" false "` and `SOPHOS_READ_ONLY_MODE=" true "` are rejected, while `SOPHOS_PORT`/`SOPHOS_TIMEOUT` accept surrounding whitespace (Pydantic strips numeric strings). A `.env` line with a space after `=` fails startup. | Probe: `Settings.from_env({... "SOPHOS_VERIFY_SSL": " false "})` → `ConfigurationError: invalid configuration: verify_ssl: Input should be a valid boolean, unable to interpret input`; `SOPHOS_PORT=" 4444 "` → `4444`; `SOPHOS_TIMEOUT=" 30 "` → `30.0`. | `return value.strip()` in `_optional` (and strip `SOPHOS_API_KEY_FILE`/`SOPHOS_CA_BUNDLE` before `Path(...)`). |
| 7 | **Low** | `src/sophos_firewall_mcp/config.py:152-168` | `Settings` accepts an empty/whitespace `api_key` when constructed directly, so `create_server`/`SophosRestClient` can start with `Authorization: Bearer ` and fail only at the first call. `from_env` rejects it. The PR description acknowledges the mutual-exclusion gap but not the empty-key case. | Probe: `Settings(host="fw.example.com", api_key="")` and `Settings(host="fw.example.com", api_key="   ")` both succeed; `Settings.from_env({"SOPHOS_HOST": "fw.example.com", "SOPHOS_API_KEY": ""})` raises `ConfigurationError`. | Add an `api_key` field validator (non-empty after strip) or re-validate in `create_server`. |
| 8 | **Low** | `src/sophos_firewall_mcp/client.py:235` | `get_page` requires `pages` to be a dict. The contract declares `pages` **optional** for `listNetworkInterfaces`, which is in the v1 network domain; a contract-valid response without `pages` would raise `SophosAPIError`. | YAML: 81 of 83 paginated GETs require `pages`; `getAllTrustedMacs` (out of v1 scope) and `listNetworkInterfaces` (in scope) declare it optional. | Require only `items` when `page_total=False`, or accept a missing `pages` (return `items` with `pages` absent). |
| 9 | **Low** | `README.md:246` | Documents `uv run python scripts/check_tdqs.py`, which this PR deletes. | `git diff --name-status origin/main...HEAD` shows `D scripts/check_tdqs.py`; the script imported `from sophos_firewall_mcp.server import mcp`, which no longer exists. | Remove/update the README line (part of #32's rewrite). |
| 10 | **Low** | `tests/test_server.py:248`; `tests/test_client.py:619` | Tests depend on private SDK/client internals: `server._lowlevel_server.get_request_handler(...)` and `client._client._trust_env`. | Issue #26: "Use public SDK registration/list APIs; do not depend on private tool registries or internal SDK implementation details." `test_transport_configuration` already shows the public alternative (capture the `httpx.AsyncClient` constructor kwargs). | Use the captured constructor kwargs for `trust_env`/`follow_redirects`; for `subscriptions=False`, assert via a public surface or document the private dependency as deliberate and version-pinned. |
| 11 | **Low** | `tests/test_coverage.py:570-588` | The live-evidence test checks tokens but not the canonical domain keys, so finding 4 passes CI. | The token list does not include `network`, `audit` or `interfaces`. | Assert the canonical domain keys from `generator.DOMAIN_ORDER`. |
| 12 | **Low** | `pyproject.toml:31-37`; `Dockerfile:14-17`; `pyproject.toml:67-75`; `.github/workflows/test.yml:15` | Deferred/nits: the dead `router` extra (`fastembed`, `numpy`) and the FastEmbed model download remain (documented deferral to #32); the pytest config lacks `asyncio_default_fixture_loop_scope`, so every run emits `PytestDeprecationWarning`; the ADR §11 says CI 3.11–3.14 while the workflow runs 3.11–3.13 (3.14 is #32). | `pyproject.toml` still declares `router`; `Dockerfile` still runs `pip install ".[router]"` and downloads `BAAI/bge-small-en-v1.5`; test output shows `PytestDeprecationWarning: The configuration option "asyncio_default_fixture_loop_scope" is unset`; `.github/workflows/test.yml:15` is `["3.11", "3.12", "3.13"]`. | #32 owns the router/Dockerfile/CI matrix; set `asyncio_default_fixture_loop_scope = "function"` now. |

---

## Verified

All commands were run in the reviewed worktree at HEAD `8c91210`; the authors' reports were not trusted.

### 1. Quality gates (run independently)

| Gate | Command | Result |
|---|---|---|
| Tests | `UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync pytest -q` | **267 passed**, 1 warning (the `asyncio_default_fixture_loop_scope` deprecation) |
| Types | `uv run --no-sync mypy src/sophos_firewall_mcp` | **Success: no issues found in 8 source files** |
| Lint | `uv run --no-sync flake8 src/sophos_firewall_mcp tests scripts` | **clean** (no output) |
| Format | `uv run --no-sync black --check src tests scripts` | **16 files unchanged** |
| Coverage drift | `uv run --no-sync python scripts/generate_coverage.py --check` | **`docs/API-COVERAGE.md` is up to date** |
| Lockfile | `uv lock --check` | **Resolved 75 packages**, exit 0 |
| Tree | `git status --short` | clean before the report was written |

### 2. Contract baseline (parsed YAML, never by eye)

- SHA-256 `58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5`, 8,934,475 bytes, git blob `40fca0b2…7214`.
- 384 paths, **700 operations** (GET 263, POST 210, PATCH 134, DELETE 93; no PUT/HEAD/OPTIONS), **700 unique operationIds** (0 missing, 0 duplicate), 32 component schemas, 76 `$ref` occurrences / 32 unique / 0 external / 0 unresolved, 0 unreferenced schemas, 0 cycles.
- 83 paginated GETs (`page`/`pageSize`/`pageTotal`); `pageSize` maximum 100 declared only on `getUsers`, `getNetworkUsers`, `getAdministrators`; no `limit`/`offset`/`cursor`.
- 134 PATCH operations, **134/134 `application/json`**, 0 `application/merge-patch+json`.
- 338 `application/json` request bodies + 1 `multipart/form-data` (`importTrustedMacs`, out of scope) + 361 none.
- 3,226 documented non-2xx responses, all one JSON envelope shape.
- 283 path parameters: 248 `sfos-object-name-or-id`, 12 `sfos-object-name-lenient-or-id`, 6 `uuid`, 17 untyped, 0 name-only (path-item-level parameters included, as the generator does).
- Status distribution exactly as ADR §2.3: 401/403/500 on 700; 400 on 636; 200 on 608; 404 on 272; 409 on 217; 201 on 92; 503 on 1.
- Constructs exactly as ADR §2.2: `allOf` 2,046, `oneOf` 1,130, `discriminator` 26, `not` 6, `nullable` 294; largest inline schema 373 dict nodes at `updateFirewallRuleIpv4` request body.

### 3. Scope revision (145 operations / 152 tools / 11 domains)

- `scripts/coverage_curated.yaml` `tool_map`: **145 entries, 145 unique tool names, every key a real operationId**.
- 7 composite tools; 145 + 7 = **152 tools**; 11 domains with tools (the other two, `admin_system`/`other`, are classification-only).
- Per domain: firewall 12 ops / 16 tools (4 composites), NAT 12/12, addresses 37/37 (MAC full CRUD, country read-only), services 10/10, auth users 6/6, live users 2/2, IPsec VPN 11/11 read-only, SSL VPN 9/9 read-only, network status 2/2, network 44/44 (41 reads + exactly 3 VLAN-only interface writes), audit 0/3.
- ADR §10 table's operationIds match `tool_map` exactly (145; the only extra YAML ids in that section are the three explicitly out-of-scope mentions `importTrustedMacs`, `networkUserLiveLogin`, `networkUserLiveLogout`); ADR per-domain numbers match API-COVERAGE §4.1 and the curated file.
- No forbidden operation in `tool_map`: no `bulkDelete*`, no WAF variant, no VPN mutation, no admin/user-group mutation, no country mutation, no non-VLAN interface write. All **79** `bulkDelete*` operations are excluded. Country groups: only `getAllCountryGroups`/`getCountryGroupByIdOrName`. MAC: exactly the 5 CRUD operations. Live users: `getLiveUsers` + `disconnectLiveUser`.
- 20 exclusion rules, 4 PATCH exceptions (`patchMessages`, `updateCentralFirewallReportingLogComponents`, `updateSyslogServerLogs`, `updateAlertNotificationSettings`; none in `tool_map`).

### 4. Coverage document completeness and determinism

- `docs/API-COVERAGE.md` has **700 operation rows, 700 unique operationIds, 700 unique (id, method, path)**; 145 rows carry a tool name and 555 carry `excluded: …`; every `tool_map` row carries exactly its mapped tool name (0 mismatches).
- `test_deterministic_regeneration` and `test_check_mode_reports_no_drift` pass; `--check` is clean; the SHA guard refuses a modified spec and `--accept-sha` does not rewrite the script for a non-default spec.
- The generated facts I spot-checked independently are correct: 3,226 non-2xx responses, 83 paginated GETs, 134 PATCH all `application/json`, 132 tags (see finding 2), 4,265 media-type schemas / 162,760 nodes under them (see finding 2), 806/19/12/248 `sfos-object-name*` format occurrences with the stated pattern coverage.

### 5. Security

- TLS verification is **on by default** (`Settings.verify_ssl=True`, `client.verify=settings.tls_verify`); `SOPHOS_CA_BUNDLE` is supported and cannot be combined with `verify_ssl=false`; `verify=false` is a documented lab override only.
- The API key is a `SecretStr`; `repr`, `str`, `model_dump_json`, validation errors and `ConfigurationError` do not contain it; `SophosRestClient.__repr__` omits it; error messages are built from method/path/status/sanitized `error` code only; `_scrub` replaces the key as defence in depth. Tests assert redaction in auth, transport and ambiguous-write errors.
- `follow_redirects=False` and `trust_env=False` are set in the `httpx.AsyncClient`; a cross-origin 302 is not followed and is mapped to `SophosAPIError`; tests prove the redirect target is never called and the environment proxy is ignored.
- Path validation rejects absolute URLs, `//` prefixes, `..`, `\`, `?`, `#`, control characters and leading/trailing whitespace **before any I/O**; no tool argument can reach `path` in phase 1 (no domain tools are registered).
- No raw remote body reaches an exception or a tool message; HTML/plain-text error envelopes are mapped by status only.
- No new secret was added by the diff (the lab key in `LAB-ACCESS.md` is pre-existing on `main`, owner decision; see Residual risks).

### 6. MCP runtime

- `Context[AppContext]` is SDK-injected and absent from the published input schema (`test_input_schema_is_closed_and_excludes_the_context_parameter`).
- The lifespan creates exactly one `SophosRestClient`, yields `AppContext(client, settings, read_only)` and closes it in `finally`; tests prove exactly-once close on normal and exceptional shutdown.
- `ToolError` for anticipated failures, `MCPError` for protocol errors, unexpected exceptions left to the SDK (the model sees only `Error executing tool <name>`); no `BaseException`; cancellation propagates (`asyncio.CancelledError` is not caught).
- `content` and `structuredContent` are not hand-duplicated (the SDK derives `content` from the return model); object-rooted output schema.
- Annotations are per tool via `register_tool`: read-only tools get `readOnlyHint=True` and no write hints; mutation tools must declare `destructiveHint` and `idempotentHint`; `openWorldHint` defaults to `True`.
- `MCPServer(..., subscriptions=False)` unregisters `subscriptions/listen` (verified against the installed `mcp==2.3.0`); STDIO stdout is clean (subprocess test), logs go to stderr, no TTY.
- Read-only mode does not register mutation tools at all (`test_read_only_mode_does_not_register_mutation_tools`); the foundation is scope-agnostic (`DEFAULT_DOMAINS = ()`, no network/audit domain code in `src/`).

### 7. Tests

- RESPX contract tests for GET/POST/PATCH/DELETE: method, exact URL, query, `Authorization`/`Accept`, `Content-Type` on POST/PATCH only, JSON body, 200/201/204, 202 rejection.
- Error cases: 400/401/403/404/409/418/500, HTML 404, plain-text 405, malformed success JSON, malformed error body, connect/DNS/TLS errors.
- Retry policy: read timeout retried once, 503 retried once, bounded at 2 attempts, no retry for 400/401/403/404/409/500, no retry for TLS/DNS.
- Ambiguous writes: POST/PATCH/DELETE timeout and connection loss raise `SophosAmbiguousWriteError` with exactly one call and no sleep.
- Lifespan, context identity, tool list, schemas, annotations, error semantics, cancellation, STDIO subprocess, coverage determinism, SHA guard.
- No test touches the network; no test is order- or time-fragile (the backoff bound is deterministic).

### 8. Git and scope

- 12 commits, no merge commits; each commit's file list is coherent with its message; no changes outside the phase paths except the justified removal of the dead `scripts/check_tdqs.py` (finding 9) and the Lead-owned `pyproject.toml`/`uv.lock`/workflow changes.
- `uv.lock` resolves `mcp==2.3.0`, `httpx==0.28.1`, `pydantic==2.13.4`; `uv lock --check` passes.
- No hand-edited generated file: the committed `docs/API-COVERAGE.md` is byte-identical to a fresh generation (`test_deterministic_regeneration`).

---

## Not verified

- **Firmware behaviour and live writes.** The lab key is read-only; no POST/PATCH/DELETE was attempted. The SFOS build is unknown (the contract exposes no version endpoint). PATCH semantics over arrays, 409 conflicts, permission-denied writes and ambiguous-write reconciliation remain unverified on the appliance.
- **ADR POC measurements that depend on the uncommitted analyzer.** `schema_objects_inline 38509`, `schema_nodes_total 52852`, the 9,180-file / 28,781,171-byte / 976,963-line generated-client measurement, the 48 warnings, 23 endpoints not generated and 25 omitted responses were not re-run; the ADR says the POC scripts are not committed. The numbers I could reproduce independently (status distribution, identifier counts, constructs, largest inline schema, SHA, size, 4,265/162,760) match except the findings above.
- **MCP Inspector.** Not available in this environment; the official SDK `Client` was used for in-process and subprocess STDIO tests, as the PR states.
- **GitHub CI execution.** Only local runs were possible. The workflow change (`8c91210`) is a single `pip install -r requirements-dev.txt` line; I did not execute GitHub Actions.
- **Commit command hygiene.** History shows file lists, not the `git add` commands; I cannot prove that no commit used `git add -A`, only that the resulting file sets are coherent.
- **Owner approval** of ADR-001 and the first-release scope (the ADR status is "Accepted (pending owner ratification … §10)").
- **Branch stability during the review.** The branch gained `8c91210` at 11:48:24 while the review was running (51 → 52 files); the findings are against HEAD `8c91210`.

---

## Residual risks

1. **Lab API key in clear.** `docs/architecture/sophos-rest-api-redesign/LAB-ACCESS.md` contains a live API key and its Bearer header (pre-existing on `main`, owner decision). It should be rotated before the repository is made public or the key is shared more widely. The new `docs/live-evidence/README.md` correctly forbids secrets in evidence records.
2. **Firmware unknown.** No compatibility claim is possible until the SFOS build is recorded and the live matrix is run per domain; the coverage matrix correctly marks this as unresolved.
3. **PATCH array/oneOf semantics, 409 and ambiguous writes** remain unverified on the appliance; the four documented PATCH exceptions are recorded but not exercised.
4. **README/Compose are stale until #32** (finding 3). Until then, the documented deployment path cannot start the REST server and recommends `SOPHOS_VERIFY_SSL=false`.
5. **Composite kind is not modelled** in `coverage_curated.yaml` (finding 1). Phase 2 must not follow §4.2's blanket read-only claim; #27/#35 must classify `firewall_rule_set_enabled_*`/`firewall_rule_clone_*` as mutations.
6. **`get_page` is stricter than the contract for `listNetworkInterfaces`** (finding 8); a contract-valid response without `pages` would be rejected.
7. **`Settings` direct construction** bypasses the empty-key/mutual-exclusion checks (finding 7); `from_env` is the enforced production path.
8. **Dead packaging weight until #32**: the `router` extra and the FastEmbed model download remain in `pyproject.toml`/`Dockerfile`; the CI matrix is 3.11–3.13 (3.14 is #32).
9. **No live `pytest -m live` tests exist yet**; the marker and protocol are documented but unexercised, so the opt-in path itself is untested.
10. **ADR counting definitions** (finding 2) should be corrected so a future reviewer does not repeat the "not reproducible" claim against the independent audit.

---

## Re-check after fixes (HEAD `c8f3d43`)

**Scope:** focused re-check of the 12 findings against the pushed HEAD `c8f3d43` (fix commits `19db836`,
`4ede207`, `a51d18b`, `c8f3d43`). This section is additive; the original verdict and findings above are
unchanged. **Original verdict: APPROVE — still stands.**

### Finding status

| # | Severity | Status | Evidence on `c8f3d43` |
|---|---|---|---|
| F1 | Medium | **Closed** | `scripts/coverage_curated.yaml` `composite_tools` carry `kind`: the four firewall composites are `mutation`, the three audit composites are `read`; `scripts/generate_coverage.py:774` rejects any value other than `read`/`mutation`; `docs/API-COVERAGE.md` §4.2 has a **Kind** column and the sentence "Each tool declares its `kind`… the four firewall composites are `mutation`… must not be registered in that mode" — the blanket "They are read-only" is gone (`grep` count 0); the per-domain tables render `4 (0 read, 4 mutation)` for firewall and `3 (3 read, 0 mutation)` for audit; `tests/test_coverage.py` asserts the exact kind map and the rendered column. |
| F2 | Medium | **Closed** | `ADR-001:58` **132** tags; `:63` 4,981 = 339 request bodies + 3,926 response media types + 706 parameters + 10 response headers; `:64` 4,265 media-type sites / 162,760 nodes, "reproduces the independent audit's figures"; the "not reproducible" note is replaced by two explicit counting definitions; `:172` 132 tag packages; `:493` CI 3.11–3.13 with 3.14 in #32. Re-parsed YAML: 132 tags, 4,265 media-type sites, 162,760 nodes, 1,148 JSON nodes / 373 dict nodes for the `updateFirewallRuleIpv4` request body. |
| F3 | Medium | **Closed** | `docker-compose.yml` passes `SOPHOS_API_KEY`/`SOPHOS_API_KEY_FILE`, `SOPHOS_VERIFY_SSL` default `true`, `SOPHOS_CA_BUNDLE`, `SOPHOS_READ_ONLY_MODE`, and no `tty`; `README.md:10-15` carries the interim REST migration note; the `scripts/check_tdqs.py` command is gone from the README; the PR #36 body now states the deferral explicitly ("The README's setup sections still describe the XML server until #32 rewrites them; an interim migration note points to `.env.example`"). |
| F4 | Low | **Closed** | `docs/live-evidence/README.md:94-97` lists the canonical 13 keys — `network` and `audit` included, `interfaces` removed. |
| F5 | Low | **Closed** | `docs/live-evidence/README.md:41-43` now says the marker is registered in `pyproject.toml`; no "not registered" caveat remains. |
| F6 | Low | **Closed** | `config.py:82-93` strips optional values; probe: `SOPHOS_VERIFY_SSL=" false "` → `False`, `SOPHOS_READ_ONLY_MODE=" true "` → `True`, `SOPHOS_PORT=" 4444 "` → `4444`; `tests/test_config.py` adds the stripping cases. |
| F7 | Low | **Closed** | `config.py:183-197` `_check_api_key`; probe: `Settings(host="fw.example.com", api_key="")` and `"   "` raise `ValidationError`; whitespace is stripped; `tests/test_config.py` adds the direct-construction cases. |
| F8 | Low | **Closed** | `client.py:243-250` accepts a missing `pages` and rejects a non-object one; probe: a `listNetworkInterfaces` body `{"items": [...]}` is accepted; tests `test_get_page_accepts_a_missing_pages_object`, `test_get_page_rejects_missing_items`, `test_get_page_rejects_non_object_pages`. |
| F9 | Low | **Closed** | `README.md` no longer references `scripts/check_tdqs.py` (the TDQS badge/section remains and is part of the #32 README rewrite — see the minor observation below). |
| F10 | Low | **Closed** | `tests/test_client.py` captures the `httpx.AsyncClient` constructor kwargs; no `_client._trust_env`/`follow_redirects` access remains (`grep` count 0). |
| F11 | Low | **Closed** | `tests/test_coverage.py` asserts `canonical_domains == generator.DOMAIN_ORDER`, every key in the README, and rejects `interfaces`/`not registered`. |
| F12 | Low | **Closed** | `pyproject.toml:70` declares `asyncio_default_fixture_loop_scope = "function"` (the project's asyncio warning is gone); `tests/test_server.py:245-254` documents the deliberate `_lowlevel_server` access and the SDK pin; the dead `router` extra/Dockerfile FastEmbed and the CI 3.14 matrix remain documented #32 items. |

### Gates re-run on `c8f3d43`

| Gate | Command | Result |
|---|---|---|
| Tests | `UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync pytest -q` | **277 passed**, 1 warning (third-party anyio `CallSpec2` deprecation; the project's `asyncio_default_fixture_loop_scope` warning is gone) |
| Types | `uv run --no-sync mypy src/sophos_firewall_mcp` | **Success: no issues found in 8 source files** |
| Lint | `uv run --no-sync flake8 src/sophos_firewall_mcp tests scripts` | **clean** |
| Format | `uv run --no-sync black --check src tests scripts` | **16 files unchanged** |
| Coverage drift | `uv run --no-sync python scripts/generate_coverage.py --check` | **`docs/API-COVERAGE.md` is up to date** |
| Lockfile | `uv lock --check` | **Resolved 75 packages**, exit 0 |

### New findings

None. Two minor observations, neither a defect:

1. The PR #36 evidence table still says "267 passed"; the re-run on `c8f3d43` is **277 passed**. Update the
   PR body for accuracy.
2. The README's TDQS badge/section (lines 6 and 37-48) still advertises the old tool set's 5.00/5.00 score.
   It is not a script reference and is covered by the #32 README rewrite; no action in phase 1.

### Re-check verdict

All 12 findings are **closed** on `c8f3d43`; no new finding. The original **APPROVE** stands.
