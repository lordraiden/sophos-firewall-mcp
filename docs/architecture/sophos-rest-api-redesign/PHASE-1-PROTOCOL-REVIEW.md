# Independent review — Phase 1 (REST foundation)

| Field | Value |
|---|---|
| **Reviewer** | `protocol-review` (independent; did not write the code, not a fork of the author) |
| **Date** | 2026-11-15 |
| **Branch** | `migration/phase-1-foundation` |
| **Reviewed HEAD** | `f5b3482` — *docs: update the review protocol and status lines for the 15 Nov scope revision* |
| **Base** | `origin/main` @ `a67492c` |
| **Diff** | 56 files, +9,779 / −4,160 |
| **PR** | [#36](https://github.com/lordraiden/sophos-firewall-mcp/pull/36) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](./execution/04-REVIEW-PROTOCOL.md) (current copy, updated for the 15 Nov 2026 scope revision) |
| **Inputs read** | full diff; PR #36 description; issues #24–#32 and #35 (bodies + the #24 scope comment); `PLAN.md`; `INDEPENDENT_REVIEW_REPORT.md`; `REFERENCES.md`; `ADR-001` (all); `API-COVERAGE.md`; `scripts/coverage_curated.yaml`; `scripts/generate_coverage.py`; `firewall_config_openapi.yaml` (parsed with Python, never read by eye); the test suite; `.github/workflows/`; `Dockerfile`; `docker-compose.yml`; `README.md`; `.env.example`; `pyproject.toml`; `uv.lock` |

---

## Verdict

**APPROVE**

No **Critical** finding. One **High**, two **Medium** and five **Low**. The High finding is a
documentation defect in the approved scope matrix, not a defect in the phase-1 code; it does not block
this merge, but it **must be corrected before #31 implements the three VLAN interface writes**, because
as written it removes the only mechanism that can enforce the VLAN-only decision on `update` and
`delete`.

The phase-1 exit criteria are met on evidence I produced myself, not on the author's report:

- the XML transport, router, raw-API tool, prompts and resources are gone; no XML-era environment
  variable, dependency or code path survives in `src/`, `pyproject.toml`, `requirements*.txt`,
  `Dockerfile`, `entrypoint.sh`, `docker-compose.yml` or `.env.example`;
- the REST client is typed, HTTPS by construction, TLS-verified by default, `trust_env=False`,
  `follow_redirects=False`, path-validated before I/O, and never retries a write;
- the MCP runtime creates exactly one client in the lifespan, closes it in `finally`, filters mutation
  tools out of the read-only tool set, propagates cancellation and lets unexpected exceptions reach the
  SDK;
- the coverage matrix is complete and deterministic: **700/700** operations, **145** in-scope
  operationIds all present and unique, **152** MCP tools across **11** domains, byte-identical
  regeneration, SHA-gated;
- `pytest` (277 passed), `mypy`, `flake8`, `black --check`, `generate_coverage.py --check` and
  `uv lock --check` are green when I run them.

I read the previous review (`PHASE-1-REVIEW.md`, verdict APPROVE, 3 Medium + 9 Low) only after forming
the findings below. I agree with its verdict and with findings 1–12 being closed; I disagree with its
implied completeness — it did not check the reachable-schema counts (my finding 4), the VLAN rationale
(finding 1) or the stale scope tables in `INDEPENDENT_REVIEW_REPORT.md` and `PLAN.md` §9 (findings 2–3).

---

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | **High** | `scripts/coverage_curated.yaml:170` (rendered at `docs/API-COVERAGE.md:592`) | The curated rationale for the VLAN-only interface writes is factually wrong and self-contradictory: "…the contract does not let the tool validate the interface type before the write; the VLAN tools reject any type other than `vlan`." The contract **does** let the tool validate before the write: `getNetworkInterface` is in the v1 scope and its 200 response exposes `type` with the full enum `physical, vlan, bridge, lag, xfrm, cellularWan`. `createNetworkInterface` carries `type` in the body (`enum: vlan, bridge, lag`), but `updateNetworkInterface` and `deleteNetworkInterface` identify the object only by `{idOrName}` and `deleteNetworkInterface` has **no** request body at all, so a pre-read is the *only* way to honour the owner decision. A phase-2 implementer following this sentence would ship `network_interface_update_vlan`/`network_interface_delete_vlan` without a pre-read and could PATCH or DELETE a physical, bridge, LAG or XFRM interface — the exact failure mode the protocol names. | Parsed YAML: `getNetworkInterface` 200 `properties.type.allOf[0].enum = [physical, vlan, bridge, lag, xfrm, cellularWan]`; `createNetworkInterface` request `type.enum = [vlan, bridge, lag]`; `updateNetworkInterface` request has a `type` property; `deleteNetworkInterface` has no `requestBody` (0 of 93 DELETEs in the contract do). Owner decision: issue #31 "A VLAN write must never be able to alter a physical interface". | Rewrite the caveat to state the required control: for `update`/`delete`, `GET` the interface by the same `{idOrName}`, reject unless `type == "vlan"`, then PATCH/DELETE; for `create`, reject any `type != "vlan"`. Regenerate `docs/API-COVERAGE.md`. |
| 2 | **Medium** | `docs/architecture/sophos-rest-api-redesign/INDEPENDENT_REVIEW_REPORT.md:192-207` | §7 "Alcance de herramientas del primer release" still publishes the **pre-revision** scope: MAC addresses "clasificado, diferido", country groups "clasificados, diferidos", and `createNetworkInterface`/`updateNetworkInterface`/`deleteNetworkInterface` listed as **excluded**. It has no network-architecture domain (zones, gateways, routes, DHCP, DNS, neighbours), no audit domain (#35), and no firewall enable/disable or clone. It contradicts ADR-001 §10, `API-COVERAGE.md` §4 and issues #24/#27/#29/#31/#35. The protocol lists this file as input 3, and `PLAN.md` §4 received a supersession note while this table did not. | `INDEPENDENT_REVIEW_REPORT.md:200` "MAC (clasificado, diferido)"; `:201` "Country groups (clasificados, diferidos)"; `:207` excluded column lists the three interface writes. `scripts/coverage_curated.yaml` tool_map contains `createMacAddress`, `getAllCountryGroups`, `createNetworkInterface` (5 MAC + 2 country + 3 interface ops), and ADR-001 §10 totals 145/152/11. | Add the same supersession note that `PLAN.md` §4 carries, pointing to ADR-001 §10 / `API-COVERAGE.md` §4, and correct the three rows. |
| 3 | **Medium** | `docs/architecture/sophos-rest-api-redesign/PLAN.md:409,567`; `PLAN.md:216`; `docs/architecture/sophos-rest-api-redesign/README.md:7,25-37` | The plan and the redesign index still describe **nine** issues and the old #31 scope. `PLAN.md` §9 is titled "Organización de los trabajos: nueve issues", lists only #24–#32, has no #35, and describes #31 as "VPN, Network Interface and Read-only Status" — the live issue #31 is "Network Architecture, VPN read-only and Status". `PLAN.md:216` (§4 prose, *not* the table the §4 note supersedes) still says interface writes "deben permanecer documentadas como diferidas". `README.md:7` says the plan covers "nueve issues"; its execution-issues table has nine rows, omits #35 and keeps the old #31 title, while the same file's Estado section correctly says "diez issues abiertas (#24–#32 y #35)". The protocol requires reporting PLAN/issues conflicts rather than silently picking one. | `PLAN.md:409` and `:567` "nueve issues"; `PLAN.md:216` "el primer release MCP empieza con list/get … Las operaciones de escritura deben permanecer documentadas como diferidas"; issue #31 title (gh) "Implement Sophos Network Architecture, VPN read-only and Status tools"; `README.md:36` "#31 — VPN, interfaces and read-only status … VPN, interfaces y diagnósticos read-only seleccionados". | Update §9 to ten issues including #35, retitle #31, and extend the §4 supersession note to cover the §4 prose; add #35 to the README table and fix its "nueve issues" line. |
| 4 | **Low** | `docs/architecture/ADR-001-rest-client-strategy.md:65,74` | The §2.2 "Reachable schema objects" figures are off by two: **38,541** (38,509 inline + 32 component) and **52,852** dict nodes do not reproduce. Re-parsing gives **38,539** (38,507 inline + 32) and **52,850**. The +2 is the two path-item-level parameters (`/application/apps/{name}`, `/application/categories/{name}`), which carry no `schema` and are therefore not schema objects; both metrics shift by exactly two. Everything else in §2 reproduces exactly, and the ADR's own definition ("every `schema` site plus the component schemas") excludes them. | Parsed YAML: 4,979 schema sites; distinct schema objects reached through `properties`/`items`/`allOf`/`oneOf`/`anyOf`/`additionalProperties`/`not` = 38,507 inline + 32 component; dict nodes over the sites + components = 52,850. The two path-level parameters: `doc["paths"]["/application/apps/{name}"]["parameters"]` and `…/categories/{name}`. | Change to 38,539 / 38,507 inline / 52,850, or state that the two path-item-level parameters are counted. |
| 5 | **Low** | `src/sophos_firewall_mcp/client.py:267-295` | `_validate_path` rejects the literal `..` but not percent-encoded traversal: a path containing `%2e%2e` passes validation and httpx sends it verbatim (`raw_path` keeps `%2e%2e`), so an appliance that percent-decodes before routing could escape the `/api/firewall-config/v1` prefix. Paths are module constants in phase 1, so this is hardening, not a live vulnerability — but the client is the public interface #27–#31 consume and issue #25's acceptance criterion is that a caller-supplied path override "is rejected by construction and by test". | `httpx.URL("https://h:4444/api/firewall-config/v1/network/%2e%2e/administration/x").raw_path` → `b'/api/firewall-config/v1/network/%2e%2e/administration/x'` (not normalised). `INVALID_PATHS` in `tests/test_client.py:530-542` covers `..`, `//`, schemes, `?`, `#`, `\`, whitespace and control characters, but not `%2e`. | Reject `%2e`/`%2E` in `_validate_path` (or normalise with `posixpath.normpath` and compare), and add the case to `INVALID_PATHS`. |
| 6 | **Low** | `tests/test_client.py:880-891` | `test_client_reuses_one_pool` asserts `client._client is inner`, which is tautological: nothing in the client ever reassigns `_client`, so the assertion cannot fail. It is a test of implementation shape, not behaviour; the real evidence for "one pool" is `test_transport_configuration`, which captures a single `httpx.AsyncClient` construction. | `client.py:135` assigns `self._client` once in `__init__` and never again; `test_client_reuses_one_pool` stores `inner = client._client` before the calls and compares identity after. | Assert the observable: one `httpx.AsyncClient` constructed across two tool calls (count the factory invocations), or delete the test and rely on `test_transport_configuration`. |
| 7 | **Low** | `.github/workflows/lint.yml:27-31` | CI enforces `flake8` and `mypy` but not `black --check`, although `black` is in `requirements-dev.txt`, in the `[dependency-groups] dev` set and in the phase-1 gate list. A formatting regression would pass every workflow. | `lint.yml` steps are exactly `flake8 src/sophos_firewall_mcp tests scripts` and `mypy src/sophos_firewall_mcp`; `grep -rn "black" .github/workflows/` returns nothing. | Add a `black --check src tests scripts` step. |
| 8 | **Low** | `Dockerfile:14,17`; `pyproject.toml:33-38` | The image still installs the dead `router` extra (`fastembed`, `numpy`) and downloads `BAAI/bge-small-en-v1.5` at build time, for a server whose router was removed in this PR. The PR documents the deferral to #32, so this is not a surprise, but it keeps a large third-party model download and two unused dependency trees in a security-sensitive image. | `Dockerfile:14` `RUN pip install --no-cache-dir ".[router]"`; `Dockerfile:17` `TextEmbedding('BAAI/bge-small-en-v1.5')`; `pyproject.toml:35-38` `router = [fastembed, numpy]`; no `router`/`fastembed` import remains in `src/`. | #32: remove the extra and the build step. |

---

## Verified

Every command was run by me in the reviewed worktree at `f5b3482`; the author's evidence table was not
trusted.

### 1. Quality gates

| Gate | Command | Result |
|---|---|---|
| Tests | `UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync pytest -q` | **277 passed**, 1 warning (`PytestRemovedIn10Warning` from anyio, third-party) |
| Types | `uv run --no-sync mypy src/sophos_firewall_mcp` | **Success: no issues found in 8 source files** |
| Lint | `uv run --no-sync flake8 src/sophos_firewall_mcp tests scripts` | **clean** (no output) |
| Format | `uv run --no-sync black --check src tests scripts` | **16 files would be left unchanged** |
| Coverage drift | `uv run --no-sync python scripts/generate_coverage.py --check` | **`docs/API-COVERAGE.md` is up to date** |
| Lockfile | `uv lock --check` | **Resolved 75 packages**, exit 0 |
| Tree | `git status --short` | clean before the report was written |

`uv.lock` resolves `mcp` **2.3.0**, matching `pyproject.toml`'s `mcp>=2.3.0,<3`.

### 2. Contract baseline (parsed YAML, never by eye)

- SHA-256 `58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5`, 8,934,475 bytes, `openapi 3.0.0`, `info.version 1.0.0`, `info.description` 2,667 chars.
- **384 paths, 700 operations** (GET 263, POST 210, PATCH 134, DELETE 93; 0 PUT/HEAD/OPTIONS/TRACE), **700 unique operationIds** (0 missing, 0 duplicate).
- **132** tags; **76** `$ref` occurrences / **32** unique / 0 external / 0 unresolved; **32** component schemas.
- **4,981** schema-keyword sites = 339 request bodies + 3,926 response media types + 706 parameters (704 operation-level + 2 path-item-level) + 10 response headers; **4,265** media-type schema sites with **162,760** JSON nodes; largest inline schema **1,148** nodes / 373 dict nodes at `updateFirewallRuleIpv4`'s request body. These reproduce the ADR §2.2 figures exactly (finding 4 is the one exception).
- Constructs: `allOf` 2,046, `oneOf` 1,130, `anyOf` 0, `discriminator` 26, `not` 6, `nullable` keyword sites 294 (282 `true`, 12 `false`).
- **83** paginated GETs, and **all 83 declare `page` + `pageSize` + `pageTotal`** — so `get_page`'s unconditional three-parameter query invents nothing. `pageSize` maximum 100 on exactly `getUsers`, `getNetworkUsers`, `getAdministrators`. No `limit`/`offset`/`cursor`.
- **134** PATCH operations, **134/134 `application/json`**, **0** `application/merge-patch+json`.
- **339** operations with a request body = 205 POST + 134 PATCH; **93** DELETEs, **0** with a body (so `delete()` sending no body is contract-accurate); **1** `multipart/form-data` (`importTrustedMacs`, out of scope).
- Status distribution: 401/403/500 on 700; 400 on 636; 200 on 608; 404 on 272; 409 on 217; 201 on 92; 503 on 1.
- **283** path-parameter sites (path-item-level inherited): 248 `sfos-object-name-or-id`, 12 `sfos-object-name-lenient-or-id`, 6 `uuid`, 17 untyped — matches ADR §2.3.
- `pages` is optional in exactly one paginated response: `listNetworkInterfaces` (in scope). `client.get_page` accepts a missing `pages` and still requires `items`.

### 3. Revised scope (145 operations / 152 tools / 11 domains)

| Domain | Ops | Tools | Method mix (verified) |
|---|---|---|---|
| Firewall rules | 12 | 16 | GET 4, POST 4, PATCH 2, DELETE 2 |
| NAT rules | 12 | 12 | GET 4, POST 4, PATCH 2, DELETE 2 |
| Addresses and groups | 37 | 37 | GET 16, POST 7, PATCH 7, DELETE 7 |
| Services and groups | 10 | 10 | GET 4, POST 2, PATCH 2, DELETE 2 |
| Auth users | 6 | 6 | GET 2, POST 2, PATCH 1, DELETE 1 |
| Live users | 2 | 2 | GET 1, POST 1 |
| IPsec VPN | 11 | 11 | **GET 11** |
| SSL VPN | 9 | 9 | **GET 9** |
| Network | 44 | 44 | **GET 41**, POST 1, PATCH 1, DELETE 1 |
| Network status | 2 | 2 | **GET 2** |
| Audit (composite) | 0 | 3 | — |
| **Total** | **145** | **152** | |

- `tool_map` has exactly **145** entries, all present in the spec, all tool names unique and lower
  snake_case, and **all 145 rendered rows carry their tool name** (0 mismatches).
- **555** operations are rendered as `excluded: …` with a reason; 145 + 555 = **700**, so every operation
  appears exactly once and none is silently dropped.
- **7 composite tools**: `firewall_rule_set_enabled_ipv4/ipv6` (1 op, PATCH), `firewall_rule_clone_ipv4/ipv6`
  (2 ops, GET+POST) are **`kind: mutation`**; `audit_firewall_rules` (12 ops), `explain_connectivity`
  (10 ops), `find_object_usage` (8 ops) are **`kind: read`**. Every underlying operationId exists in the
  spec **and** in `tool_map`; none is a mutation inside an audit composite.
- **VPN read-only**: all **20** VPN operationIds (11 IPsec + 9 SSL VPN) are `GET`; 0 non-GET.
- **Network writes**: exactly **3** non-GET operations in the network domain — `createNetworkInterface`
  (POST), `updateNetworkInterface` (PATCH), `deleteNetworkInterface` (DELETE) — and 41 reads.
- **MAC CRUD**: 5 operations `getAllMacAddresses`/`getMacAddressByIdOrName`/`createMacAddress`/
  `updateMacAddressByIdOrName`/`deleteMacAddressByIdOrName` (GET, GET, POST, PATCH, DELETE), all in
  `tool_map`; `bulkDeleteMacAddresses` excluded.
- **Country groups read-only**: exactly 2 operations, both `GET`; `createCountryGroup`,
  `updateCountryGroupByIdOrName`, `deleteCountryGroupByIdOrName` are **not** in `tool_map` and render as
  excluded by `country_group_mutations`.
- **Bulk delete excluded everywhere**: `bulkDeleteFirewallRulesIpv4` renders
  `excluded: Bulk delete excluded from v1…`.
- **WAF excluded**: the four firewall create/update rows carry "accepts ruleType=firewall only; WAF
  variant excluded", and the curated `exclusions` state it.
- Domain mapping spot-checked: `/network/addresses/mac` → `addresses`, `/network/address-groups/country`
  → `addresses`, `/network/dns/protection/status` → `network_status` (before `network`),
  `/network/interfaces/network-interfaces` → `network`, `/routing/gateways/ipv4` → `network`,
  `/sd-wan/routes/ipv4` → `network`, `/authentication/live-users` → `live_users`.
- ADR-001 §10, `API-COVERAGE.md` §4.1 and `coverage_curated.yaml` `release.summary` **agree** on
  145 / 152 / 11; the §4.1 table sums to 145 and 152.

### 4. Coverage generator

- SHA-256 and size are embedded (`generate_coverage.py:37-47`); a changed spec refuses to write
  (`test_sha_guard_refuses_a_modified_spec` asserts exit 2 and no output), and `--accept-sha` on the
  default spec **does** rewrite the constant (`update_embedded_sha`, `:1760`) while a non-default spec
  leaves it untouched — the docstring is accurate.
- Deterministic: no timestamps; `test_deterministic_regeneration` compares two runs byte-for-byte and
  against the committed file; `test_generator_has_no_hardcoded_timestamp` guards it.
- Refuses unknown `tool_map` ids, unknown composite operationIds, composite ids outside `tool_map`,
  duplicate composite names, name collisions, unknown composite `kind`, and duplicate/missing rendered
  rows; asserts every domain has operations or composites and every operation belongs to exactly one
  domain.
- `--check` is byte comparison and is exercised in CI through `tests/test_coverage.py::test_check_mode_reports_no_drift`.

### 5. Security invariants (checked against code, not docs)

| Invariant | Evidence |
|---|---|
| TLS verified by default | `config.py:171` `verify_ssl: bool = True`; `.env.example` `SOPHOS_VERIFY_SSL=true`; `docker-compose.yml` default `true`; `test_transport_configuration` asserts `captured["verify"] is True` |
| `verify=false` lab-only and documented | `.env.example` "Set to false ONLY for a lab appliance"; `SOPHOS_CA_BUNDLE` preferred; `_check_tls_combination` forbids CA bundle + verification off |
| API key out of logs/errors/tool output | `SecretStr` (`config.py:169`); `_summarize` drops Pydantic `input` (`:96-106`); `from None` (`:314`); `client._scrub` (`:399-403`); `tool_error` builds only from type/status/path/error_code; `AppContext`/`Settings`/client `repr` safe; three redaction tests plus `test_repr_and_serialization_never_contain_the_key` and `test_validation_errors_never_contain_the_key` |
| No cross-origin Bearer forwarding | `follow_redirects=False` (`client.py:143`), `test_cross_origin_redirect_is_not_followed` asserts the evil origin is never called |
| No model-controlled URL/path/headers | `_validate_path` (`client.py:267-295`) rejects schemes, `//`, `..`, `\`, `?`, `#`, whitespace and control chars before I/O; `_send` builds `base_url + path`; no tool takes a path; `test_invalid_path_is_rejected_before_io` covers 12 paths × 4 methods with `call_count == 0` |
| Sanitized errors, no raw remote bodies | `_extract_error_code` discards `message` and the raw body; `_describe_exception` truncates to 200 chars; `tool_error`/`_sanitize` bound to 300 chars and drop `<`/`>` and control characters |
| No secrets in CI/artifacts | no secret in workflows, Dockerfile, compose or `.env.example`; the lab key in `LAB-ACCESS.md` is pre-existing on `main` (see residual risks) |
| `SOPHOS_READ_ONLY_MODE` does not register mutations | `tools/__init__.py:216-221` returns a no-op decorator for `ToolKind.MUTATION` when `read_only`; `server.py:105,136-137` resolves the flag before registration; `test_read_only_mode_does_not_register_mutation_tools` asserts the tool list is exactly the read tool |

### 6. MCP invariants

| Invariant | Evidence |
|---|---|
| `Context[AppContext]` injected, out of the input schema | `test_input_schema_is_closed_and_excludes_the_context_parameter` asserts `set(schema["properties"]) == {"request"}` and `additionalProperties is False` |
| One client per process, created in the lifespan, closed in `finally` | `server.py:107-128`; `test_lifespan_closes_the_client_exactly_once_on_normal_shutdown` and `…on_exceptional_shutdown` |
| `ToolError` for anticipated, `MCPError` for protocol, unexpected to the SDK | `test_tool_error_reaches_the_model`, `test_protocol_error_propagates_as_mcp_error`, `test_unexpected_exception_does_not_leak_details`, `test_crashes_are_reported_as_unexpected_tool_errors` |
| No `BaseException`; cancellation propagates | no `except BaseException` and no bare `except` anywhere in `src/` (the single `BaseException` occurrence is the `_describe_exception` type annotation at `client.py:91`); `test_cancellation_propagates_instead_of_becoming_an_error` |
| `structuredContent`/`content` not hand-duplicated; object-rooted output | `test_structured_output_is_published_on_both_channels`, `test_output_schema_is_object_rooted_and_typed`, `test_invalid_structured_output_is_a_generic_error` |
| Annotations per tool, `openWorldHint` justified | `_build_annotations` rejects write hints on read tools and requires both write hints on mutations; `test_tool_annotations_use_the_wire_names_and_expected_values` asserts the exact wire values |
| STDIO: stdout protocol only, logs to stderr, no TTY | `main()` uses `logging.basicConfig(stream=sys.stderr)`; `test_stdio_keeps_stdout_clean_when_configuration_is_invalid` asserts `stdout == ""` and exit 2; `test_stdio_transport_works_with_the_official_client` negotiates `2026-07-28` and lists zero tools; `docker-compose.yml` no longer sets `tty` |
| `subscriptions=False` with a static catalog | `server.py:134`; `test_create_server_builds_the_stdio_server` asserts `get_request_handler("subscriptions/listen") is None` (the one deliberate, documented private-SDK access) |
| No XML/raw REST/router tool advertised | `test_no_legacy_raw_rest_xml_or_router_tools_are_advertised`; `DEFAULT_DOMAINS == ()` |
| Pagination cannot silently truncate | `get_page` requires `items`, preserves `pages` when present, validates `page >= 1` and `1 <= pageSize <= 100` before I/O |

### 7. Tests, error cases and hygiene

- Error coverage: 400/401/403/404/409 mapping, 204/empty body, malformed JSON on success and on error,
  HTML 404, plain-text 405, unexpected 2xx, connect/read/write timeout, TLS error, DNS error, connection
  loss — all present and asserted on the wire request.
- Write safety: `test_write_timeout_is_ambiguous_and_never_retried` and
  `test_write_connection_loss_is_ambiguous_and_never_retried` assert **one** request was sent.
- Read retries: bounded at 2 attempts, only for connect/read timeout and 502/503/504; not for 400/401/
  403/404/409; jittered backoff is patched out, so no test sleeps on the network.
- No order/time/network fragility observed: 277 tests in 30.3 s, no live appliance contact.
- Git hygiene: 19 commits with scoped prefixes, no `add -A` artefacts, no branch switching, no
  hand-edited generated file (`--check` is byte-identical), no changes outside the phase-1 scope.
- No critical `TODO` without an issue: the two documented deferrals (router extra/Dockerfile, full
  lockfile CI) point at #32.

---

## Not verified

- **VLAN-only enforcement in code.** Phase 1 registers no domain tools (`DEFAULT_DOMAINS == ()`), so
  there is no `network_interface_*_vlan` implementation to inspect. The decision is only specified
  (finding 1 shows the specification's rationale is wrong). Enforcement must be re-reviewed in #31.
- **Mutation composites excluded in read-only mode.** The four firewall composites exist only in
  `coverage_curated.yaml`/`API-COVERAGE.md`; no code registers them. `register_tool` filters
  `ToolKind.MUTATION` correctly and is tested, but nothing links the curated `kind` to the code, so a
  phase-2 composite registered as `READ` would bypass the filter. Re-review in #27.
- **Firmware behaviour.** No write was attempted (the lab key is read-only) and the SFOS build is still
  unknown. Mocks prove contract shape, not appliance behaviour. Unverified in particular: PATCH merge
  semantics over arrays, 409 conflict shape, whether the appliance rejects a `type` change on a non-VLAN
  interface, and whether it accepts an explicit `pageTotal=false`.
- **Live test module.** The `live` marker is registered and `docs/live-evidence/README.md` documents the
  protocol, but no `pytest -m live` module exists yet; the deferral is explicit and owned by #27–#32.
- **CI execution.** I read `.github/workflows/` but did not run the workflows. `test.yml` runs only
  `pytest`; `lint.yml` runs `flake8` + `mypy`; `black` is not enforced (finding 7).
- **Docker image build.** Not executed; the Dockerfile still installs the `router` extra and downloads
  the FastEmbed model (finding 8).
- **`Settings` mutual exclusion on direct construction.** `Settings(...)` does not re-check that exactly
  one key source is set; `from_env` is the enforced production path and the empty-key case is now
  rejected on both paths. Acknowledged in the PR.
- **MCP Inspector.** Not available in this environment; the official SDK `Client` was used for the
  in-process and subprocess STDIO tests.

---

## Residual risks

- **Read-only mode is a convention, not a structural boundary.** A domain module can bypass
  `register_tool` and call `server.add_tool` directly; nothing prevents it. The guarantee depends on
  #27–#35 using the documented contract. A phase-2 review should assert the registered tool set per
  domain against `coverage_curated.yaml`.
- **`_scrub` is literal.** It replaces the exact key string only; a transformed or encoded key echoed by
  the appliance would not be redacted. The key is never placed in a message by construction, so this is
  defence in depth.
- **Ambiguous-write classification is conservative to a fault.** A `ConnectTimeout`/`ConnectError` on a
  POST is reported as `SophosAmbiguousWriteError` although the request was never sent, forcing an
  unnecessary reconciliation read. Safe direction, but it will produce false "may have been applied"
  messages.
- **`LAB-ACCESS.md` carries a plaintext lab API key on `main`** (owner decision, read-only profile,
  pre-existing and not introduced by this PR). It remains a secret in the repository; the
  `.env.example`/`SOPHOS_API_KEY_FILE` path is the right pattern for real deployments.
- **`requirements.txt` duplicates the `pyproject.toml` dependency set** and is hand-maintained; it is
  consistent today but can drift until #32 makes the lock canonical.
- **The `router` extra and the FastEmbed model download stay in the image** (finding 8) — an unnecessary
  supply-chain and build-reliability surface until #32.
- **Firmware compatibility remains unproven**, and the contract is `openapi 3.0.0` version 1.0.0 while
  the portal may evolve independently. The SHA gate protects the checked-in file, not the appliance.
