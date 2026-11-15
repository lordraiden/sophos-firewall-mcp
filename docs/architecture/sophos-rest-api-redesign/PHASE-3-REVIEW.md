# Independent review — Phase 3 (hardening and release)

| Field | Value |
|---|---|
| **Reviewer** | `reviewer3` (independent; did not write the code) |
| **Date** | 2026-11-15 |
| **Branch** | `migration/phase-3-hardening-release` |
| **Reviewed HEAD** | `6b981bf` — *docs: record the phase-3 live results and the input-naming limitation* |
| **Base** | `origin/main` |
| **Diff** | 27 files, +2,699 / −1,028, 11 commits |
| **PR** | [#38](https://github.com/lordraiden/sophos-firewall-mcp/pull/38) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](./execution/04-REVIEW-PROTOCOL.md) |
| **Inputs** | full diff; PR description; issue #32 body and its 15 Nov pre-release comment; the 15 Nov scope comment on #24; `PLAN.md`; `INDEPENDENT_REVIEW_REPORT.md`; `REFERENCES.md`; `ADR-001` (all of it, §10 in particular); `docs/API-COVERAGE.md`; `scripts/coverage_curated.yaml`; `scripts/generate_coverage.py`; `firewall_config_openapi.yaml` parsed with Python; the test suite; `.github/workflows/`; `Dockerfile`; `docker-compose.yml`; `entrypoint.sh`; `README.md`; `.env.example`; `CHANGELOG.md`; `docs/live-evidence/`; `docs/release/`; the phase-1 and phase-2 reviews (context only) |

---

## Verdict

**CHANGES REQUIRED** — **1 Critical**, **2 High**, **3 Medium**, **7 Low**.

The code side of phase 3 is in good shape and I could not break it. The two live deviations are
narrow, output-model-only and regression-tested; the MCP surface is exactly 152 tools (98 read-only,
54 mutations) through the official SDK v2 `Client`; STDIO negotiates 2026-07-28 by default and still
works with `mode="legacy"`; stdout carries only the protocol; the REST client is hardened (SecretStr,
TLS on by default, no redirects, no inherited proxy, explicit timeouts, idempotent close, sanitized
errors); `pytest`, `mypy`, `flake8`, `black`, `generate_coverage.py --check` and `uv lock --check` are
green when I run them; `pip-audit` on the locked runtime export reports no known vulnerabilities and
`semgrep` reports 0 findings.

The blocking problems are not in the code. They are in the **release pack and the CI claims**:

1. a **live Sophos Firewall API key is committed in clear text in a public repository**, and the PR
   states the wrong precondition for rotating it ("before making the repository public" — it already
   is);
2. the **`Security` workflow is disabled and has never run**, so `pip-audit` and `semgrep` are not CI
   gates, contrary to the PR's evidence table and the release checklist;
3. the **`Publish Docker image` workflow is disabled and has never run**, so the gate-B procedure
   ("the `v0.4.0` tag push triggers the publish workflow") cannot publish anything as written.

Findings 1–3 must be resolved before integration and publication. Findings 4–6 are cheap, concrete
fixes that close explicit requirements from issue #32. The Low findings are documentation and
test-quality defects.

---

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | **Critical** | `docs/architecture/sophos-rest-api-redesign/LAB-ACCESS.md:26,27,37` | A live Sophos Firewall API key is committed in clear text in a **public** repository. The PR's residual-risk note says "rotate before making the repository public", but the repository is already public, so the exposure is current. | `gh api repos/lordraiden/sophos-firewall-mcp --jq .visibility` → `public`; `git show origin/main:docs/architecture/sophos-rest-api-redesign/LAB-ACCESS.md` contains `sfos_9a506adf_…` three times; an unauthenticated `curl https://raw.githubusercontent.com/lordraiden/sophos-firewall-mcp/main/docs/architecture/sophos-rest-api-redesign/LAB-ACCESS.md` returns **HTTP 200**. The key was used successfully against `10.10.10.1:443` on 2026-11-15 (`docs/live-evidence/phase-3-live-matrix.md` §1) and is recorded as "not rotated after the run". | Rotate the key on the appliance **now**, replace the value in `LAB-ACCESS.md` with a placeholder, purge it from history (or record the accepted history exposure explicitly), and record the rotation in #32. Blocks integration and publication. |
| 2 | **High** | `.github/workflows/security.yml:1` | The `Security` workflow is disabled (`disabled_fork`) and has **never run**, so `pip-audit` and `semgrep` are not CI gates. The PR's evidence table ("Dependencies … no known vulnerabilities", "Static analysis … 0 findings") and release checklist §3.1 ("CI green … `pip-audit` against the lock, semgrep") describe local runs, not CI. | `gh api repos/lordraiden/sophos-firewall-mcp/actions/workflows` → `Security | disabled_fork`; `…/workflows/security.yml/runs` → `total_count: 0`; the check-runs for `6b981bf` list only Tests (3.11–3.14), Lint and Docker build. The scans themselves are clean when I run them (see Verified). | `gh workflow enable security.yml`; add "Security workflow enabled and green" to release checklist §3.1; attach the run to the PR. |
| 3 | **High** | `.github/workflows/docker-publish.yml:1` | The `Publish Docker image` workflow is disabled (`disabled_manually`) and has never run, but release checklist §3.3 asserts "The `v0.4.0` tag push triggers the publish workflow, which builds and pushes the stable tags". Following gate B as written publishes nothing. | `gh api …/actions/workflows` → `Publish Docker image | disabled_manually`; `…/docker-publish.yml/runs` → `total_count: 0`. | Add "re-enable the Publish Docker image workflow" to §3.1 preconditions (or re-enable it now) and correct §3.3 to state the precondition. |
| 4 | Medium | `.github/workflows/live.yml:52-69` | The opt-in live workflow can pass with **zero** live tests. The precondition check omits `SOPHOS_PORT`, and the run step does not assert that any test ran; a missing `SOPHOS_PORT` secret makes `_LIVE_READY` false, every test skips, and the job is green. | `tests/live/conftest.py:38-42` requires `SOPHOS_HOST`, `SOPHOS_PORT` and a key; `live.yml:52-58` checks only `SOPHOS_HOST` and `SOPHOS_API_KEY`; `live.yml:69` runs `pytest -m live -q tests/live/` with no count assertion. | Add `SOPHOS_PORT` to the precondition check and assert a minimum passed count (parse the summary or use `--junitxml`). |
| 5 | Medium | `.github/workflows/` (all) | No CI job runs `scripts/generate_coverage.py --check`, although issue #32 §5 requires comparing the generated operation count/IDs and the spec SHA **in CI** "so a spec replacement cannot silently invalidate coverage decisions". | `grep -rn coverage .github/workflows/` → no match. The generator's SHA gate (`scripts/generate_coverage.py`) is exercised only locally. | Add `uv run --no-sync python scripts/generate_coverage.py --check` to `lint.yml` (or `test.yml`). |
| 6 | Medium | `docs/release/RELEASE-0.4.0.md:101-105`, `README.md:310-313` | Pre-release item 1 of the owner's 15 Nov comment on #32 ("Unify the published MCP input naming convention … Add a surface test that asserts one convention") is not implemented. The deferral to 0.5.0 is recorded only in the PR body; #32 still says the item is "required before the release". | `gh issue view 32 --comments`; no test asserts a single convention (`grep -rn "snake_case\|convention" tests/` → only a tool-name regex test); measured 75 tools with a camelCase input property, 65 without, 12 parameterless. | Record the owner's deferral decision in #32 (and reference it from the release notes), or implement the unification plus the surface test before publication. |
| 7 | Low | `docs/API-COVERAGE.md:277` | The generated "Live evidence" line is a single markdown link whose label **and** target are a comma-joined pair of paths, so the link is broken. | `scripts/coverage_curated.yaml:781` sets `live_evidence` to `"docs/live-evidence/api-smoke-2026-11-15.md, docs/live-evidence/phase-3-live-matrix.md"`; `scripts/generate_coverage.py:1503-1506` wraps the whole string in one `[…](…)`. | Make `live_evidence` a single path, or teach the generator to accept a list and emit one link per entry. |
| 8 | Low | `tests/test_mcp_e2e.py:359-375` | The cancellation test is tautological with respect to the checklist item "No `BaseException`; cancellation propagates": it cancels the client-side task and asserts `await task` raises `CancelledError`, which asyncio guarantees once `task.cancel()` is called, and it never observes the server handler. | The test body cancels `client.call_tool(…)` and awaits it; no server-side signal is asserted. The server-side property is only established by inspection (`grep -rn "except BaseException" src/` → none). | Assert on the server side (a handler that records `CancelledError`) or rename the test to what it actually proves. |
| 9 | Low | `tests/test_mcp_e2e.py:10` | The module docstring claims "`structured_content` validates against the published schema", but no test validates `structured_content` against `tool.output_schema`; the test only checks one field. | `grep -rn "jsonschema" tests/` → no match; `test_a_read_tool_returns_structured_content_matching_its_schema` asserts `structured_content["items"][0]["name"]`. | Validate with `jsonschema` against `tool.output_schema`, or correct the docstring. |
| 10 | Low | `docs/live-evidence/phase-3-live-matrix.md:224` | The firewall row counts "8 mutations" (operations) while the total row says 54 mutation tools; the "Contract-tested only" column sums to 50, not 54. The 4 firewall composite mutation tools are named in the parenthetical but not counted. | Column sum: 8+8+21+6+3+1+0+0+3+0+0 = 50; the total row says 54; firewall has 12 mutation tools (8 operations + 4 composites). | Change the firewall row to 12 mutations, or state that the column counts operations. |
| 11 | Low | `README.md:293` | "No example in this repository disables verification" is contradicted by two lab runbook commands that set `SOPHOS_VERIFY_SSL=false`. | `docs/live-evidence/README.md:79`, `docs/live-evidence/phase-3-live-matrix.md:33`. | Qualify the sentence ("no client-configuration example …; the lab runbook uses it only for the self-signed lab appliance"). |
| 12 | Low | `README.md:310-313`, `docs/release/RELEASE-0.4.0.md:101-105` | The documented "79 wire / 61 snake / 12 parameterless" split is not reproducible from the published input schemas. | Measured through the SDK `Client`: 75 tools with at least one camelCase input property, 65 with none, 12 with no parameters (152 total). | State the counting method or correct the numbers. |
| 13 | Low | `docs/release/RELEASE-0.4.0.md:274` | §3.4 instructs "Record the current `latest` digest first", but no `latest` tag exists for the first release, so the command fails. | `git tag -l` → 0 tags; `gh release list` → empty; the publish workflow has never run. | Make the step conditional ("if a `latest` tag exists") or record the absence explicitly. |

---

## Verified

Everything below was run or parsed by me in this worktree; I did not take the author's numbers on
trust.

**Contract and scope**

- Parsed `firewall_config_openapi.yaml` with Python: 384 paths, 700 operations (GET 263, POST 210,
  PATCH 134, DELETE 93), 134 PATCH operations all `application/json` and **0**
  `application/merge-patch+json`, 83 GET operations declaring `page`/`pageSize`. SHA-256
  `58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5` and size 8,934,475 bytes match
  `docs/API-COVERAGE.md` §1.
- All 145 operationIds in ADR-001 §10 exist in the parsed YAML; the 3 audit composites' and 4
  firewall composites' underlying operationIds all exist and are in `tool_map`.
- All 98 operationIds **and** method+path pairs in `docs/live-evidence/phase-3-live-matrix.md` §2 match
  the YAML exactly (checked programmatically, 0 mismatches).
- Scope counts agree across ADR-001 §10, `docs/API-COVERAGE.md` §4.1 and the code: **145 operations /
  152 tools / 11 domains**. The 152-tool surface is confirmed through the SDK `Client`: 152 tools, 98
  read-only, 54 mutations; `SOPHOS_READ_ONLY_MODE=true` publishes 98 tools and 0 mutations.
- Domain decisions hold: VPN read-only (11 IPsec + 9 SSL = 20 operationIds), WAF excluded (clone
  refuses `ruleType: waf`), bulk delete absent, country groups read-only, MAC CRUD present, VLAN-only
  interface writes pre-read the interface and refuse any non-`vlan` type, the four firewall composites
  are `ToolKind.MUTATION` and are not registered in read-only mode, `disconnectLiveUser` requires
  `message` (1–600), login/logout are not registered, no raw REST/XML/router/prompts/resources code
  remains in `src/`.
- Pagination is only used where declared: DHCP servers/relays use an unpaginated `collection()` and
  DHCP leases use `keyset()`; no client-side cursors or auto-pagination.

**Gates (run by me)**

| Gate | Command | Result |
|---|---|---|
| Tests | `uv run --no-sync pytest -q` | **962 passed, 100 skipped** (139.8 s) |
| Types | `uv run --no-sync mypy src/sophos_firewall_mcp` | clean, 26 files |
| Lint | `uv run --no-sync flake8 src/sophos_firewall_mcp tests scripts` | clean |
| Format | `uv run --no-sync black --check src tests scripts` | 50 files unchanged |
| Coverage drift | `uv run --no-sync python scripts/generate_coverage.py --check` | up to date |
| Lock | `uv lock --check` | resolves 55 packages |
| Dependency audit | `uvx pip-audit -r <uv export --locked --no-dev>` | **No known vulnerabilities found** |
| SAST | `uvx --from semgrep==1.185.0 semgrep --config=p/python --config=p/security-audit --error src/sophos_firewall_mcp` | **0 findings**, 200 rules, 26 files |
| Pre-fix audit | `pip-audit` on `certifi==2026.7.22 cryptography==49.0.0 pyjwt==2.13.0` | **19 advisories in 3 packages**, exactly the IDs in `CHANGELOG.md` (PYSEC-2026-4320, PYSEC-2026-3552, PYSEC-2026-4140…4152/4183, GHSA-pxh4-856f-4h89) |

**MCP end-to-end**

- `tests/test_mcp_e2e.py`: 19 tests, all pass through the official SDK v2 `Client`.
- Discovery: 152 tools, unique names, every tool has a title and a description ≥ 20 chars; every input
  schema is an object rooted at `request` with `additionalProperties: false` (or a closed `oneOf`
  variant); every output schema is object-rooted with properties; every tool declares
  `openWorldHint=true`; read-only tools never declare write hints.
- Structured output: `structured_content` is a dict and the text channel carries the same projection.
- Errors: 401 → sanitized `ToolError` that does not contain the key; malformed payload → sanitized
  `ToolError` that names the field and does not echo the payload; invalid argument rejected before any
  I/O (`route.call_count == 0`); unknown tool → `isError`; unknown JSON-RPC method → `-32601`.
- STDIO: `client.protocol_version == "2026-07-28"` by default; `mode="legacy"` still lists 152 tools;
  a hand-driven subprocess proves every stdout line is JSON-RPC, stdin/stdout are not TTYs, stderr
  carries the startup log, and EOF on stdin exits 0; a missing configuration exits 2 with empty stdout
  and one actionable stderr line.
- Lifespan: one client created, closed exactly once on normal and exceptional shutdown
  (`tests/test_server.py:346,359`); no `except BaseException` anywhere in `src/`.

**Live evidence**

- Counted the matrix programmatically: 98 rows, **74 PASS / 24 SKIP / 0 FAIL**, matching the claim.
- Read-only by construction: `tests/live/conftest.py` forces `read_only_mode=True` and
  `assert_read_only_surface` asserts 98 tools and `read_only_hint is True` before any call; the module
  sends only GETs.
- The two tolerated deviations are **output-model only**: `Ipv4AddressIpList`/`Ipv6AddressIpList` drop
  `min_length` while `Ipv4AddressCreateIpList`/`Ipv6AddressCreateIpList`/`Ipv4AddressUpdateInput` keep
  `min_length=1` (`src/sophos_firewall_mcp/models/objects.py:251-340,392-485`); `DnsSettings.updatedAt`
  maps only `""` to `None` and still rejects `"not-a-date-time"`
  (`src/sophos_firewall_mcp/models/network.py:1167-1189`). `tests/test_live_deviations.py` (10 tests)
  proves both the relaxation and that a genuinely malformed payload still raises the sanitized
  `ToolError`.
- The record has date, endpoint, profile, per-tool operationIds and PASS/FAIL/SKIP, plus a deferral
  table with reasons — the format `docs/live-evidence/README.md` requires.

**Security**

- Key flow: `SecretStr`, exactly one of `SOPHOS_API_KEY`/`SOPHOS_API_KEY_FILE`, mounted secret file,
  `_scrub` redaction in exception messages, `repr` never shows the key, `_summarize` strips Pydantic
  inputs.
- TLS on by default; `SOPHOS_CA_BUNDLE` implies verification; no `verify=false` in any
  client-configuration example (the only occurrences are the two lab runbooks — finding 11).
- `follow_redirects=False` (no redirect is followed at all), `trust_env=False` (no inherited proxy),
  explicit `httpx.Timeout`, idempotent `aclose` in the lifespan `finally`.
- Path validation rejects schemes, `//`, `..`, `%2e`, `?`, `#`, backslashes and control characters, so
  no model-controlled URL/path/header.
- Sanitized `ToolError`; raw remote bodies are never returned; error codes are pattern-filtered and
  bounded.
- No secret in the new artifacts: the only key in the tree is the pre-existing `LAB-ACCESS.md` one
  (finding 1); the test key is a fake.

**CI and container**

- `test.yml`/`lint.yml`/`live.yml` use `astral-sh/setup-uv` + `uv sync --locked`; the matrix is
  3.11–3.14 and **all four jobs are green on the PR** (`gh pr checks 38`).
- `security.yml` audits the locked runtime export (`uv export --locked --no-dev`) with `--strict` and
  runs semgrep from a pinned image with pinned packs — but the workflow is disabled (finding 2).
- `docker-build.yml` builds on PR without pushing, asserts uid 10001, runs STDIO discovery with
  `--network none` and no TTY (expects 152 tools), and asserts no `xmltodict`/`fastembed`/`numpy`; the
  job **passed** on the PR.
- `live.yml` is `workflow_dispatch` only, uses the `live-lab` environment, forces read-only mode and
  defaults `SOPHOS_VERIFY_SSL` to `true`.
- `docker-publish.yml` publishes only `main` + `sha-*` on a main push; semver and `latest` only from a
  `v*` tag in the `release` environment — but the workflow is disabled (finding 3).
- Every action version used exists (`actions/checkout@v7`, `astral-sh/setup-uv@v7`,
  `docker/build-push-action@v7`, `docker/login-action@v4`, `docker/metadata-action@v6`,
  `docker/setup-buildx-action@v3`), the `semgrep/semgrep:1.185.0` tag exists, and `uv:0.13.8` matches
  the local uv.
- Container (static inspection; Docker is not installed here): REST-only, no `.[router]`, no FastEmbed,
  no curl, `uv sync --locked --no-dev`, non-root uid 10001, `ENTRYPOINT` → `exec` so the server is PID 1
  and receives signals, no TTY, no HTTP port. Compose uses a secret file, `tty: false`,
  `read_only: true`, `cap_drop: ALL`, `no-new-privileges`.

**Docs and git**

- README, `.env.example` and `CHANGELOG.md` are REST-only and consistent; version **0.4.0** in
  `pyproject.toml` and `uv.lock`; GHCR namespace `ghcr.io/lordraiden/sophos-firewall-mcp` matches
  `github.repository`.
- No git tag and no GitHub release exist, consistent with "gate B prepared, not executed".
- The rollback commit `e6c9e1f` is the parent of the XML-removal commit `3ed5f2f`, is version 0.3.1,
  still carries `xmltodict`, and its Dockerfile is buildable — the rollback plan is accurate.
- 11 commits, each scoped to its stated paths (max 9 files); no out-of-scope change; the
  `requirements*.txt` removal is in scope (issue #32 §5). No `TODO`/`FIXME` in `src/`, `tests/`,
  `scripts/`.

---

## Not verified

- **Docker build and run.** Docker is not installed on this host, so the image is verified only by the
  CI job (which passed) and by static inspection of the Dockerfile, compose file and entrypoint.
- **Absence of a GHCR image.** The registry returns 401 unauthenticated; I could not confirm that no
  image exists. No tag and no GitHub release exist, which is consistent with the release pack.
- **Firmware build, appliance model and API allowlist source.** Not exposed by the API; the evidence
  records them as unknown and makes no firmware claim.
- **All 54 mutation tools against a real appliance.** The lab key is read-only; PATCH merge semantics,
  ambiguous-write reconciliation and 403 denial remain unverified.
- **The 24 live SKIPs.** The appliance holds no object of those kinds, so those get-by-id paths are
  unexercised.
- **The `Security` workflow's behaviour in CI.** It has never run (finding 2); I reproduced its two
  commands locally instead.
- **The exact fix-version mapping of the 19 advisories.** The count and IDs reproduce exactly, but the
  "fix versions" are pip-audit's data, not the project's.

---

## Residual risks

- **The lab API key is valid and public until it is rotated** (finding 1). The read-only profile limits
  the blast radius to disclosure of the appliance configuration (rules, NAT, users, VPN, interfaces),
  which is still sensitive.
- **No write validation.** Every mutation is contract-tested against mocked HTTP only; a real
  appliance may reject or reinterpret a payload.
- **Firmware compatibility is unknown and not claimed.** The results apply to one appliance on
  2026-11-15.
- **24 live SKIPs** mean several get-by-id paths have never been exercised against a real appliance.
- **The container is verified in CI only.** A local build is not part of the evidence.
- **The input-naming inconsistency is deferred to 0.5.0** as a breaking change; callers that hard-code
  parameter names will break twice.
- **The two output-model deviations are a deliberate divergence from the contract.** If a future
  contract revision restores `minItems: 1`, the model will not notice; the deviation is documented but
  not machine-checked against the YAML.
- **`uvx pip-audit` is unpinned** in `security.yml`, so a new pip-audit release can change the gate
  without a reviewed bump (semgrep is pinned by image).
- **The `Security` and `Publish Docker image` workflows are disabled at the repository level.** A file
  change cannot fix that; it needs an owner action, and it will silently regress if the repository is
  transferred or forked again.

---

## Re-check after fixes

**Re-checked HEAD:** `8d1f002` — three commits on top of the reviewed `6b981bf` (`3cec372`,
`1460191`, `8d1f002`). **Scope:** focused re-check of the 13 findings, not a second full review. The
verdict and findings above are kept exactly as issued.

### Status of the original findings

| # | Severity | Status | Evidence |
|---|---|---|---|
| 1 | Critical | **Partially closed — publication still blocked** | The full key is gone from the working tree (`grep -rn "sfos_9a506adf_"` → no match outside `.git`), replaced by `<REDACTED — ask the owner>` at `LAB-ACCESS.md:32,33,43`, and the new notice at `LAB-ACCESS.md:3-8` is accurate: it states the value was removed from the working tree, remains in git history (`cb8dbe3`) and that **rotation, not deletion, is the remediation**. The key is still valid until the owner rotates it, so the exposure is not remediated. |
| 2 | High | **Closed** | `gh workflow list --all` → `Security active`; the workflow now runs on the PR and both jobs are green on `8d1f002`: `Dependency audit (locked resolution)` pass (17 s) and `SAST (Semgrep)` pass (39 s). |
| 3 | High | **Partially closed** | `gh workflow list --all` → `Publish Docker image active`. But `docker-publish.yml` triggers only on `push` (`main`, `v*`) and has no `pull_request` trigger, so a PR run does **not** exercise it (`…/docker-publish.yml/runs` → `total_count: 0`). It is first exercised by the merge to `main` (development job) or the `v*` tag (release job); the release checklist should say so. |
| 4 | Medium | **Closed** | `live.yml:55-79` now requires `SOPHOS_HOST`, `SOPHOS_PORT` and one of `SOPHOS_API_KEY`/`SOPHOS_API_KEY_FILE`; `live.yml:91-121` parses `--junitxml` and fails on zero collected tests or zero executed tests. I simulated the gate with three fixtures: normal → OK, all-skipped → FAIL, zero-tests → FAIL. |
| 5 | Medium | **Closed** | `lint.yml:45-47` adds a `Coverage drift` step running `generate_coverage.py --check`; the check is green. |
| 6 | Medium | **Closed** | The new comment on #32 ("Phase-3 review outcome and owner decisions, 15 Nov 2026") records the review outcome, the owner decision to publish 0.4.0 with the inconsistency documented and unify in 0.5.0, and the measured split. |
| 7 | Low | **Closed** | `scripts/generate_coverage.py:1504-1511` splits `live_evidence` on commas and emits one link per path; `docs/API-COVERAGE.md:277` now renders two separate, valid links. |
| 8 | Low | **Closed** | `tests/test_mcp_e2e.py:379-416` adds a synthetic tool that records `CancelledError` and the test waits for that server-side signal, so a server that swallowed the cancellation now fails instead of passing. Falsifiable. |
| 9 | Low | **Closed** | The docstring no longer claims JSON-Schema validation; `tests/test_mcp_e2e.py:248-249` asserts required ⊆ `structured_content` ⊆ declared properties, plus the item-level equivalent. |
| 10 | Low | **Closed** | `docs/live-evidence/phase-3-live-matrix.md:222-227` states the counting method and the firewall row now reads 12 mutations; the column sums to 54 (12+8+21+6+3+1+0+0+3+0+0). |
| 11 | Low | **Still open** | `README.md:293` is unchanged: "No example in this repository disables verification", while `docs/live-evidence/README.md:79` and `docs/live-evidence/phase-3-live-matrix.md:33` still set `SOPHOS_VERIFY_SSL=false`. |
| 12 | Low | **Still open** | The numbers changed to 74/55/5/6/12 but are still not reproducible. Measured through the SDK `Client` on the published schemas (resolving `$ref` and `oneOf`): **75** camelCase-only, **57** snake_case-only, **3** mixed, **8** single-word-only, **9** no-parameter (8 tools with no `request` property + 1 empty `request` model) = 152. The "12 parameterless" figure also contradicts the e2e test's own "eight operations declare no parameters". |
| 13 | Low | **Still open** | `docs/release/RELEASE-0.4.0.md:274` is unchanged: "Record the current `latest` digest first", although no `latest` tag exists for the first release. |

### Gates re-run on `8d1f002`

| Gate | Command | Result |
|---|---|---|
| Tests | `uv run --no-sync pytest -q` | **962 passed, 100 skipped** (138.4 s) |
| Types | `uv run --no-sync mypy src/sophos_firewall_mcp` | clean, 26 files |
| Lint | `uv run --no-sync flake8 src/sophos_firewall_mcp tests scripts` | clean |
| Format | `uv run --no-sync black --check src tests scripts` | 50 files unchanged |
| Coverage drift | `uv run --no-sync python scripts/generate_coverage.py --check` | up to date |
| Lock | `uv lock --check` | resolves 55 packages |
| CI on the PR | `gh pr checks 38` | Tests 3.11–3.14, Lint, Docker build, **Dependency audit**, **SAST (Semgrep)** all pass |

### New findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| N1 | Low | `docs/architecture/sophos-rest-api-redesign/LAB-ACCESS.md:11,93,96` | The key was removed but the file now contradicts itself: line 11 ("la credencial se registra en claro en este repositorio") and line 93 ("Esta credencial está en claro en el repositorio") still assert the credential is in clear, and line 96 still says the owner "rotará la clave al terminar las pruebas" instead of "must rotate now". | The new notice at lines 3-8 says the value was removed; the three later statements were not updated. | Rewrite lines 11, 93 and 96 to match the notice: the credential is **not** in the repository, it must be rotated immediately, and the placeholder is the only value that may be committed. |

### Re-check verdict

**CHANGES REQUIRED stands, but the blocking set is now small and mostly operational.**

- Findings **2, 4, 5, 6, 7, 8, 9, 10 are closed** and verified (finding 2 is now proven in CI, not just
  locally).
- Finding **1 is only partially closed**: the working tree is clean and the notice is accurate, but the
  key remains in history and valid, so **publication stays blocked until the owner confirms rotation**.
  That is an owner action, not a code change.
- Finding **3 is partially closed**: the workflow is enabled, but it cannot be exercised by a PR; it
  will first run on the merge to `main` or on the `v*` tag. The release checklist should state that.
- Findings **11, 12, 13 are still open** — all Low, all documentation-only, and none of them blocks
  integration. They should be closed before the release notes are published, because they are factual
  claims in user-facing documents.
- New finding **N1** (Low) is a self-contradiction introduced by the key removal; it should be fixed in
  the same pass as the rotation.

No new Critical or High finding was introduced by the fixes. The code, the tests, the CI pipeline and
the container are unchanged in substance and remain green.

---

## Final confirmation

Re-checked `8cddb8e` (docs-only: `README.md`, `LAB-ACCESS.md`, `RELEASE-0.4.0.md`). **#11 is closed** —
`README.md:293-295` now reads "No example in this README disables verification; the lab runbooks under
`docs/architecture/` use `SOPHOS_VERIFY_SSL=false` only for the self-signed lab appliance and say so",
which matches the two runbooks. **#12 is closed and reproduces exactly**: enumerating `tools/list` and
classifying each tool's `request` object's own `properties` (camelCase = any uppercase letter,
snake_case = any underscore, no `oneOf` resolution) yields **74 camelCase-only, 55 snake_case-only, 5
mixed, 6 single-word-only, 12 no-parameter (8 with no `request` property + 4 with an empty request
model) = 152**, identical to the documented figures; my earlier 75/57/3/8/9 was my own measurement
error — my camelCase regex `[a-z][A-Z]` missed digit-prefixed names such as `ipv4Addresses`, and I
resolved `oneOf`, which moves the three address/MAC create tools into camelCase. **#13 is closed** —
`RELEASE-0.4.0.md:274-277` now says "if one exists", states that a first release has no `latest` and
uses the pre-promotion commit as the rollback target, and `:269-271` records that `docker-publish.yml`
has no `pull_request` trigger and first runs on the merge to `main` or the `v*` tag. **N1 is closed** —
`LAB-ACCESS.md:11,93,96` now say the credential is **not** stored in the repository and that the
previous key must be rotated **now**, consistent with the notice at `:3-8`. Gates re-run on `8cddb8e`:
`pytest -q` **962 passed / 100 skipped**, mypy clean (26 files), flake8 clean, black 50 unchanged,
`generate_coverage.py --check` up to date, `uv lock --check` 55 packages; CI on the PR is fully green
(Tests 3.11–3.14, Lint, Docker build, Dependency audit, SAST). No finding remains open. **The only
remaining blocker is the owner's rotation of the exposed lab key** (it is still valid and still in
public git history at `cb8dbe3`); publication stays blocked until that rotation is confirmed.
