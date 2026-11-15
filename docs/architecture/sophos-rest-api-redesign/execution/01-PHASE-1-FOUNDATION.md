# 01 — Phase 1: REST foundation (#24, #25, #26)

> **Before starting:** read and apply [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md). This prompt assumes its rules (team, board, git, verification, escalation).

## Phase objective

Turn the OpenAPI contract into an implementable base and leave the MCP server ready for five agents to add domain tools without touching the foundation.

**Issues:** [#24](https://github.com/lordraiden/sophos-firewall-mcp/issues/24) (audit/ADR/coverage), [#25](https://github.com/lordraiden/sophos-firewall-mcp/issues/25) (REST client), [#26](https://github.com/lordraiden/sophos-firewall-mcp/issues/26) (MCP foundation).

**Out of scope:** domain tools (#27–#31), hardening/release (#32), CI/Docker changes (phase 3), writes against the lab.

## Expected outcome

- `docs/architecture/ADR-001-rest-client-strategy.md` with the client decision (generated vs manual) and its evidence.
- `docs/API-COVERAGE.md` generated deterministically from the YAML, with curated per-domain decisions.
- `scripts/generate_coverage.py` reproducible and SHA-checked.
- `src/sophos_firewall_mcp/client.py` REST-only, typed, with validated configuration and typed errors.
- `src/sophos_firewall_mcp/server.py` with lifespan, `AppContext`, modular registration, and `SOPHOS_READ_ONLY_MODE`.
- Client and foundation tests; `pytest`, `mypy`, `flake8`, `black` green.
- Phase PR open, not merged.

## Team and write ownership

| Member | Task | Writes (exclusive) | Does not touch |
|---|---|---|---|
| `contract` | #24 | `docs/API-COVERAGE.md`, `docs/architecture/ADR-001-rest-client-strategy.md`, `scripts/generate_coverage.py`, `docs/live-evidence/README.md` | `src/`, `tests/`, `pyproject.toml` |
| `client` | #25 | `src/sophos_firewall_mcp/client.py`, `config.py`, `errors.py`, `tests/test_client.py`, `tests/test_config.py` | `server.py`, `tools/`, `pyproject.toml` |
| `foundation` | #26 | `src/sophos_firewall_mcp/server.py`, `context.py`, `tools/__init__.py`, `tests/test_server.py`, `tests/test_context.py` | `client.py`, `config.py`, `tools/<domain>.py` |
| `reviewer` | review | nothing (report only) | everything |
| Lead | integration | `pyproject.toml`, `uv.lock`, branch, integration commits | domain code |

If someone needs a change in a file they do not own, they ask via `send_message`; they do not edit it.

## Task graph

```text
T1 [#24 ADR + client strategy]  ──► T2 [#25 REST client] ──► T3 [#26 MCP foundation]
T4 [#24 coverage + generator]  (parallel, blocks phase 2)
T5 [independent review]  (blocked by T2, T3, T4)
```

- **T1 blocks T2**: no client implementation without a client decision.
- **T2 blocks T3**: #26 consumes #25's public interface.
- **T4 does not block T2/T3**, but it blocks phase 2 and #32.
- **T5** starts when T2, T3, and T4 are `completed`.

## Step by step

### Step 0 — Preflight (Lead)

1. Clean `git status`; create branch `migration/phase-1-foundation` from `main`.
2. Verify the environment: `uv sync` (if the lock needs regeneration, record it and decide with the owner; use `--locked` only when it is current), `uv run pytest -q` (it must pass or the baseline failure must be recorded).
3. Confirm the lab responds **read-only** using `LAB-ACCESS.md`; do not perform writes.
4. Create tasks T1–T5 on the board with `write_scopes` and `blocked_by`.
5. Create `contract`, `client`, `foundation`, and `reviewer` with `subagent` (self-contained prompts).
6. Send each one its task and work prompt; do not launch them all at once if there are dependencies.

### Step 1 — T1: ADR and client strategy (`contract`)

Deliverables:

- `ADR-001-rest-client-strategy.md` with: context, options (manual HTTPX+Pydantic, `openapi-python-client` ≥0.30.0, hybrid), POC evidence, decision, consequences, and risks.
- Bounded POC: parse the full document, generate/implement 5 representative operations (simple GET, paginated list, IPv4 create, NAT PATCH, object with nested references), measure size/complexity, do not merge generated code.
- `scripts/generate_coverage.py`: parses the YAML, resolves `$ref`, validates operationId uniqueness, emits `docs/API-COVERAGE.md` with one row per operation and per-domain sections; fails if the SHA-256 changes without a reviewed regeneration.
- `docs/API-COVERAGE.md`: generated facts + curated decisions (v1 scope, exclusions, PATCH exceptions, pagination, identifiers, error statuses).
- `pytest -m live` protocol documented (read-only with the current key).

Acceptance criteria: those of #24, including the measurable AC (operationIds, schemas, status codes, identifiers, and pagination per domain).

**Gate:** when the ADR is ready, the Lead unblocks T2 and notifies `client`.

### Step 2 — T2: REST client (`client`)

Deliverables:

- `config.py`: typed settings (`SOPHOS_HOST`, `SOPHOS_PORT`, `SOPHOS_API_KEY`/`_FILE` mutually exclusive, `SOPHOS_VERIFY_SSL`, `SOPHOS_CA_BUNDLE`, `SOPHOS_TIMEOUT`), host/port validation, no secrets in errors.
- `errors.py`: `SophosAPIError` hierarchy → auth/validation/not-found/conflict/ambiguous-write/transport.
- `client.py`: `SophosRestClient` with `get/post/patch/delete`, fixed base URL, Bearer, TLS on, timeouts, no cross-origin redirects, no caller-supplied URL/path, `aclose()` and `async with`, pagination only where the contract declares it, bounded read retry (2 attempts, 502/503/504, jittered backoff), and **no** blind retry of writes.
- RESPX tests: URL/method/query/headers/content-type/body/status per primitive; 401/400/404/409; timeouts/TLS/malformed JSON; key redaction; absolute-URL rejection; pool close.

Criteria: those of #25, including the documented public interface.

**Gate:** publish the interface (methods, exceptions, `aclose`) in the PR and notify `foundation`.

### Step 3 — T3: MCP foundation (`foundation`)

Deliverables:

- `context.py`: `AppContext(client, settings, read_only)`.
- `server.py`: factory/entrypoint, lifespan creating **one** client and closing it in `finally`, modular per-domain registration, injected `Context[AppContext]`, `subscriptions=False`, STDIO, logging to stderr.
- Remove `_guard.py`, the FastEmbed router, and the raw XML tool; no `BaseException`.
- `SOPHOS_READ_ONLY_MODE`: does not register mutation tools; test comparing the tool list in both modes.
- Errors: `ToolError` for anticipated failures, `MCPError` only for protocol, unexpected exceptions to the SDK; `content`/`structuredContent` not duplicated; `extra="forbid"` where the contract is closed.
- Tests: lifespan (startup, invalid config, normal and exceptional shutdown, exactly-once close), context identity, tool list, schemas/annotations, errors, cancellation, STDIO with the SDK `Client`.

Criteria: those of #26.

### Step 4 — T4: Coverage (`contract`, in parallel)

- Run `scripts/generate_coverage.py` and commit the result.
- Fill in the curated per-domain decisions (v1 scope, exclusions, WAF, VPN read-only, interfaces read-only, live-users, bulk delete).
- Record the PATCH exceptions (`patchMessages`, `updateCentralFirewallReportingLogComponents`, `updateSyslogServerLogs`, `updateAlertNotificationSettings`).
- Document the live protocol and the `docs/live-evidence/<domain>.md` format.

### Step 5 — T5: Independent review (`reviewer`)

- Create a **new** `reviewer` (not `subagent_fork`) with the diff, the issues, and the plan.
- It must verify: contract vs implementation, security (TLS, secrets, redirects, fixed URL), errors, lifecycle, tests that prove behavior, nothing outside scope.
- It delivers a report with findings by severity and a verdict: approve / changes required.
- The Lead fixes or reassigns; a critical finding is not ignored.

### Step 6 — Integration and close (Lead)

1. Review `git diff main...HEAD`: only phase paths.
2. Run the full suite and linters.
3. Confirm `docs/API-COVERAGE.md` regenerates without unexpected changes.
4. Open the PR `migration/phase-1-foundation` → `main` with: what, evidence, decisions, risks, pending items.
5. **Do not merge** without owner approval.
6. Report per master §9.

## Phase exit criteria

- [ ] ADR approved by the owner (or explicitly marked as a pending decision).
- [ ] `API-COVERAGE.md` generated and reproducible; SHA recorded.
- [ ] REST client with no XML, tests, and typed errors.
- [ ] Foundation with lifespan, `AppContext`, registration, and read-only mode.
- [ ] `pytest`, `mypy`, `flake8`, `black` green.
- [ ] Independent review with no open criticals.
- [ ] PR open, not merged.
- [ ] Board with no orphan tasks.

## Phase-specific escalation

- If the ADR concludes a huge generated client is needed, **ask** before putting it into production.
- If the contract does not allow implementing an operation safely, document it and do not expose it.
- If the lab stops responding, do not block the phase: use mocks and record the limitation.
