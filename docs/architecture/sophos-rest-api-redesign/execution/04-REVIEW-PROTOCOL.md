# 04 — Independent review protocol (per phase)

> Use this in a **new session** (or with a new `reviewer`, never a `subagent_fork` of the author) at the end of each phase. Its output is a report, not a merge.

## Role

You are an independent principal reviewer. You did not write the code you are reviewing. Your job is to **find what is wrong**, not to confirm what is right. If you cannot verify a claim, say so; do not accept it.

## Inputs

1. The phase PR (full diff, description, and evidence).
2. Issues #24–#32 and #35 (full body), including the **owner scope revision of 15 November 2026**
   (the comment on #24 and the scope updates at the top of #27, #29 and #31), and [`PLAN.md`](../PLAN.md).
   Where PLAN.md and the issues disagree, the issues win for the first release; report the conflict.
3. [`INDEPENDENT_REVIEW_REPORT.md`](../INDEPENDENT_REVIEW_REPORT.md) and [`REFERENCES.md`](../REFERENCES.md).
4. [`ADR-001-rest-client-strategy.md`](../ADR-001-rest-client-strategy.md) — it defines the client decision
   **and** the first-release scope (§10), so it is an input, not just background.
5. `firewall_config_openapi.yaml` (parsed, not by eye), `API-COVERAGE.md` and
   `scripts/coverage_curated.yaml` (the curated decisions the generated document merges).
6. The test suite and the workflows; the previous phase review report, if one exists.

## Method

1. **Read the full diff** (`git diff <base>...<head>`), not just the PR summary.
2. **Run** the suite and linters; do not trust the author's report.
3. **Check every tool** — including every **composite** tool — against its operationId(s), schema,
   status codes and media type in the YAML.
4. **Actively look for** the failures in the checklist below.
5. **Classify** each finding by severity and cite file:line and evidence.
6. **Issue a verdict**: approve / changes required.

If the PR is large, you may use `workflow` to review per domain in parallel (`pipeline` with one agent per domain) and consolidate the verdict yourself.

## Checklist

### Contract and scope

- [ ] Every tool maps to a real, audited operationId **or** is a declared composite tool whose
      underlying operationIds are audited and present in `tool_map`; no invented endpoints.
- [ ] The v1 surface matches the revised scope: **145 operations / 152 MCP tools across 11 domains**
      (ADR-001 §10, API-COVERAGE §4). Excluded operations are documented and not registered.
- [ ] Domain decisions are honoured: IPv4/IPv6 per family; WAF (`ruleType: waf`) excluded; VPN and
      SSL VPN read-only (20 operationIds); **interfaces read-only except VLAN writes**; live-users as
      scoped; **network architecture read-only**; **MAC CRUD**; **country groups read-only**;
      **audit tools read-only**; **firewall enable/disable (PATCH `enabled`) and clone (get+create)**;
      bulk delete excluded everywhere.
- [ ] VLAN-only writes are enforced: `createNetworkInterface`/`updateNetworkInterface`/
      `deleteNetworkInterface` are exposed only for `type: vlan`, and no tool can mutate a physical,
      bridge, LAG or XFRM interface.
- [ ] Composite tools declare `kind` (`read`/`mutation`) and the four firewall composites are
      mutations; they are not registered when `SOPHOS_READ_ONLY_MODE=true`.
- [ ] PATCH: `application/json`, merge patch, no invented `application/merge-patch+json`.
- [ ] Pagination only where the contract declares it; no invented cursors.
- [ ] `enabled`/`position`/`ruleType` and move-by-name are correctly modeled for firewall.
- [ ] `message` required (1–600) on disconnect; login/logout not registered.
- [ ] No raw REST, XML, semantic router, or prompts/resources without a decision.

### Security

- [ ] TLS verified by default; `verify=false` only in the lab and documented.
- [ ] API key out of logs, errors, traces, and tool output; `SecretStr` or equivalent.
- [ ] No cross-origin redirects that forward the Bearer.
- [ ] No model-controlled URL/path/headers.
- [ ] Sanitized errors; no raw remote bodies.
- [ ] No secrets in images, CI, artifacts, or screenshots.
- [ ] `SOPHOS_READ_ONLY_MODE` does not register mutations **or mutation composites**, and is tested.

### MCP

- [ ] `Context[AppContext]` injected and out of the input schema.
- [ ] One client per process; the lifespan creates it and closes it in `finally`.
- [ ] `ToolError` for anticipated failures; `MCPError` only for protocol; unexpected exceptions to the SDK.
- [ ] No `BaseException`; cancellation propagates.
- [ ] `structuredContent`/`content` not duplicated; output schemas valid.
- [ ] Annotations per tool, not in bulk; `openWorldHint` justified.
- [ ] STDIO: stdout is protocol only; logs to stderr; no TTY.
- [ ] `subscriptions=False` if the catalog is static.

### Tests

- [ ] Every tool, including every composite tool, has contract tests (method, path, query, headers,
      body, status).
- [ ] The coverage matrix is tested: full parse, every operation exactly once, deterministic
      regeneration, SHA gate, and the composite `kind` classification.
- [ ] Tests prove behavior, not implementation.
- [ ] Mocks are not presented as firmware compatibility.
- [ ] Live tests are opt-in, read-only, recorded or deferred with a reason.
- [ ] Error cases: 400/401/403/404/409, timeout, malformed JSON, network.
- [ ] No tests fragile to order, time, or network.

### Quality and git

- [ ] `pytest`, `mypy`, `flake8`, `black` green.
- [ ] No changes outside scope; no hand-edited generated files.
- [ ] Commits with explicit paths; no `add -A`; no branch switching by teammates.
- [ ] `API-COVERAGE.md` regenerable and without drift.
- [ ] ADR-001 §10, `API-COVERAGE.md` §4 and `scripts/coverage_curated.yaml` agree on the scope
      counts (145 operations / 152 tools / 11 domains).
- [ ] Documentation updated and consistent with the code.
- [ ] No critical `TODO`s without an issue.

## Output

```markdown
# Independent review — Phase N

## Verdict
APPROVE | CHANGES REQUIRED

## Findings
| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | Critical/High/Medium/Low | ... | ... | ... | ... |

## Verified
- (what you checked and how)

## Not verified
- (what you could not check and why)

## Residual risks
- ...
```

## Rules

- Do not edit `src/` or tests: your output is a report. If the Lead asks you to fix, do it as a separate task with explicit ownership.
- Do not merge or publish anything.
- A critical finding **blocks** integration; it is not downgraded to a nit to close early.
- If you and the author disagree, provide primary evidence (operationId, YAML line, test output), not opinion.
