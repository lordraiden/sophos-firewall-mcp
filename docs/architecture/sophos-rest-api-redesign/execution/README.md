# Executing the REST migration with subagents and Agent Teams

This directory contains the prompts for executing the Sophos Firewall MCP migration plan with **subagents** and **Agent Teams** in DeepSeek Harness (DSH).

## Why the work is split into phases

The nine issues **cannot be executed all at once** with quality:

1. **#24 decides the contract** (client ADR, coverage, live protocol). #25 and #26 cannot start without that decision.
2. **#25 defines the client interface** and **#26 consumes it**; done simultaneously without a contract, they contradict each other.
3. **#27–#31 share the foundation** (`AppContext`, tool registration, errors). Without it, each agent invents its own layer.
4. **#32 depends on all of the above** and additionally requires owner approval to publish.
5. A single session does not have enough context for 700 operations + 9 issues + review; quality drops and agents step on each other.

Therefore: **3 sequential phases + 1 independent review per phase**.

| Phase | Issues | Prompt | Output |
|---|---|---|---|
| 1 — Foundation | #24, #25, #26 | [`01-PHASE-1-FOUNDATION.md`](./01-PHASE-1-FOUNDATION.md) | ADR, `API-COVERAGE.md`, REST client, MCP foundation, tests |
| 2 — Domain tools | #27, #28, #29, #30, #31, #35 | [`02-PHASE-2-DOMAIN-TOOLS.md`](./02-PHASE-2-DOMAIN-TOOLS.md) | 6 domain PRs + coverage + tests |
| 3 — Hardening and release | #32 | [`03-PHASE-3-HARDENING-RELEASE.md`](./03-PHASE-3-HARDENING-RELEASE.md) | CI, Docker, docs, evidence, release prepared |
| Review | cross-cutting | [`04-REVIEW-PROTOCOL.md`](./04-REVIEW-PROTOCOL.md) | Adversarial report per phase |

Each phase prompt **starts by reading** [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md), which contains the shared context and rules. Do not duplicate context in every phase: if a rule changes, change it in the master.

## How to use them

1. Open a new DSH session in the repository workspace with **Agent Teams enabled**.
2. Paste the contents of `01-PHASE-1-FOUNDATION.md` as the first message (or say "read and execute this prompt").
3. The Lead creates the team, the task board, and executes the phase.
4. When it finishes, run `04-REVIEW-PROTOCOL.md` as an independent session (or ask the Lead for a separate reviewer).
5. Only if the review passes and the owner approves the merge, start phase 2.
6. Repeat with `02` and `03`.

**Do not chain phases automatically**: each phase ends in a PR and a human approval gate.

## Recommended team

| Phase | Members | Write ownership |
|---|---|---|
| 1 | `contract`, `client`, `foundation`, `reviewer` | `docs/API-COVERAGE.md`, `docs/architecture/ADR-001-*`, `scripts/coverage*`, `src/sophos_firewall_mcp/client.py`, `config.py`, `server.py`, `context.py`, `tests/` |
| 2 | `firewall`, `nat`, `objects`, `users`, `network`, `audit`, `reviewer` | `src/sophos_firewall_mcp/tools/<domain>.py`, `tests/test_<domain>.py`, `docs/api-coverage/<domain>.md` |
| 3 | `hardening`, `release`, `reviewer` | `.github/`, `Dockerfile`, `docker-compose.yml`, `README.md`, `.env.example`, `pyproject.toml`, `uv.lock` |

The Lead does not write domain code: it coordinates, reviews diffs, integrates, and decides. The `reviewer` never writes to `src/`.

## Golden rules (summary)

1. **Read before writing**: PLAN, REFERENCES, LAB-ACCESS, audit report, issue, and OpenAPI contract.
2. **Contract first**: #25 publishes the interface; #26 and #27–#31 consume it.
3. **Disjoint writes**: one owner per file; shared files are touched only by their owner.
4. **One branch per phase**, no `checkout`/`rebase` by teammates; commits with explicit paths.
5. **The lab key is read-only**: writing to the firewall is forbidden.
6. **Nothing is merged or published without owner approval.**
7. **Evidence over claims**: operationId, status code, and test; no "it should work".
8. **Independent review** before every merge.
9. **Collect and verify** all results before answering.
10. **Escalate** when a decision or credential is missing; do not invent.

## Starting state

- Independent audit complete: [`INDEPENDENT_REVIEW_REPORT.md`](../INDEPENDENT_REVIEW_REPORT.md).
- Corrected plan: [`PLAN.md`](../PLAN.md).
- Issues #24–#32 corrected and open.
- Lab verified live (read-only): [`LAB-ACCESS.md`](../LAB-ACCESS.md) and [`docs/live-evidence/api-smoke-2026-11-15.md`](../../../live-evidence/api-smoke-2026-11-15.md).
- Implementation: **not started**.
