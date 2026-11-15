# Phase 4 — Test, feedback and refinement

**Status:** implemented (15 Nov 2026), pending independent review. **Base:** `main` after 0.4.0 (`c8411c0`).
**Objective:** exercise the released server against the real appliance, collect concrete feedback, and refine the implementation from it. This phase is feedback-driven: no work item is accepted without evidence from a real run or a reproducible defect.

## What is already done

- 0.4.0 published: tag `v0.4.0`, image `ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0` (`0.4`, `latest`), GitHub release.
- Server installed locally from the published tag into `.agents/mcp-venv` and connected to DSH through a configuration-only MCP bundle (`@local/sophos-firewall-mcp`, stdio).
- STDIO smoke test: protocol 2026-07-28, 98 read-only tools, 0 mutations, two live read-only calls returned 200.

## Workstreams

| # | Workstream | Owner | Depends on | Output |
|---|---|---|---|---|
| A | **Dogfooding (read-only)** — done: 71 PASS / 24 SKIP / 3 FAIL, 31 defects: exercise all 98 read-only tools against the lab through the installed server; record defects, UX/schema issues and error-message problems | `dogfood` | — | `docs/live-evidence/phase-4-feedback.md` + issues |
| B | **Refinement fixes** from A — done: B1, H1–H4, D1, M3–M8, L2, L4, L5 fixed; M2, M9–M16, L1/L3/L6–L10 deferred | `refine` | A | code + tests + updated feedback record |
| C | **M1 input naming unification** (0.5.0) — done: 0 camelCase-publishing tools: 79 tools publish camelCase; unify on snake_case with wire aliases, add a surface test | `naming` | — | code + tests |
| D | ~~Streamable HTTP transport~~ — **cancelled by the owner**: the aitools stack was only considered in case the MCP required a container; it does not. The server stays stdio-only and DSH launches it. | — | — | — |
| E | **Live write validation** — done: create/update/delete with cleanup verified; D1 found and fixed — the owner confirmed the key can write rules and objects, with strict constraints: create only new `mcp-test-*` objects, never enable a rule, never edit or delete existing objects, and delete everything created before finishing. | `writes` | owner approval (given) | `docs/live-evidence/phase-4-write-validation.md` |
| F | **Firmware build identification** | owner | — | recorded build |
| G | **Rotate the exposed lab key** | owner | — | updated `LAB-ACCESS.md` |
| H | **Independent review** of the phase | `reviewer4` | B, C, D | `PHASE-4-REVIEW.md` |

## Rules

- Read-only against the appliance until the owner provides a write key and a disposable-object plan.
- Every finding cites the tool, the input, the observed output and the expected behaviour.
- No speculative refactor: a change must answer a recorded finding or a known issue (M1, D).
- One branch `migration/phase-4-refinement`; one PR; independent review before merge.
