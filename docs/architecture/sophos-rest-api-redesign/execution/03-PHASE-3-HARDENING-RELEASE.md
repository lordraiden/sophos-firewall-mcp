# 03 — Phase 3: Hardening and release (#32)

> **Before starting:** read and apply [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md). **Precondition:** phases 1 and 2 are merged and verified.

## Phase objective

Close the migration: end-to-end verification, security, CI, container, documentation, and release preparation. **Actual publication requires explicit owner approval.**

**Issue:** [#32](https://github.com/lordraiden/sophos-firewall-mcp/issues/32).

## Two-gate structure

| Gate | Content | Approval required? |
|---|---|---|
| **A — Hardening** | MCP e2e, live integration (read-only), security, CI, Docker, docs | No; execute and review |
| **B — Release** | version, tags, GHCR, `latest`, release notes | **Yes, explicit owner approval** |

Do not start gate B until A is green and reviewed.

## Preflight (Lead)

1. Confirm `main` contains phases 1 and 2, the suite is green, and `API-COVERAGE.md` is up to date.
2. Create branch `migration/phase-3-hardening-release`.
3. Create tasks T33–T38 + T39 (review) with disjoint `write_scopes`.
4. Create `hardening`, `release`, and `reviewer`.
5. Verify the lab key is still **read-only**; there are no writes in this phase.

## Write ownership

| Member | Writes (exclusive) | Does not touch |
|---|---|---|
| `hardening` | `.github/workflows/`, `Dockerfile`, `docker-compose.yml`, `entrypoint.sh`, `tests/` (integration), `docs/live-evidence/` | `src/` except fixes approved by the Lead |
| `release` | `pyproject.toml`, `uv.lock`, `README.md`, `.env.example`, `CHANGELOG.md`, release metadata | workflows, Docker, `src/` |
| `reviewer` | nothing (report) | everything |
| Lead | integration, PR, publish decision | — |

`pyproject.toml`/`uv.lock` belong to `release`; if `hardening` needs a change, it asks.

## Tasks

### T33 — MCP end-to-end verification (`hardening`)

- Tests with the official SDK `Client`: discovery, input/output schemas, annotations, `isError`, cancellation.
- STDIO subprocess test: stdout is protocol only, no TTY, orderly shutdown.
- Compatibility: 2026-07-28 by default and `mode="legacy"` if legacy support is declared.
- MCP Inspector: discovery smoke test and representative calls.
- Record evidence in the PR.

### T34 — Appliance integration (`hardening` + `reviewer`)

- Matrix in `API-COVERAGE.md`: live-tested / contract-tested / unsupported / deferred / not implemented.
- Run `pytest -m live` **read-only** with the lab key; record build, profile, date, and operations in `docs/live-evidence/`.
- Do not write rules, NAT, interfaces, VPN, or sessions. If a write test is needed, **stop and ask** for a write key + disposable-object plan.
- Document what could not be tested and why.

### T35 — Security review (`hardening` + `reviewer`)

- API key flow: origin, `SecretStr`, file vs env, permissions, mount, redaction in logs/errors/tools.
- TLS by default, CA bundle, no `verify=false` in examples.
- Cross-origin redirects, explicit proxy, timeouts, pool close.
- No secrets in images, CI, artifacts, or screenshots.
- Sanitized errors; remote bodies are not returned raw.
- Review `pip-audit` against the real lock and `semgrep`.

### T36 — CI and pipeline (`hardening`)

- `uv sync --locked` in CI/build; `pyproject.toml` + `uv.lock` as the single source.
- Python matrix 3.11–3.14.
- `pip-audit` against the real locked resolution, not the obsolete `requirements.txt`.
- Tests, lint, mypy, semgrep, and image build on PR.
- Opt-in integration workflow (`pytest -m live`) with secrets, without printing them.
- No `latest` on pushes to `main`: development tags only (`main`, SHA).

### T37 — Container and documentation (`hardening` + `release`)

- `Dockerfile`: no FastEmbed or model downloads, no `.[router]`, non-root if viable, no TTY, STDIO `ENTRYPOINT`, signals and orderly shutdown.
- `docker-compose.yml`: REST configuration and secret only; `tty: false`; no XML credentials.
- `README.md`: REST-only, Sophos prerequisites, variables, MCP client examples, correct image names.
- `.env.example`: REST-only, no XML username/password, secure TLS by default.
- `CHANGELOG.md`: migration changes.
- Verify the canonical GHCR namespace (`ghcr.io/lordraiden/...`) and fix links.

### T38 — Release preparation (`release`, only with approval)

- Semantic version and release notes.
- Publish workflow: `main` → development tags; `v*` → stable tags; `latest` only in an approved promotion.
- GitHub Environment with reviewers if the owner approves.
- **Do not** publish a tag, stable image, or `latest` without explicit approval.
- Attach the rollback plan.

## Review (T39)

- An independent `reviewer` reviews the full PR: security, CI, Docker, docs, live evidence.
- Verdict: approve / changes required.
- The Lead fixes or reassigns; criticals block.

## Close

1. Full suite, linters, image build, and STDIO smoke test green.
2. `git diff main...HEAD` limited to scope.
3. Phase PR with evidence, risks, and pending items.
4. **Gate B:** request explicit owner approval before any publication.
5. Report per master §9.

## Exit criteria

- [ ] MCP e2e and STDIO verified with the official SDK.
- [ ] Live/contract/unsupported/deferred matrix complete.
- [ ] Security reviewed with no criticals.
- [ ] CI with lock, 3.11–3.14 matrix, real `pip-audit`, semgrep.
- [ ] Docker REST-only, no TTY, no FastEmbed, non-root if viable.
- [ ] README/`.env.example`/CHANGELOG consistent.
- [ ] GHCR and tag policy fixed; `latest` only with approval.
- [ ] PR open, not merged; release **not** published.
- [ ] Live evidence recorded or deferred with a reason.

## Phase-specific escalation

- If the SFOS build or a write key is missing, **do not invent** evidence: record the blocker.
- If the owner does not approve the release, leave gate B prepared and documented, without publishing.
- If a CI/Docker change breaks the suite, revert and report; do not hide it.
