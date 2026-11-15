# Release 0.4.0 — REST-only Sophos Firewall MCP server

| Field | Value |
|---|---|
| Version | **0.4.0** (previous version: 0.3.1 — never published as a git tag or image tag) |
| Release type | **Breaking** — XML API removed, REST-only |
| Date prepared | 15 November 2026 |
| Status | **Gate B prepared, not executed.** No tag, image, `latest` move or GitHub release has been created. |
| Publication gate | Independent phase-3 review **APPROVE** + Lead approval + explicit owner approval |
| Owner decision | Version **0.4.0**; publication only after review and Lead approval (15 Nov 2026) |

This document is the gate-B pack for issue [#32](https://github.com/lordraiden/sophos-firewall-mcp/issues/32):
release notes, rollback plan and the publication checklist. It contains no secrets.

---

## 1. Release notes

### 1.1 Summary

`sophos-firewall-mcp` 0.4.0 is a **breaking, REST-only release**. The server now administers a Sophos
Firewall (SFOS) appliance exclusively through the **Sophos Firewall Configuration REST API**
(`https://<host>:<port>/api/firewall-config/v1`, Bearer API key) over **STDIO**. The XML API transport,
the XML credentials, the raw XML tool, the semantic tool router and the FastEmbed dependency are gone,
with no compatibility mode.

The tool surface is rebuilt from the checked-in OpenAPI contract: **152 typed tools across 11 domains**,
covering **145 audited operations** plus **7 composite tools** that add no new endpoint. Every tool maps
to a documented `operationId`; the mapping and every exclusion are recorded in
[`docs/API-COVERAGE.md`](../API-COVERAGE.md).

### 1.2 Tool surface

| Domain | Tools | Access |
|---|---:|---|
| Firewall rules (IPv4/IPv6) | 16 | read + write (incl. enable/disable and clone composites) |
| NAT rules (IPv4/IPv6) | 12 | read + write |
| Addresses and address groups | 37 | read + write (MAC CRUD; country groups read-only) |
| Services and service groups | 10 | read + write |
| Network users | 6 | read + write |
| Live users | 2 | read + write (list, disconnect) |
| IPsec VPN | 11 | read-only |
| SSL VPN | 9 | read-only |
| Network architecture | 44 | read-only + 3 VLAN-only interface writes |
| Network status | 2 | read-only |
| Audit (composite) | 3 | read-only |
| **Total** | **152** | 54 mutation tools; **98 tools / 0 mutations** with `SOPHOS_READ_ONLY_MODE=true` |

### 1.3 Breaking changes

- **XML transport removed.** `SOPHOS_USERNAME`, `SOPHOS_PASSWORD` and `SOPHOS_API_VERSION` are no longer
  read; `/webconsole/APIController` is no longer called; `xmltodict` is no longer a dependency.
- **Tool surface replaced.** The 28 XML-era `sophos_*` tools are gone. Tool names, input schemas and
  output schemas are new, so saved tool calls and client-side allowlists must be updated.
- **No raw API tool.** There is no replacement for `sophos_raw_api_request`: no tool accepts a URL, path,
  HTTP method, header or arbitrary payload.
- **Semantic router removed.** `USE_ROUTER` / `TOOL_ROUTING`, `route_tools`, `call_routed_tool`, the
  `router` extra and the FastEmbed model download are gone. The full tool list is always advertised.
- **Prompts and resources removed.** The `sophos://` resources and guided prompts are not part of the
  REST surface.
- **Packaging.** `pyproject.toml` + `uv.lock` are the single dependency source; `requirements.txt` and
  `requirements-dev.txt` are removed. Runtime dependency: `mcp>=2.3.0,<3`.

### 1.4 Security model

- **Bearer API key** held as `SecretStr`; sent only in the `Authorization` header; never logged, never in
  errors, never in tool output. Exactly one of `SOPHOS_API_KEY` / `SOPHOS_API_KEY_FILE` (a mounted secret
  file is preferred for containers).
- **TLS verified by default**; `SOPHOS_CA_BUNDLE` for a private or self-signed appliance certificate.
  `SOPHOS_VERIFY_SSL=false` is a lab-only escape hatch and appears in no example.
- **No inherited proxy**: `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` are ignored so the token cannot be
  routed through an unexpected proxy.
- **No cross-origin redirects**: a redirect to another origin is refused rather than followed with the
  token attached.
- **Sanitized errors**: anticipated failures raise `ToolError` with a short message; raw remote bodies,
  stack traces and secrets are not returned to the model.
- **No write retry**: a write that times out raises an ambiguous-write error instead of being repeated.
- **Read-only mode** (`SOPHOS_READ_ONLY_MODE=true`) does not register mutation tools at all. It is defence
  in depth: effective authorization comes from the Sophos administrator profile, the API allowlist and
  host-side approval policy. Tool annotations are advisory metadata, not access control.
- **Least privilege**: use a dedicated administrator with only the needed per-feature permissions; the
  API allowlist accepts at most 64 entries; keys are shown once, limited to 10 per administrator and
  1,024 per appliance, valid for one year, and rotated/revoked manually.
- **Dependencies**: CI runs `pip-audit` against the locked runtime resolution (`uv export --locked
  --no-dev`). The 0.4.0 lock bumps `certifi`, `cryptography` and `pyjwt` past their known advisories and
  reports no known vulnerabilities.

### 1.5 Accepted regressions

The REST contract exposes no endpoint for these capabilities, so they are not migrated and no
placeholder tool is advertised:

| Regression | Statement |
|---|---|
| System information | No endpoint for appliance model, serial number, firmware version or uptime (`getSystemSettings` returns only `hostname`, `loginDisclaimer`, `updatedAt`). |
| Service status | No endpoint returns the running state of system services. |
| Log query | Log destinations can be configured, but logs cannot be read through this API. |

### 1.6 Known limitations

- **Input parameter naming is not yet uniform.** Measured by enumerating `tools/list`: 74 tools publish
  camelCase-only inputs (firewall, network, VPN), 55 publish snake_case-only (NAT, objects, users), 5
  mix both, 6 have only single-word fields, and 12 take no parameters (8 declare no `request` property
  and 4 expose an empty request model). Every tool schema is self-describing, so this is an ergonomics
  inconsistency, not a functional defect. It will be unified in **0.5.0** as a documented breaking
  change; callers that hard-code parameter names should expect that change.
- **Target firmware build is unknown.** The contract exposes no version endpoint, so this release makes
  **no firmware compatibility claim**. Verify against your own appliance before relying on a tool.
- **No live write validation.** The shared lab credential is read-only; no POST, PATCH or DELETE has been
  executed against a real appliance. Write tools are covered by contract tests (mocked HTTP) only. Read
  paths are exercised by the opt-in `pytest -m live` suite and recorded in
  [`docs/live-evidence/`](../live-evidence/).
- **Audit tools are configuration analysis, not packet tests.** `explain_connectivity` reports
  `method: config-analysis` and returns `not-verifiable` when the configuration lacks evidence; findings
  are bounded and report truncation.
- **Pagination is one page per call**; the server never auto-paginates. `pageSize` is validated to
  `1..100`.
- **Excluded by design**: bulk delete, administrator CRUD, user groups, network-user login/logout, all
  VPN mutations, WAF, IPS, and the network mutation families outside the VLAN-only interface writes.

### 1.7 Upgrade from 0.3.1

1. Replace the XML credentials with an API key:
   `SOPHOS_API_KEY` (or `SOPHOS_API_KEY_FILE`), and delete `SOPHOS_USERNAME`, `SOPHOS_PASSWORD`,
   `SOPHOS_API_VERSION` and `USE_ROUTER`.
2. Enable API access on the appliance, add the client's source IP to **Allowed IP hosts**, and confirm
   **Device access** allows HTTPS / Web Admin Console from the administrator's zone.
3. Create a dedicated least-privilege administrator and generate the key from it.
4. Update the MCP client configuration to the new image tag or command (see
   [`README.md`](../../README.md#mcp-client-configuration)).
5. Rewrite any saved tool calls: names and schemas changed. Use `SOPHOS_READ_ONLY_MODE=true` first to
   discover the read surface safely.

---

## 2. Rollback plan

### 2.1 Impact assessment

The server is **stateless**: it holds no database, no local cache, no migration state and no files. It
only issues HTTP requests to the appliance. Therefore:

- **No data or configuration impact.** Rolling back the server changes nothing on the appliance. Objects
  created through 0.4.0 (rules, NAT entries, addresses, VLAN interfaces) remain on the appliance and are
  not reverted by a rollback — revert them explicitly if that is the intent.
- **No schema or migration to undo.**
- **The only rollback surface is the deployed artifact** (container tag or installed package) and the
  client configuration.

### 2.2 Roll back to the previous (XML-era) code

**There is no published `0.3.1` artifact to pull.** The repository has no git tags at all, and the
publish workflow only creates semver image tags from a `v*` tag, so no `0.3.1` image tag exists. The last
XML-era code is commit **`e6c9e1f`** (version 0.3.1, the parent of the XML-removal commit). Roll back by
building that commit, or by pulling the pre-promotion `latest` digest if it was recorded (§3.4):

```bash
# Option A — build the last XML-era commit
git clone https://github.com/lordraiden/sophos-firewall-mcp.git
cd sophos-firewall-mcp
git checkout e6c9e1f
docker build -t sophos-firewall-mcp:0.3.1-xml .

# Option B — pull the digest that `latest` pointed at before the 0.4.0 promotion
docker pull ghcr.io/lordraiden/sophos-firewall-mcp@sha256:<recorded-pre-promotion-digest>
```

Then restore the XML-era configuration in the MCP client (`SOPHOS_HOST`, `SOPHOS_PORT`,
`SOPHOS_USERNAME`, `SOPHOS_PASSWORD`, `SOPHOS_API_VERSION`; remove the REST key variables and
`SOPHOS_READ_ONLY_MODE`) and restart the client.

For a local install, the project is not on PyPI, so install from the same commit:

```bash
git clone https://github.com/lordraiden/sophos-firewall-mcp.git
cd sophos-firewall-mcp && git checkout e6c9e1f && pip install .
```

### 2.3 What breaks on rollback

| Area | Effect |
|---|---|
| Credentials | 0.3.1 needs XML username/password and `SOPHOS_API_VERSION`; the REST API key is ignored. XML API access must be enabled on the appliance. |
| Tool names | Every 0.4.0 tool name disappears; clients with saved calls or allowlists fail until reverted. |
| Read-only mode | `SOPHOS_READ_ONLY_MODE` is not supported by 0.3.1; mutation tools are always registered. |
| Security posture | 0.3.1 has no REST client hardening (no ambiguous-write protection, no cross-origin redirect refusal, different error sanitization). |
| Capability | 0.3.1 exposes the 28 XML tools, not the 152 REST tools; the audit tools do not exist. |

### 2.4 Roll back the release itself (tag and image)

Only the Lead/owner performs this, and only after an approved release:

```bash
# Delete the GitHub release and the tag (does not delete the image)
gh release delete v0.4.0 --yes
git push origin :refs/tags/v0.4.0
git tag -d v0.4.0

# Move `latest` back to the digest recorded before the promotion (§3.4)
docker pull ghcr.io/lordraiden/sophos-firewall-mcp@sha256:<recorded-pre-promotion-digest>
docker tag  ghcr.io/lordraiden/sophos-firewall-mcp@sha256:<recorded-pre-promotion-digest> \
            ghcr.io/lordraiden/sophos-firewall-mcp:latest
docker push ghcr.io/lordraiden/sophos-firewall-mcp:latest
```

The `0.4.0` and `0.4` image tags stay in the registry as immutable history; do not delete them unless the
owner asks. Record the rollback (date, reason, digests) in the release issue.

---

## 3. Publication checklist (gate B)

> **Do not execute any step below until the independent phase-3 review has returned **APPROVE**, the Lead
> has approved, and the owner has approved publication in writing.** Nothing in this repository has been
> tagged or published.

### 3.1 Preconditions

- [ ] Phase-3 PR merged to `main`; CI green on the merge commit (tests on 3.11–3.14, flake8, mypy,
      black, `pip-audit` against the lock, semgrep, image build).
- [ ] Independent phase-3 review verdict **APPROVE**
      (`docs/architecture/sophos-rest-api-redesign/PHASE-3-REVIEW.md`), no open critical findings.
- [ ] Lead approval recorded on the PR; owner approval recorded in writing.
- [ ] `pyproject.toml` and `uv.lock` both say `0.4.0`; `uv lock --check` passes.
- [ ] `CHANGELOG.md` has the `[0.4.0]` entry; `README.md` and `.env.example` are REST-only.
- [ ] `docs/API-COVERAGE.md` regenerates without a diff
      (`uv run python scripts/generate_coverage.py --check`).
- [ ] Live evidence recorded or explicitly deferred with a reason in `docs/live-evidence/`.
- [ ] Publish workflow policy verified: pushes to `main` produce **development tags only** (`main`,
      `sha-<short>`) and **never** move `latest`; the semver tags and `latest` come only from a `v*` tag
      in the `release` job, which uses the `release` GitHub Environment (required reviewers).
      Check before tagging:
      ```bash
      grep -n "latest\|environment:" .github/workflows/docker-publish.yml
      ```
      `latest` must appear only in the `release` job (gated on `refs/tags/v*`), never in the
      `development` job.

### 3.2 Tag the release

```bash
git checkout main
git pull --ff-only origin main
git log --oneline -1                     # confirm the reviewed merge commit
git tag -a v0.4.0 -m "sophos-firewall-mcp 0.4.0 — REST-only release"
git push origin v0.4.0
```

### 3.3 Publish the container image

The `v0.4.0` tag push triggers the publish workflow, which builds and pushes the stable tags:

| Tag | Expected |
|---|---|
| `ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0` | stable, immutable |
| `ghcr.io/lordraiden/sophos-firewall-mcp:0.4` | stable minor alias |
| `ghcr.io/lordraiden/sophos-firewall-mcp:latest` | **only** via the approved promotion below |

Verify the workflow run and the tags:

```bash
gh run list --workflow=docker-publish.yml --limit 3
docker manifest inspect ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0 > /dev/null && echo "0.4.0 present"
docker manifest inspect ghcr.io/lordraiden/sophos-firewall-mcp:0.4   > /dev/null && echo "0.4 present"
```

### 3.4 Promote `latest` (approved promotion only)

`latest` is moved **only** by this approved promotion — never by a push to `main`. Note that
`docker-publish.yml` has no `pull_request` trigger: it first runs on the merge to `main` (development
tags) or on the `v*` tag (release job), so a PR run does not exercise it. The `release` job in
`.github/workflows/docker-publish.yml` runs in the `release` GitHub Environment, so configure required
reviewers there and let the workflow publish the semver tags and `latest`; promote manually only if that
environment is unavailable, and record the digests.

**Record the current `latest` digest first, if one exists** — it is the rollback target (§2.4). On a
first release there is no `latest` yet; record that instead and use the pre-promotion commit as the
rollback target:

```bash
docker buildx imagetools inspect ghcr.io/lordraiden/sophos-firewall-mcp:latest
# Save the sha256 digest in issue #32 before continuing.
```

Then promote:

```bash
docker pull ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0
docker tag  ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0 ghcr.io/lordraiden/sophos-firewall-mcp:latest
docker push ghcr.io/lordraiden/sophos-firewall-mcp:latest

# Confirm latest and 0.4.0 resolve to the same digest
docker buildx imagetools inspect ghcr.io/lordraiden/sophos-firewall-mcp:latest
docker buildx imagetools inspect ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0
```

### 3.5 Create the GitHub release

```bash
gh release create v0.4.0 \
  --title "v0.4.0 — REST-only release" \
  --notes-file docs/release/RELEASE-0.4.0.md \
  --verify-tag
```

If the internal checklist should not be public, publish only §1 (release notes) as the release body and
keep this document in the repository.

### 3.6 Post-publish verification

```bash
# 1. The image pulls and the entrypoint runs: with no configuration it must exit 2
#    with one actionable line on stderr (never a traceback, never a key).
docker run --rm -i ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0 < /dev/null; echo "exit=$?"

# 2. STDIO discovery through the official MCP SDK client (run from the repository).
#    Expect: 152 tools in read-write mode.
uv run --no-sync python - <<'PY'
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

params = StdioServerParameters(
    command="docker",
    args=["run", "-i", "--rm",
          "-e", "SOPHOS_HOST", "-e", "SOPHOS_PORT", "-e", "SOPHOS_API_KEY",
          "ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0"],
    env={"SOPHOS_HOST": "192.0.2.10", "SOPHOS_PORT": "4444", "SOPHOS_API_KEY": "unused-for-discovery"},
)

async def main() -> None:
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("tools:", len(tools.tools))
            assert len(tools.tools) == 152, len(tools.tools)

asyncio.run(main())
PY

# 3. Read-only discovery: expect 98 tools and zero mutations.
#    Re-run the snippet with SOPHOS_READ_ONLY_MODE=true added to the container env and assert 98.
```

The discovery calls above do not need a reachable appliance: the server validates configuration at
startup and only contacts the appliance when a tool is called. Do not point the smoke test at a
production appliance, and never send a write.

### 3.7 Record the release

- [ ] Attach the CI run, image digests, review verdict and this checklist to issue #32.
- [ ] Record the published tags and digests in the release notes.
- [ ] Confirm `latest` was moved only by the approved promotion.
- [ ] Close the gate-B items; leave the release **unpublished** if any precondition is missing.

---

## 4. Owner approval record

| Decision | Value | Date |
|---|---|---|
| Version | **0.4.0** (breaking XML→REST migration; previous release 0.3.1) | 15 Nov 2026 |
| Publication | Only after the independent review passes and the Lead approves | 15 Nov 2026 |
| `latest` promotion | Only through the approved release promotion, never on a `main` push | 15 Nov 2026 |
| Gate B execution | **Not executed** — prepared only | 15 Nov 2026 |

Approval for publication must be recorded in writing on the phase-3 PR or issue #32 before §3.2 is run.
