# Release 0.6.0 — output contract, SFOS 23 positioning

**Status:** prepared, **not published** — pending explicit owner approval. **Previous release:** 0.5.0
(feedback-driven refinement). **Target appliance:** Sophos Firewall 23, **SFOS 23.0.0 GA-Build371**.

## 1. Release notes

### 1.1 Summary

0.6.0 closes the remaining phase-4 dogfooding findings and makes the output surface as consistent as
the input surface. 0.5.0 unified every published *input* parameter on snake_case; the *outputs* were
still split, with 119 tools publishing camelCase and 23 tools (12 NAT, 8 users and 3 audit tools)
publishing snake_case. 0.6.0 unifies them on **camelCase, the Sophos wire names**, because outputs are
projections of the appliance payload.

This release also states the product's appliance support explicitly: this is an **MCP server for
Sophos Firewall 23 (SFOS 23.0)**, implementing the **Configuration REST API v1**
(`/api/firewall-config/v1`). The live evidence in this repository was produced against **SFOS 23.0.0
GA-Build371**; no general firmware compatibility claim is made for any other SFOS build.

The **breaking** changes are the output naming and the new default page size. The JSON request body
sent to the appliance is unchanged; the default `pageSize` query value changes from 50 to 10 (see
§1.2).

### 1.2 Breaking changes

- **Published output field names are camelCase everywhere.** Every published output property, at every
  depth, is now the Sophos wire name (`pageSize`, `nameContains`, `idOrName`, `servicesOrGroups`,
  `originalServicesOrGroups`, `translatedSource`, …). 23 tools change: 12 NAT, 8 users and 3 audit
  tools. Callers that parsed the 0.5.0 snake_case output names must update. The convention is
  deliberate and now documented: **inputs are snake_case because the model writes them, outputs are
  wire-faithful because the model reads them.**
- **List tools default to `page_size: 10`.** A default call no longer returns a whole collection. A
  caller that relied on the implicit 50-item default must pass `page_size` explicitly. This is a
  behaviour change, not a schema change: `page_size` was already published.

### 1.3 Fixed

- **M11 — default output size.** Every list tool defaults to `page_size: 10`, and the heavy domains
  (firewall rules, NAT, services) state the approximate size of a full page, so a default call no
  longer returns a 72 KB firewall-rule collection (~18,000 tokens) into a model context.
- **M12 — evaluation `position`.** Firewall and NAT rule list outputs carry the page offset plus the
  index; a get-by-id returns `position: null`, because a single object has no evaluation order.
- **M13 — NAT `kind`.** NAT rules carry a derived `kind` (`snat` / `dnat` / `unknown`), computed from
  which translation field is populated, because the appliance exposes no discriminator.
- **M14 — one reference shape.** NAT projections use the same `{"name": …}` reference objects as
  firewall rules, so one parser works across both domains.
- **M15 — keyset ceiling documented.** `dhcp_lease_list_ipv4` exposes no undeclared inputs; the
  description states that only the first page is reachable and that a non-null `nextKey` means the list
  is incomplete.
- **M16 — uniform list envelope.** `dhcp_server_list_ipv4/ipv6` and `dhcp_relay_list_ipv4/ipv6` return
  `pages: null` instead of omitting the key, so "empty" is distinguishable from "truncated".
- **L1 — `Pages` semantics.** Field descriptions reach the published `outputSchema`: `pages.total` is
  the number of **pages**, `pages.items` the number of **items**.
- **L3 — audit description.** The `audit_firewall_rules` description matches the finding shape:
  object-scoped findings carry the object and leave `ruleName` / `ruleId` / `position` null.
- **L6 — epoch sentinel.** Built-in objects report `createdAt` / `updatedAt` as `null` instead of
  `1970-01-01T00:00:00Z`.
- **L7 — duplicated payload documented.** The JSON appears in a `TextContent` block and in
  `structuredContent`; the duplication is the MCP SDK's single-argument convention and is documented
  rather than silently changed.
- **L8 — `pages.maxSize` on DHCP leases** is documented as the item count, not a page-size bound.
- **L9 — IPsec live-connection ceiling.** The 1000-item ceiling of `ipsec_live_connection_list_ipv4` is
  documented, because the tool takes no arguments and a larger set would be silently truncated.
- **L10 — unset IPsec remote access.** An all-null object with `connectionState: "unset"` is described
  as "not configured".
- **M9 — `dhcp_relay_get_ipv4` 401 quirk.** The description states that this endpoint answers `401` for
  a UUID that does not exist, unlike every other get tool's `404`.
- **M10 — the `request` wrapper.** The descriptions state the wrapper instead of leaving the agent to
  discover it from a validation error.

### 1.4 Known limitations

- **Firmware compatibility is limited to the tested build.** The live evidence applies to **SFOS 23.0.0
  GA-Build371** only. The Configuration REST API exposes no version endpoint, so the server cannot
  detect the firmware it is talking to and makes no claim for any other SFOS build, including later
  23.0 maintenance builds and SFOS 24. Verify the behaviour you depend on against your own appliance.
- **Live write validation is limited** to the object kinds exercised on the lab appliance; ambiguous
  write reconciliation, a real `403` denial, bulk delete and interface/VPN mutations remain unverified.
- **Accepted regressions** are unchanged: no system information, no service status and no log query,
  because the Configuration REST API exposes no endpoint for them.
- **Audit tools are configuration analysis, not packet tests**; `explain_connectivity` reports
  `method: config-analysis` and `not-verifiable` when the configuration lacks the evidence.
- **Pagination is one page per call**; the server never fetches every page automatically.

## 2. Rollback

The server is stateless: rolling back changes no appliance configuration and no stored data.

1. Re-deploy the previous image `ghcr.io/lordraiden/sophos-firewall-mcp:0.5.0` (or the `0.5` alias).
2. If you run from source, check out `v0.5.0` and reinstall.
3. Clients that adopted the camelCase output names must go back to the 0.5.0 snake_case spellings for
   the 23 affected tools; the JSON request body is unchanged.
4. Clients that relied on the implicit 50-item default page size get it back; no other behaviour
   changes.

## 3. Publication checklist

- [x] `pyproject.toml` and `uv.lock` both say `0.6.0`; `uv lock --check` passes. The bump is part of
      this PR (commit `6dd66a7`).
- [ ] `CHANGELOG.md` has the `[0.6.0]` entry; `README.md` reflects 0.6.0.
- [ ] `docs/API-COVERAGE.md` regenerates without a diff.
- [ ] Independent review **APPROVE**
      (`docs/architecture/sophos-rest-api-redesign/PHASE-5-REVIEW.md`).
- [ ] CI green on the merge commit (tests 3.11–3.14, lint, image build, dependency audit, semgrep).
- [ ] Tag `v0.6.0` on the merge commit; the `release` job publishes `0.6.0`, `0.6` and `latest`.
- [ ] GitHub release with these notes.
- [ ] GitHub repository description and topics name Sophos Firewall 23 / SFOS 23 (Lead-owned).
- [ ] Post-publish: image tags present; the container build + STDIO smoke test ran green in CI on the
      same commit.

## 4. Approval record

**Not approved yet.** 0.6.0 is prepared on `migration/phase-5-output-contract` and must not be tagged,
published or promoted to `latest` without explicit owner approval, per phase-5 decision D17. The
approval is recorded here once given, together with the independent review verdict.
