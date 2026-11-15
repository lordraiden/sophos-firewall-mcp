# Release 0.5.0 — feedback-driven refinement

**Status:** published 15 November 2026. **Previous release:** 0.4.0 (REST-only migration).

## 1. Release notes

### 1.1 Summary

0.5.0 is the refinement release that follows the first real use of the 0.4.0 server against a live
appliance. The 98 read-only tools were exercised end to end (71 PASS / 24 SKIP / 3 FAIL, 31 defects
recorded) and the write tools were validated with disposable objects (create → read → update → delete,
cleanup verified). The defects that mattered are fixed here.

The only **breaking** change is the input-naming unification: every published input property, at every
depth, is now snake_case. The JSON body sent to the appliance is unchanged.

### 1.2 Breaking changes

- **Input parameter names are snake_case everywhere.** 0.4.0 published two conventions (74 tools
  camelCase-only, 55 snake_case-only, 5 mixed, 6 single-word-only, 12 parameterless). Every tool now
  publishes `page_size`, `name_contains`, `id_or_name`, `rule_type`, `reference_item`, and the nested
  fields too (`source_networks.fqdn_addresses`, `services[].source_port`, …). Callers that hard-coded
  `pageSize` / `nameContains` / `idOrName` must update. The wire body is byte-identical.
- **Closed argument models.** The published input schemas set `additionalProperties: false`; an unknown
  argument is rejected with a sanitized message instead of being ignored.

### 1.3 Fixed

- **`explain_connectivity` no longer returns a false verdict when a rule's service criterion does not
  match** (blocker): a rule is decisive only when every projected criterion matches; the same guard
  applies to NAT rules. 48-case regression matrix.
- **`audit_firewall_rules` no longer reports in-use objects as unused** when `ip_family` restricts the
  scan; the reference scan reads both families.
- **`explain_connectivity` models the WAN gateway as the default route**, so internet destinations are
  not reported as `no-route`.
- **`service_list`'s `type` filter works client-side** instead of being a silent no-op.
- **HTTP 401 is reported as an authentication failure**, not as a permission problem; 403 keeps the
  authorization message.
- **`network_user_create`/`update` send `group` as a `{"name": …}` reference**, so creating a network
  user no longer fails with 400.
- **Built-in and list-returned identifiers are accepted** (`##ALL_RW`, names containing `/`).
- **Audit findings are sorted by severity before truncation**, built-in objects are excluded from
  `unused-object` (with the heuristic and its limit stated), `rule_name_contains` narrows the report,
  every indeterminate rule is reported as a candidate, and routing truncation is explicit.
- **Validation errors no longer leak internal model names or pydantic URLs.**
- **`live_user_list` no longer names a tool that is not registered in read-only mode.**

### 1.4 Known limitations

- **Output field naming is still split** (NAT/users snake_case, other domains camelCase). It is the
  same class of issue as the input naming and will be unified in a later breaking release.
- **Target firmware build is unknown**; no firmware compatibility is claimed.
- **Live write validation is limited** to the seven object kinds exercised on the lab appliance;
  ambiguous-write reconciliation, a real `403` denial, bulk delete and interface/VPN mutations remain
  unverified.
- The remaining dogfooding findings (M9–M16, L1, L3, L6–L10) are recorded in
  [`docs/live-evidence/phase-4-feedback.md`](../live-evidence/phase-4-feedback.md) §10.

## 2. Rollback

The server is stateless: rolling back changes no appliance configuration and no stored data.

1. Re-deploy the previous image `ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0` (or the `0.4` alias).
2. If you run from source, check out `v0.4.0` and reinstall.
3. Clients that adopted the snake_case parameters must go back to the 0.4.0 spellings; the wire body
   is unchanged in both directions.

## 3. Publication checklist

- [x] `pyproject.toml` and `uv.lock` both say `0.5.0`; `uv lock --check` passes.
- [x] `CHANGELOG.md` has the `[0.5.0]` entry; `README.md` reflects 0.5.0.
- [x] `docs/API-COVERAGE.md` regenerates without a diff.
- [x] Independent review **APPROVE** (`docs/architecture/sophos-rest-api-redesign/PHASE-4-REVIEW.md`).
- [x] CI green on the merge commit (tests 3.11–3.14, lint, image build, dependency audit, semgrep).
- [x] Tag `v0.5.0` on the merge commit; the `release` job publishes `0.5.0`, `0.5` and `latest`.
- [x] GitHub release with these notes.
- [x] Post-publish: image tags present; the container build + STDIO smoke test ran green in CI on the
      same commit.

## 4. Approval record

The repository owner approved publishing 0.5.0 on 15 November 2026, after the independent review
returned APPROVE.
