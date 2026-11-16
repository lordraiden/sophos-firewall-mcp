# Release 0.7.1 — the 0.7.0 standards-review findings

**Status:** prepared, **not published** — pending explicit owner approval. **Previous release:** 0.7.0
(the IPv4/IPv6 collapse and flat arguments). **Target appliance:** Sophos Firewall 23, **SFOS 23.0.0
GA-Build371**.

## 1. Release notes

### 1.1 Summary

0.7.1 is a patch release. It closes the **High** finding and the cheap findings of the independent
MCP standards review of 0.7.0
([`MCP-STANDARDS-REVIEW-0.7.md`](../architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW-0.7.md)),
and it fixes one input-contract defect found on the appliance.

- **No tool is renamed and no argument is removed.** The surface stays at **112 tools** (107
  one-to-one + 5 composites): **74 read-only / 38 mutations**, 7 no-argument / 105 argument tools.
- **The wire body is unchanged for every call that already worked.** No request or response payload
  changes; the only input-contract change is that `nat_rule_create` now requires `position`, which the
  appliance already rejected a create without.
- **One behaviour change** (§1.2) and **eleven findings closed** (§1.3).
- The catalog grows by about **2.9 KB of descriptions** (the shared `ip_family` text, the IPsec notes
  and the `address_create` sentence, less the dropped `annotations.title`). The tool count and the
  read-only/mutation split are unchanged.

The release is a patch, so a client that worked against 0.7.0 keeps working, with one exception: a
`nat_rule_create` call that omitted `position` was already failing with a generic `400` and now fails
earlier with a clear argument error. A caller that sent `position` is unaffected.

### 1.2 Behaviour change: `nat_rule_create` requires `position`

The appliance rejects `POST /nat/rules/ipv4` and `POST /nat/rules/ipv6` without `position` with
`400 invalidRequest` ("Invalid position."), for both families and every match/translation variant. The
OpenAPI document does not list `position` as required, so 0.7.0 published it as optional and the
adapter omitted it: **every create that did not send `position` failed with a generic `400`**.

0.7.1 makes `position` a required input on both create variants, like `firewall_rule_create`, and the
adapter always sends it:

- accepted values: `top`, `bottom`, `after`, `before`;
- `after` and `before` still require `reference_item` (the anchor rule), and that is validated before
  any request is sent;
- a caller that omits `position` now gets a clear argument error instead of a `400` from the
  appliance.

Verified live against SFOS 23.0.0 GA-Build371: IPv4 and IPv6 creates with `position: "bottom"` return
`201`; a create without `position` is rejected by the tool before anything is sent.

### 1.3 Fixed

#### H1 — the four gated delete descriptions are honest about the confirmation

`firewall_rule_delete`, `nat_rule_delete`, `network_user_delete` and
`network_interface_delete_vlan` call `confirm_destructive` before touching the appliance. On the
modern (`2026-07-28`) per-request path, `mcp` 2.3.0 refuses a server-initiated request, so the
confirmation is skipped and the delete proceeds. The four descriptions said "the call first asks the
user to confirm", which is false on the protocol era the server advertises.

0.7.1 makes the description match the behaviour: the confirmation is **best-effort**, it fires on the
legacy handshake path where the transport can carry a server-initiated request, and on the
`2026-07-28` path it is skipped and the client's own confirmation UI is the only gate. The skip is no
longer silent: `confirm_destructive` logs a `WARNING` naming the action and the target, so an operator
can see a delete that ran without the question.

The real fix — the specification's `InputRequiredResult` round trip — is deliberately deferred to
**0.8.0** (§1.4).

#### M1 — `destructiveHint` is consistent for the PATCH-merge updates

All eleven update tools publish `destructiveHint: true`. The nine object, user and VLAN updates were
`false` while the two rule updates were already `true`, so the same operation class was classified two
ways. A JSON Merge Patch overwrites stored values, so it is not an additive update.

#### M2 — one shared `ip_family` description

Every required `ip_family` publishes the same sentence in `inputSchema`:

> *"IP family of the collection: 'ipv4' or 'ipv6'. Required: the two collections are separate, so the
> family is never inferred."*

That covers the 32 tools that require it — including the six firewall tools, which published no
description at all — and the 8 union tools that carry it (22 variant definitions). The three audit
composites keep their own optional description, where omitting the field means "both families".

#### M3 — `serverInfo.description` publishes the real tool count

The description substitutes the number of tools the server actually registered (112, or 74 in
read-only mode) instead of the installed distribution's summary, so a stale editable install can no
longer publish "152 typed tools" against a 112-tool surface. A drift test compares the published
description with `project.description` in `pyproject.toml`.

#### M4 — `prompts/get` returns `-32602` for a caller-fixable failure

An unknown prompt, missing or invalid arguments, or a render failure is reported as invalid params
instead of an internal error, matching the specification's prompts error handling and the
`resources/read` path.

#### M5 — `elicitation: {}` counts as form-mode support

The specification defines the empty capabilities object as equivalent to declaring form mode, so the
confirmation gate now fires for that client generation instead of treating it as unable to answer. A
`url`-only client is still not asked, because it cannot answer a boolean question.

#### M7 — a bad union selector is reported by name

`address_create` with `ip_family: "ipv5"` now reports `ip_family must be one of 'ipv4', 'ipv6'`
instead of "type is required", because the union error names a selector field the caller actually sent
with a value no variant accepts. The `address_create` description also states that `type` selects the
variant and must match `ip_family`.

#### L5 — `annotations.title` is dropped

The tool-level `title` already wins the specification's display precedence, so the duplicate string is
no longer published on any of the 112 tools.

#### L7 — `INSTRUCTIONS` names the resources and prompts

A model that reads only `instructions` now learns that `sophos://conventions` exists and that
`audit_firewall`, `explain_flow` and `find_unused_objects` carry the three analysis workflows.

#### L9 — the elicitation schema is plain prose

The confirmation form's `requestedSchema.description` is user-facing text instead of the internal
`_DestructiveConfirmation` docstring.

#### L10 — the six IPv4-only IPsec tools say so

`ipsec_connection_list_ipv4`, `ipsec_live_connection_list_ipv4`,
`ipsec_policy_based_connection_get_ipv4`, `ipsec_policy_based_connection_list_ipv4`,
`ipsec_route_based_connection_get_ipv4` and `ipsec_route_based_connection_list_ipv4` now state "The
API has no IPv6 counterpart", so a model does not look for an `_ipv6` sibling that does not exist.

### 1.4 Known limitations

- **The MRTR round trip is 0.8.0.** The confirmation still cannot fire on the `2026-07-28` per-request
  path: `mcp` 2.3.0 refuses a standalone server-to-client request there, and the specification's
  `InputRequiredResult` round trip would change every handler signature. 0.7.1 makes the limitation
  visible — the descriptions say it and the skip is logged — instead of leaving it silent; the real fix
  is scheduled for 0.8.0.
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

## 2. Rollback to 0.7.0

The server is stateless: rolling back changes no appliance configuration and no stored data.

1. Re-deploy the previous image `ghcr.io/lordraiden/sophos-firewall-mcp:0.7.0`. Use the exact `0.7.0`
   tag, not the `0.7` alias: the alias moves to 0.7.1 when this release is published.
2. If you run from source, check out `v0.7.0` and reinstall.
3. No client change is required. 0.7.0 accepts `position` when it is sent, so a 0.7.1 caller that
   always sends it keeps working; a caller that omits it gets the 0.7.0 behaviour back — the create
   fails with a generic `400` from the appliance instead of a clear argument error.
4. The tool names, the arguments, the wire body and the output payload are identical in both releases;
   only the descriptions, the annotations and the `serverInfo` description differ.

## 3. Publication checklist

- [x] `pyproject.toml` and `uv.lock` both say `0.7.1` (the Lead bumps them; this release pack does not
      touch either file).
- [x] `CHANGELOG.md` has the `[0.7.1]` entry; `README.md` reflects 0.7.1 (this PR).
- [x] Local gates green on this branch: `pytest -q` → **1254 passed, 100 skipped**; `mypy src` → clean;
      `flake8 src tests` → clean; `black --check src tests` → clean.
- [ ] Independent review **APPROVE**.
- [ ] CI green on the merge commit (tests 3.11–3.14, lint, image build, dependency audit, semgrep).
- [ ] Tag `v0.7.1` on the merge commit; the `release` job publishes `0.7.1`, `0.7` and `latest`.
- [ ] GitHub release with these notes.
- [ ] Post-publish: image tags present; the container build + STDIO smoke test ran green in CI on the
      same commit.

## 4. Approval record

**Not approved yet.** 0.7.1 is prepared on `fix/mcp-0.7.1` and must not be tagged, published or
promoted to `latest` without explicit owner approval. The approval is recorded here once given,
together with the independent review verdict.
