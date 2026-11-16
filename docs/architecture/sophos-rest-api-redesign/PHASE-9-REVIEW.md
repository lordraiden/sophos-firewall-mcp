# Independent review — Phase 9 (0.7.1 patch release, PR #64)

| Field | Value |
|---|---|
| **Reviewer** | `reviewer9` (independent; did not write the code) |
| **Branch / HEAD** | `fix/mcp-0.7.1` @ `837fbb2` (base `origin/main` @ `30697a8`, `v0.7.0-7-g30697a8`) |
| **PR** | [#64](https://github.com/lordraiden/sophos-firewall-mcp/pull/64) |
| **Protocol** | [`execution/04-REVIEW-PROTOCOL.md`](execution/04-REVIEW-PROTOCOL.md) |
| **Inputs** | PR diff and description; [`MCP-STANDARDS-REVIEW-0.7.md`](MCP-STANDARDS-REVIEW-0.7.md); `CHANGELOG.md`, `README.md`, `docs/release/RELEASE-0.7.1.md`, `pyproject.toml`, `uv.lock`; `tools/__init__.py`, the four gated deletes, `server.py`, the tests |
| **Date** | 2026-11-16 |

## Verdict

**APPROVE**

The patch does what it claims. The NAT `position` fix is correct on both families, is caught by
pydantic before any request, and leaves the wire body of a call that already sent `position`
unchanged. H1 is closed honestly: the four delete descriptions now name the modern-path skip, the
skip is logged at `WARNING` with the action and target, and the legacy path still asks (34
confirmation tests pass, including accept/decline/cancel and the no-capability case). M1, M2, M3,
M4, M5, M7 and the cheap Lows each match the finding, each has a test that fails on the pre-fix
code, and none weakens the closed argument model (103 flat tools `additionalProperties: false`, 0
nested open objects), the sanitized errors (no caller value echoed) or the read-only guarantees (74
tools, 0 mutations). `serverInfo.description` publishes the registered count (112 write / 74
read-only) and the drift test compares it to `pyproject.toml`. Version 0.7.1 is in `pyproject.toml`,
`uv.lock` and `serverInfo.version`; the CHANGELOG, README and release pack carry no stale current
`152`/`0.7.0` claim. All gates are green and the diff is in scope.

No Critical or High finding. Nine Low findings follow: one description still omits one of the two
conditions under which the confirmation fires, one docstring overclaims what `_rejected_selector`
checks, the shared `ip_family` text is slightly contradictory on the union `const` variants, three
documents simplify the audit composites' omitted `ip_family` to "both families" (it is also `fqdn`
on `find_object_usage`), the README's catalog arithmetic mixes two protocol envelopes, the release
notes' rollback section contradicts the `position` change, the new `_lowlevel_server` private seam
is not in the pinned seam note and its wiring is not pinned by a test, the read-only
`serverInfo.description` is untested, and the PR description attributes the NAT fix to this PR when
it is already in the base. None blocks integration.

## Findings

| # | Severity | File:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| 1 | Low | `src/sophos_firewall_mcp/tools/__init__.py:238-244`; `README.md:484-490` | **`CONFIRMATION_NOTE` still omits one of the two conditions under which the confirmation fires.** The note says the call asks "when the transport can carry a server-initiated request (the legacy handshake path)", but `_client_can_elicit` also requires the client to declare the `elicitation` capability. A legacy client that declared no capability is not asked, so the note is false for that client class — the same class of defect H1 fixed for the modern path. | `_client_can_elicit` returns `False` when `capabilities.elicitation` is `None` (`tools/__init__.py:340-361`); `tests/test_destructive_confirmation.py:144` (`test_a_client_without_the_elicitation_capability_is_not_asked`) passes; `README.md:484-490` states both conditions ("when it declared the `elicitation` capability **and** the transport has a back-channel"). The note names only the transport. | Add "and the client declared the `elicitation` capability" to `CONFIRMATION_NOTE`, matching the README. |
| 2 | Low | `src/sophos_firewall_mcp/tools/__init__.py:1031-1038` | **The `_rejected_selector` docstring overclaims what the code checks.** It says "Only a field that is a literal on every variant is considered", but the implementation collects `Literal` values from whichever variants declare the field and never requires every variant to declare it. A future top-level union with a field that is a `Literal` on one variant and a plain `str` on another would reject a value the other variant accepts. | `_discriminator_values` (`:1014-1024`) returns the union of `Literal` values from the variants that have one; `_rejected_selector` (`:1041-1049`) uses it without an "every variant" check. I enumerated the nine top-level request unions (`firewall_rule_create/update`, `nat_rule_create/update`, `address_create/update`, `address_group_create/update`, `mac_address_create`): no mixed field exists today, so there is no current false rejection. | Either check that every variant declares the field as a `Literal`, or reword the docstring to "a field that is a literal on at least one variant". |
| 3 | Low | `src/sophos_firewall_mcp/tools/__init__.py:865-899`; published `address_create` `$defs` | **The shared `ip_family` description is contradictory on the union `const` variants.** The text says "'ipv4' or 'ipv6'", but each variant's `ip_family` is a `const` with a single value. A model reading `Ipv4AddressCreateIp.properties.ip_family` sees `const: "ipv4"` and a description that offers both values. | `address_create` `$defs.Ipv4AddressCreateIp.properties.ip_family` = `{"const": "ipv4", "title": "Ip Family", "type": "string", "description": "IP family of the collection: 'ipv4' or 'ipv6'. Required: the two collections are separate, so the family is never inferred."}`; `_describe_ip_family` applies the shared text to every `$defs` definition (`:891-894`). The M2 finding only asked for the 32 root-level tools; the union-variant extension is the PR's own choice (`tools/__init__.py:875-876`). | Use a variant-specific description (e.g., "Selects the ipv4 variant") or omit the description on the `const`. |
| 4 | Low | `README.md:236,245`; `CHANGELOG.md:48`; `docs/release/RELEASE-0.7.1.md:83`; `src/sophos_firewall_mcp/tools/__init__.py:875-876` | **The docs say the audit composites' omitted `ip_family` means "both families", but `find_object_usage` also accepts `fqdn` and omitting it means all.** The M2 finding itself noted "`fqdn` on `find_object_usage`". | Published `find_object_usage.input_schema.properties.ip_family` = `{"enum": ["ipv4","ipv6","fqdn"], "description": "Narrow address and address-group lookups to one family; omit for all."}`; `MCP-STANDARDS-REVIEW-0.7.md:131` ("optional, 'both' when omitted, `fqdn` on `find_object_usage`"). The three docs say "omitting the field means 'both families'". | Say "both families (and `fqdn` on `find_object_usage`)" or "all families". |
| 5 | Low | `README.md:257-259` | **The README's catalog arithmetic mixes two protocol envelopes.** It adds the 0.7.1 modern-era delta (2,882 B) to the 0.7.0 legacy-era wire line (622,787 B), so the implied total (625,669 B) reproduces neither HEAD line. | Measured over STDIO at HEAD: legacy `tools/list` line = **625,824 B**, modern (`_meta`) = **626,255 B**. 0.7.0: legacy = 622,787 B (canonical, `CHANGELOG.md:103`), modern = 623,373 B (`MCP-STANDARDS-REVIEW-0.7.md:204`). Legacy delta = 3,037 B; modern delta = 2,882 B. The README's "622,787 + about 2.9 KB" mixes the legacy baseline with the modern delta. | State the baseline and the delta from the same era, or say "about 3.0 KB" for the legacy line. |
| 6 | Low | `docs/release/RELEASE-0.7.1.md:162-163` | **The rollback section contradicts the `position` change.** It says "The tool names, the arguments, the wire body and the output payload are identical in both releases", but §1.2 says `nat_rule_create`'s `position` becomes required in 0.7.1. The arguments are not identical. | `RELEASE-0.7.1.md:30-47` ("Behaviour change: `nat_rule_create` requires `position`") vs `:162-163`; `CHANGELOG.md:10-11` correctly says "One input becomes required". | Say "the tool names, the wire body and the output payload are identical; the only argument change is that `position` is required". |
| 7 | Low | `src/sophos_firewall_mcp/server.py:334-340`; `src/sophos_firewall_mcp/tools/__init__.py:641-660` | **The new `_lowlevel_server` private seam is not in the pinned seam note, and its wiring is not pinned by a test.** `create_server` writes `server._lowlevel_server.description`; the seam note lists only `MCPServer._tool_manager`, `Tool.fn_metadata.arg_model` and `Tool.parameters`. The drift test passes with a fresh install even if the assignment is a no-op, so the substitution wiring is not pinned. | `server.py:339-341`; seam note `tools/__init__.py:641-660`; `tests/test_server.py:397` (`test_server_info_description_matches_the_declared_summary`) passes with a fresh install (112) whether or not the assignment runs. I proved the wiring works by monkeypatching `_package_identity` to a stale "152 typed tools" summary and observing the published description "112 typed tools", but no committed test does that. | Add `MCPServer._lowlevel_server.description` to the seam note and add a test that patches the identity to a stale summary and asserts the published description. |
| 8 | Low | `tests/test_server.py:397-414` | **The read-only `serverInfo.description` (74) is not pinned by a test.** The drift test uses the default (write) mode; the read-only mode publishes "74 typed tools" but no test asserts it. | `create_server(make_settings(read_only_mode=True))` → `serverInfo.description` "... 74 typed tools ..." (measured); `tests/test_server.py:616` tests the read-only tool list, not the description. | Add a read-only assertion to the drift test. |
| 9 | Low | PR #64 description; `git log origin/main` | **The PR description attributes the NAT `position` fix to this PR, but the fix is in the base.** The description says 0.7.1 "closes ... plus the NAT position fix found by the live probe", but `fc5324a fix(nat): require position on NAT rule create` is an ancestor of `origin/main` and of HEAD; the PR diff does not contain it. The release notes are correct for the 0.7.1 release delta (the fix is between `v0.7.0` and the 0.7.1 tag), but a reviewer reading only the diff cannot see the fix. | `git merge-base --is-ancestor fc5324a origin/main` → YES; `git diff --stat origin/main...HEAD` has no `models/nat.py`; `git describe --tags origin/main` → `v0.7.0-7-g30697a8`. | State in the PR description that the fix landed in `main` before the branch and is part of the 0.7.1 release delta, not of this PR's diff. |

## Verified

All commands were run in this worktree at `837fbb2`; nothing below is taken from the PR text.

- **Gates green.** `pytest -q` → **1254 passed, 100 skipped** (207.5 s). `mypy src` → *"Success: no
  issues found in 28 source files"*. `flake8 src tests` → clean. `black --check src tests` → *"52
  files would be left unchanged"* (54 with `scripts`). `python scripts/generate_coverage.py --check`
  → *"docs/API-COVERAGE.md is up to date"*. `uv lock --check` → *"Resolved 55 packages"*.
- **NAT `position` fix.** `_NatRuleCreateBase.position` is a required `NatRulePosition`
  (`models/nat.py:619-621`), shared by `NatRuleCreateIpv4Input` and `NatRuleCreateIpv6Input`, so the
  published schema marks it required in both `$defs` variants. A create without it is rejected by
  pydantic before any I/O: `nat_rule_create` with the six contract fields but no `position` →
  `invalid arguments: position is required`. A create that already sent `position` sends the same
  body: `test_create_ipv6_sends_the_position_the_appliance_requires` asserts
  `body["position"] == "top"`; the adapter's `model_dump(by_alias=True, exclude_unset=True,
  exclude_none=True, exclude={"ip_family"})` includes it because it is now always set. The fix is in
  the base (`fc5324a`), not in this PR's diff (finding 9).
- **H1.** The four gated descriptions carry `CONFIRMATION_NOTE` (`firewall_rules.py:560`,
  `nat_rules.py:356`, `users_auth.py:410`, `network.py:410`); the note names the
  `2026-07-28` skip. `confirm_destructive` logs `WARNING` "confirmation skipped: <action> <target>
  proceeds without asking the client ..." on `NoBackChannelError` (`tools/__init__.py:394-404`). The
  legacy path still asks: `tests/test_destructive_confirmation.py` → **34 passed**, including
  accept/decline/cancel, the no-capability case, the `url`-only case, the empty-`{}` case, and the
  modern-path warning (`caplog` asserts "confirmation skipped", the action and the target).
- **M1.** 11/11 PATCH-merge updates publish `destructiveHint: true` and `idempotentHint: true`
  (`address_update`, `address_update_fqdn`, `address_group_update`, `address_group_update_fqdn`,
  `firewall_rule_update`, `mac_address_update`, `nat_rule_update`, `network_interface_update_vlan`,
  `network_user_update`, `service_update`, `service_group_update`); no read-only tool declares write
  hints.
- **M2.** 32 root-level required `ip_family` properties + 22 union-variant definitions = **54
  occurrences, all equal to `IP_FAMILY_DESCRIPTION`** (0 mismatches). The three audit composites keep
  their own optional descriptions (`audit_firewall_rules`, `explain_connectivity`,
  `find_object_usage`).
- **M3.** `serverInfo.description` = "... **112 typed tools** ..." in write mode and "... **74 typed
  tools** ..." in read-only mode; `serverInfo.version` = `0.7.1`; the drift test compares the
  description to `project.description` in `pyproject.toml`. A stale identity ("152 typed tools")
  publishes "112 typed tools" (proved by monkeypatching `_package_identity`).
- **M4.** `prompts/get` → `-32602` for an unknown prompt ("Unknown prompt: nope"), missing arguments
  ("Missing required arguments: {...}") and a render failure ("Error rendering prompt
  explain_flow"); valid prompts still render (`audit_firewall`, `find_unused_objects`,
  `explain_flow`).
- **M5.** `elicitation: {}` → asked (`test_an_empty_elicitation_object_counts_as_form_mode`); a
  `url`-only client → not asked; no capability → not asked.
- **M7.** A bad `ip_family` on `address_create`, `address_update`, `address_group_create`,
  `address_group_update`, `nat_rule_update` and `firewall_rule_update` → `ip_family must be one of
  'ipv4', 'ipv6'`; a bad `type` → `type must be one of 'ipv4Address', ...`; a valid `type` with a
  mismatched `ip_family` → `ip_family must be one of 'ipv4'`.
- **L5.** 0 tools publish `annotations.title`; every tool still publishes a tool-level `title`.
- **L7.** `INSTRUCTIONS` names `sophos://conventions` and the three prompts (`audit_firewall`,
  `explain_flow`, `find_unused_objects`).
- **L9.** `_DestructiveConfirmation.model_json_schema()["description"]` is plain prose; no `:func:`,
  "Elicitation schemas" or "primitive".
- **L10.** 6/6 `_ipv4` IPsec tools carry "The API has no IPv6 counterpart".
- **Closed model.** 103 flat tools publish root `additionalProperties: false`; 0 nested open objects
  in any input schema; the 9 union tools keep closed `$defs` variants.
- **Sanitized errors.** `_rejected_selector` echoes only the accepted values, never the caller's
  value; the flat-tool path still reports `bogus is not an accepted argument; accepted arguments are
  ...`.
- **Read-only.** `SOPHOS_READ_ONLY_MODE=true` → **74 tools, 0 mutations**.
- **Version and docs.** `pyproject.toml` 0.7.1, `uv.lock` 0.7.1, `serverInfo.version` 0.7.1. No
  stale current "152 typed tools" claim: the remaining `152` occurrences are historical (0.7.0
  release notes, the M3 description of the old defect, the 0.7.0 catalog delta). The release pack is
  "prepared, not published"; the approval record is "Not approved yet"; the independent-review and
  CI checkboxes are unchecked.
- **Scope and git.** `git diff --stat origin/main...HEAD` touches only the expected 19 files (code,
  tests, CHANGELOG, README, release notes, `pyproject.toml`, `uv.lock`). The three commits are scoped:
  `cb748c0` (code + tests), `731c4ad` (docs), `837fbb2` (version bump). No untracked files, no new
  `TODO`/`FIXME` in the diff.
- **Scope counts.** `ADR-001 §10`, `API-COVERAGE.md §4` and `scripts/coverage_curated.yaml` agree on
  **145 operations / 112 tools / 11 domains**; the generated coverage document is drift-free.

## Not verified

- **No live appliance.** I did not exercise a successful tool call or a NAT create against SFOS. The
  NAT `position` fix's live evidence is the commit message and the release notes, not re-run here.
- **The `mcp` 2.3.0 private seams.** `MCPServer._tool_manager` and the new
  `MCPServer._lowlevel_server.description` are pinned by tests and a comment; I cannot predict an SDK
  change. The failure modes are loud (`RuntimeError`/`AttributeError` at registration or startup),
  not silent data loss.
- **CI.** I ran the local gates only; the workflows (tests 3.11–3.14, lint, image build, dependency
  audit, semgrep) were not run here.
- **Docker and the live workflow.** I read `Dockerfile`, `docker-compose.yml` and the workflows but
  did not build or run them.
- **The protocol checklist's "145 operations / 152 MCP tools".** The checklist is stale relative to
  the 0.7.0 IPv4/IPv6 collapse: `ADR-001 §10` and `API-COVERAGE.md §4` now say 112 tools, and the
  measured surface is 112. I verified the current 112-tool counts, not the checklist's 152.

## Residual risks

- **`_prompt_error_middleware` maps every "Error rendering prompt" `ValueError` to `-32602`.** A
  server-side template bug would be misclassified as a client error (the spec would call it
  `-32603`). The M4 finding's recommendation asked for this mapping, so it is deliberate; the
  middleware cannot distinguish a bad-argument render failure from a bug.
- **`_rejected_selector` latent false rejection.** If a future top-level union has a field that is a
  `Literal` on one variant and a plain `str` on another, a value the `str` variant accepts would be
  rejected by name (finding 2). No current union has such a field.
- **The `_lowlevel_server` seam and the read-only description are not pinned** (findings 7 and 8). A
  future SDK change that makes the assignment a no-op, or a regression in the read-only count, would
  not be caught by the current tests.
- **The catalog is still ~156k tokens with no `nextCursor`.** The 0.7.1 change adds ~2.9 KB of
  descriptions, so the context-cost problem is unchanged; the output-schema trim and pagination are
  explicitly out of scope.
- **The MRTR round trip is deferred to 0.8.0.** The modern-path confirmation remains skipped; it is
  now documented and logged, but the safety affordance is still absent on the protocol era the
  server advertises.
- **The `serverInfo.description` substitution depends on the installed summary containing the phrase
  "N typed tools".** A summary without that phrase would not be corrected; the drift test would
  catch a prose change, but not a count-only change in a different phrasing.
