# Agent-Team Execution Plan — MCP Reliability and Operations Issues (#54–#63)

**Status:** execution plan; implementation not started by this document  
**Prepared:** 16 November 2026  
**Repository:** [lordraiden/sophos-firewall-mcp](https://github.com/lordraiden/sophos-firewall-mcp)  
**Scope:** the ten currently open GitHub issues #54–#63, and only those issues

## 1. Mission and scope boundary

This plan coordinates the implementation, review and integration of the ten open issues listed in §3. The target is to improve the reliability, MCP contract, discoverability, configuration and operational safety of the existing Sophos Firewall MCP server.

**The REST API migration and the redesign that produced the current REST-based server are already completed. They are not part of this execution.** The current repository implementation is the baseline. Do not reopen, repeat, extend or reinterpret the historical XML-to-REST migration, the original API coverage exercise, or the old migration phases as work for this plan.

The execution has these deliverables:

1. Each issue is implemented against its own acceptance criteria and current repository code.
2. Changes are covered by focused regression tests and the repository's complete quality gates.
3. Changes are reviewed independently, integrated through pull requests and merged only after the Lead has validated them.
4. Every issue is either closed by its merged implementation or explicitly left open with a precise, evidence-based blocker.

### Included

- MCP destructive-operation confirmation using the currently advertised protocol.
- Correct mutation annotations.
- Model-facing tool schemas, descriptions and discovery guidance.
- Configurable selection of tool domains.
- Reduction of the MCP tool catalog payload without weakening structured results.
- A truthful, tested MCP SDK compatibility range.
- Correct JSON-RPC invalid-parameter handling for tool and prompt requests.
- Accurate package/server/repository metadata.
- Safer Docker Compose defaults and correct concurrency configuration.
- An explicit invocation-rate policy appropriate to the local STDIO deployment.

### Explicitly excluded

- Reimplementing or redesigning the Sophos REST client or API integration.
- Repeating the old migration, OpenAPI audit or domain-tool implementation work.
- Adding new Sophos API coverage or expanding the number of supported operations.
- Adding an HTTP transport, multi-user server, authentication gateway or new deployment architecture.
- Logs, Syslog, event ingestion, SIEM, log storage or log-query features.
- Live destructive tests against a production firewall.
- Unrequested release publication, Docker image promotion, tag creation or version announcement.
- Broad refactors unrelated to closing one of the ten issues.

Any incidental defect discovered outside this scope must be recorded and reported separately. Do not silently expand the task or create more issues without the owner's approval.

## 2. Source of truth and execution principles

### 2.1 Authority order

Use the following order when resolving requirements:

1. The current code and tests on the verified starting commit.
2. The individual GitHub issue body and its acceptance criteria.
3. The applicable official MCP specification and SDK documentation linked by the issue.
4. The existing repository conventions, CI workflows and project configuration.
5. This document for sequencing, ownership, collaboration and integration policy.

This document is an orchestration plan, not a replacement for the issue bodies. Do not copy the full acceptance criteria into this file and then let the two versions drift. Each issue remains the canonical implementation contract.

If an issue statement conflicts with current code, the official protocol/specification, or a newer verified SDK contract, stop that specific implementation, document the discrepancy with evidence, and ask the Lead to resolve it before changing behavior.

### 2.2 Required engineering approach

- Inspect before changing. Establish the actual behavior using code, tests and protocol-level observations.
- Prefer supported public SDK APIs. Where private SDK internals remain unavoidable, isolate them behind one compatibility seam and pin only versions actually verified.
- Make the smallest change that closes the issue. Avoid generic frameworks, new abstractions or dependencies without a demonstrated need.
- Preserve backwards compatibility unless the issue explicitly authorizes a behavior change.
- Treat MCP annotations and tool filtering as client guidance/surface reduction, not as authorization. Sophos permissions remain the effective appliance-side authorization boundary.
- Never weaken the no-blind-retry policy for mutations.
- Do not claim a protocol guarantee based only on a helper-level unit test. Exercise the real MCP dispatch/STDIO path where the issue requires it.
- Do not add hidden constants, undocumented bypasses, permissive fallbacks or silent typo handling.
- Keep user-facing error messages actionable and sanitized. Do not expose secrets, internal tracebacks or raw untrusted appliance content as instructions.
- Make test claims only for commands actually executed and results actually observed.

## 3. Issue inventory

All ten issues were confirmed open when this plan was prepared. Re-check their state and bodies at execution time.

| Order | Issue | Priority | Implementation objective |
|---:|---|---|---|
| 01 | [#54 — MCP MRTR confirmations](https://github.com/lordraiden/sophos-firewall-mcp/issues/54) | P0 | Implement a protocol-correct, fail-closed confirmation flow for the four destructive operations. |
| 02 | [#55 — mutation destructiveHint audit](https://github.com/lordraiden/sophos-firewall-mcp/issues/55) | P1 | Review and test the annotation semantics of all mutation tools. |
| 03 | [#56 — model-facing schemas and discovery](https://github.com/lordraiden/sophos-firewall-mcp/issues/56) | P1 | Make tool inputs, variants, getter outputs and discovery guidance self-explanatory and accurate. |
| 04 | [#57 — configurable domain selection](https://github.com/lordraiden/sophos-firewall-mcp/issues/57) | P1 | Add a validated domain allowlist while preserving the complete default surface. |
| 05 | [#58 — reduce tools/list payload](https://github.com/lordraiden/sophos-firewall-mcp/issues/58) | P1 | Reduce catalog size through measured, semantics-preserving changes and verified discovery behavior. |
| 06 | [#59 — MCP SDK compatibility range](https://github.com/lordraiden/sophos-firewall-mcp/issues/59) | P1 | Align dependency metadata with the SDK surface the implementation actually uses and tests. |
| 07 | [#60 — JSON-RPC Invalid params](https://github.com/lordraiden/sophos-firewall-mcp/issues/60) | P2 | Map invalid tool/prompt requests to -32602 without misclassifying execution or internal failures. |
| 08 | [#61 — server/package metadata](https://github.com/lordraiden/sophos-firewall-mcp/issues/61) | P2 | Keep runtime identity, package metadata, README and repository description accurate, including filtered instances. |
| 09 | [#62 — Compose defaults and concurrency](https://github.com/lordraiden/sophos-firewall-mcp/issues/62) | P2 | Make the supplied Compose example read-only by default and pass documented runtime settings correctly. |
| 10 | [#63 — invocation-rate policy](https://github.com/lordraiden/sophos-firewall-mcp/issues/63) | P2 | Record and implement, only if justified, a rate policy distinct from the existing concurrency limit. |

### 3.1 Issue-specific cautions

These are coordination reminders, not substitutes for the full issue criteria:

- **#54:** The current legacy confirmation attempt must never degrade into an unconfirmed write. The four affected operations are firewall rule delete, NAT rule delete, network user delete and VLAN interface delete. A declined, missing, stale, malformed, cancelled or unsupported confirmation must not reach Sophos.
- **#55:** Audit all 38 mutations, not merely the nine PATCH examples. Keep destructive and idempotent semantics independent.
- **#56:** Test the actual published schemas/descriptions. Include required and optional ip_family differences, the address union selector, IPv4-only IPsec explanations, getter result descriptions, mutually exclusive MAC-address variants and compact discovery guidance.
- **#57:** An unset domain setting must preserve the full existing default surface. Invalid identifiers must fail at startup. Audit composites must not be registered without their adapter dependencies. Read-only mode must compose with domain selection.
- **#58:** Measure the serialized catalog before and after. Preserve Pydantic runtime validation, output schemas where required, structuredContent and content compatibility. Do not claim success by globally deleting outputSchema or fabricating pagination.
- **#59:** Verify the exact public/private SDK boundary against the selected package versions. Keep any private compatibility seam centralized, and test a clean install rather than relying only on the developer's editable environment.
- **#60:** Convert only expected request/argument errors to JSON-RPC -32602. Valid tool execution failures remain tool errors; genuine internal failures remain -32603.
- **#61:** Avoid a fixed tool count in server metadata if domain filtering can change the registered surface. Check clean package installation metadata, not only stale editable metadata.
- **#62:** The Compose example must be read-only by default without silently changing the application's existing default. Preserve mounted secrets and existing container hardening. Evaluate restart behavior against the actual STDIO launch model.
- **#63:** Concurrency and invocation rate are different controls. The final decision may be that a separate rate limiter is unnecessary for this local, one-client-per-process STDIO model; if so, document the threat-model reasoning and residual risk explicitly. Do not add an arbitrary limiter merely to satisfy the issue title.

## 4. Dependency graph and execution order

The following dependencies are deliberate. They prevent agents from editing the same contract in contradictory ways and ensure later decisions use the earlier implementation.

- **#59 → #54:** establish and test the supported SDK baseline before relying on its MRTR/resolution support.
- **#54 → #55:** finish the destructive confirmation path before the mutation annotation audit and final description pass.
- **#55 → #56:** keep the mutation contract/description changes ordered before the broader model-facing description pass.
- **#59 + #57 → #60:** protocol error handling must be based on the supported SDK dispatch path and the final dynamic prompt/resource registration model.
- **#57 → #61:** metadata must describe the real full or filtered registration model.
- **#56 + #57 → #58:** measure and document progressive discovery in the context of the final schemas and configurable domains.
- **#62 → #63:** first make the runtime configuration and concurrency mapping consistent; then decide whether an additional time-based limiter is needed.

Dependency graph:

- #59 → #54 → #55 → #56 → #58
- #59 + #57 → #60
- #57 → #61
- #62 → #63
- #57 is also a prerequisite for final #58 discovery guidance.

### 4.1 Suggested waves

At most three implementation agents may be actively writing at the same time. These waves assume each writer has an isolated worktree/branch. If that cannot be guaranteed, use the serialization fallback in §6.

| Wave | Work | Can start when |
|---|---|---|
| 0 — Baseline | Lead inspects repository state, issues, PRs, CI, available DSH tools and clean-install/test commands. Reviewer prepares a read-only risk map. | Immediately |
| 1 — Foundations | #59, #57 and #62 | After the baseline; each in a separate worktree. |
| 2 — Dependent safety and identity | #54, #61 and #63 | Respectively after #59, #57 and #62 are merged or the Lead has integrated their verified changes. |
| 3 — Contract correctness | #55 and #60 | #55 after #54; #60 after #59 and #57. |
| 4 — Model-facing contract | #56 | After #55; coordinate resource/instruction changes with #57 and #60. |
| 5 — Catalog optimization | #58 | After #56 and #57; use the finalized catalog as the comparison baseline. |
| 6 — Final integration | Independent end-to-end review, full CI, issue reconciliation and final report. | After all implementation PRs are merged. |

A wave is a scheduling guide, not permission to violate a dependency. If a predecessor PR is delayed or fails review, do not start its dependent implementation against an obsolete assumption. Read-only analysis/test preparation may continue while waiting.

### 4.2 One issue, one implementation PR by default

Open one focused PR per issue, using the title prefix/order from the issue inventory. A single PR may close multiple issues only if the implementation is genuinely inseparable and the Lead records why separate PRs would create duplicate or unsafe intermediate behavior. Do not bundle unrelated cleanup into a PR.

Use branch names such as:

- agent/issue-59-sdk-compatibility
- agent/issue-57-domain-selection
- agent/issue-62-compose-safety
- agent/issue-54-mrtr-confirmations

Dependent work must be based on the latest integrated main. Before a dependent PR is opened, update/rebase its branch onto the current target and rerun the affected tests. Do not leave a stack of hidden, unreviewed dependent commits.

## 5. DSH Agent Teams operating model

### 5.1 Root Lead responsibilities

The root session is the **Team Lead and sole integration authority**. It owns:

- Repository baseline and protection of pre-existing user changes.
- The shared task board, dependencies, task ownership and wave transitions.
- Team member creation, explicit launch, messaging, waiting and interruption.
- Assignment of bounded tasks with file-scope hints and acceptance criteria.
- PR creation/integration review, conflict resolution and merge decisions.
- Full-suite/CI verification and final issue reconciliation.

The Lead does not delegate away final review or merge authority. An implementation agent must never merge its own PR.

### 5.2 Suggested flat roster

Use a flat team. Avoid nested agents unless a specific implementation task demonstrably needs a specialist child.

| Agent name | Responsibility | Issues |
|---|---|---|
| sdk-protocol | SDK compatibility, MRTR confirmation flow and JSON-RPC request error mapping | #59, #54, #60 (in dependency order) |
| tool-contract | Mutation annotations, input/output descriptions, validation feedback and catalog optimization | #55, #56, #58 (in dependency order) |
| surface-config | Domain selection, dependencies, filtered discovery and accurate identity | #57, #61 |
| runtime-safety | Compose/STDIO defaults, concurrency mapping and invocation-rate policy | #62, #63 |
| independent-reviewer | Read-only review of design, diffs, issue coverage, security and test evidence | All PRs |

The Lead may adjust the roster if actual tool availability, model capability or file ownership requires it. Keep the owner of each task explicit. The independent reviewer must not edit implementation files during a review; requested corrections return to the owning implementer or Lead.

### 5.3 Task board requirements

Create one board task per issue. Each task must include:

- Issue number and canonical GitHub URL.
- Goal and a short restatement of the acceptance boundary.
- Explicit owner selected from the live roster returned by DSH.
- Dependencies by task ID.
- Expected write scopes (directories/files where known).
- Worktree/branch name and base commit.
- Test commands to run or discover.
- PR URL, review state and CI state once available.
- A completion summary and any remaining caveat.

Use the board's current revision on every update. If a compare-and-set update is rejected as stale, re-read the task and update from the current revision; do not retry a stale mutation blindly.

**Important DSH behavior:** creating or assigning a task does not itself start the owner. The Lead must explicitly launch/message the agent and verify that work has started. Use the actual available tool names and schemas surfaced by this DSH session; do not invent tool names or assume an unavailable package is installed.

### 5.4 Team mode and tool availability

At kickoff:

1. Verify that Agent Teams is enabled on the root session.
2. Verify that both the Team task-board package and the normal subagent controls are actually exposed.
3. Check that the session can create, list, message, wait for and interrupt teammates, and create/update/list/get tasks.
4. If Team mode is disabled, enable it through the supported session setting. Do not simulate a Team with multiple unrelated chats.
5. If any required capability is unavailable, tell the Lead exactly what is missing and use the safest supported fallback. Do not claim that agents ran or tasks were delegated when they were not.

Official DSH references:
- [Agent Teams package](https://github.com/deepseek-ai/deepseek-harness/tree/master/packages/team/agent-team)
- [Team task tools and collaboration policy](https://github.com/deepseek-ai/deepseek-harness/tree/master/packages/team/tool-agent-team)
- [Subagent subsystem](https://deepseek-harness.github.io/deepseek-harness/en/reference/subsystems/subagent)
- [Tool catalog, including worktree availability](https://deepseek-harness.github.io/deepseek-harness/en/reference/tool-catalog)

## 6. Filesystem isolation and safe parallelism

This is a critical execution constraint.

DSH Agent Team members normally share a working directory and filesystem. Team task write scopes are **advisory warnings, not filesystem locks**. A task board does not prevent two agents from editing the same file. Shell commands, formatters and generators are not made safe by assigning different task owners.

### Preferred mode: isolated worktrees

1. Inspect the source checkout's git status first. Do not stash, reset, clean, checkout over, or discard user-owned changes.
2. Fetch and identify the exact current target commit. Do not assume that the default branch or local main is up to date.
3. Check whether the DSH worktree capability (for example, create_worktree) is actually exposed and usable.
4. Create one isolated worktree and branch per active write task, based on the pinned clean target commit. Confirm its path and branch before launching the worker.
5. Remember that a new worktree is based on committed files: uncommitted and untracked source-checkout files are not copied into it.
6. Pass the exact worktree path to the relevant agent and verify that commands run there, not in the shared checkout.
7. Limit active writers to three. Keep the independent reviewer read-only.
8. Integrate PRs in dependency order. Refresh/rebase dependent work onto the latest main and resolve conflicts deliberately.

The official DSH worktree tool is a separately enabled capability; do not assume it exists merely because Agent Teams is enabled.

### Fallback: shared checkout

If isolated worktrees cannot be created and verified:

- Allow only one implementation agent to write at a time.
- Other agents may perform read-only investigation, design review or test planning.
- Do not let agents edit disjoint-looking files concurrently unless the Lead has confirmed they cannot overlap through imports, generated files, formatting or shared tests.
- Do not use Git branches alone as evidence of isolation: two sessions in one checkout still see the same working tree.

### Conflict handling

When a conflict occurs, the Lead must inspect both changes and their issue intent. Never resolve conflicts by accepting an entire side without reviewing semantics. Re-run the tests for both issues after resolution and record the resolution in the relevant PR/task.

## 7. Implementation and PR protocol

For each issue:

1. Read the complete current issue body and inspect every referenced code/test file.
2. Reproduce the relevant existing behavior or defect before editing.
3. Confirm the exact target branch/commit and the task's dependencies.
4. Implement only the required behavior, with focused tests.
5. Run formatter, linter, type checks and targeted tests using the repository's actual documented/CI commands.
6. Inspect the complete diff for unrelated changes, accidental generated-file churn, secrets, and changes outside the task scope.
7. Ask the independent reviewer to review the diff against the issue body and relevant official specifications.
8. Correct review findings and rerun the relevant tests.
9. Open/update the PR with an issue reference (for example, Closes #54) and a complete test/evidence summary.
10. The Lead independently inspects the final diff and CI before merging.

Every PR description must contain:

- The issue(s) it closes and the observable defect/goal.
- The chosen implementation and why it is correct for the current SDK/protocol.
- Files or subsystems changed.
- Tests run, exact commands and pass/fail outcomes.
- Compatibility implications and any limitations.
- Reviewer findings and how they were addressed.
- Explicit confirmation that no out-of-scope migration/release work was included.

Use draft PRs while the implementation is incomplete. Do not enable auto-merge. Do not merge with failing, pending-required or skipped mandatory checks. If a check is unavailable, state why and obtain an explicit Lead decision rather than presenting the PR as fully verified.

## 8. Quality gates and issue-specific verification

### 8.1 Repository-wide gates

At kickoff, discover the exact quality commands from pyproject configuration, CI workflow files and contributor documentation. Do not guess command names or claim that an unconfigured tool was run.

At minimum, the final integration must verify:

- Complete Python test suite.
- Formatting and lint checks used by CI.
- Type/static checks used by CI, if configured.
- Dependency lock consistency and clean package installation.
- Security/dependency checks used by CI.
- Docker Compose configuration validation.
- MCP protocol behavior over the real STDIO transport.
- All required GitHub Actions checks on each PR and on the final integrated main.

A targeted test passing is not a substitute for the complete suite when the repository gate is available.

### 8.2 Minimum evidence by issue

| Issue | Required evidence at implementation/review |
|---|---|
| #54 | Tests exercise modern MRTR acceptance/resume, decline, cancellation, malformed/stale/mismatched state and unsupported/no-back-channel paths. Prove rejected or unsupported confirmation sends no POST/PATCH/DELETE. Verify exact target binding and at-most-once execution. |
| #55 | A test enumerates every registered mutation and pins explicit destructiveHint/idempotentHint semantics. Read-only tools must not inherit write hints. |
| #56 | Inspect actual tools/list output. Test field descriptions, selectors, accepted values, validation errors, getter descriptions, MAC variant conflict and instructions/resource/prompt discovery. |
| #57 | Test the complete default registration and each supported domain selection, unknown/empty/malformed values, audit dependencies and read-only composition. Verify filtered documentation does not claim excluded tools. |
| #58 | Record deterministic before/after serialized tools/list byte measurements, split by input schemas/output schemas/descriptions/envelope. Preserve structuredContent, output-schema correctness and content fallback. Verify pagination only if the supported SDK implements it correctly. |
| #59 | Clean install/build test, declared range/lock consistency, compatibility test for the exact SDK seam, and CI coverage of the supported version range. |
| #60 | Real STDIO tests for unknown tool/prompt names, missing/extra arguments, valid prompts, execution errors and genuine internal errors. Verify -32602 versus tool errors and -32603. |
| #61 | Clean installation confirms runtime serverInfo metadata equals canonical package metadata. Verify README/repository description and filtered instances do not advertise a false fixed tool count. |
| #62 | Compose defaults to no mutation tools, API key remains file-mounted, SOPHOS_MAX_CONCURRENCY is configurable, hardening remains intact, and STDIO lifecycle/restart semantics are accurately documented and tested. |
| #63 | Written threat-model decision distinguishes concurrency from invocation rate. If implemented, test deterministic boundaries, parallel calls, cancellation and shutdown. If not implemented, document rationale and residual risk without calling the semaphore a rate limiter. |

### 8.3 Cross-issue regression checks

The final review must specifically verify the interactions that can be broken by the combined work:

- MRTR resumption still works after SDK version constraints and server dispatch changes.
- No delete can proceed after an unsuccessful confirmation.
- Domain filtering cannot expose audit tools whose adapter dependencies are absent.
- Read-only mode and domain selection compose without leaking mutation tools.
- Resources, prompts, server instructions and identity metadata describe the actual registered surface.
- Catalog reduction preserves every required schema constraint and runtime structured result.
- Correct JSON-RPC request errors do not swallow genuine tool or server failures.
- Compose defaults remain safe while application-level backwards-compatible defaults remain unchanged.
- Concurrency limiting is not mislabeled as invocation-rate limiting.
- All STDIO output remains protocol-clean; diagnostics stay on stderr.

## 9. Security and operational constraints

- Never print, commit or include the Sophos API key, environment secrets, credentials or private appliance data in logs, fixtures, PRs or generated artifacts.
- Do not perform live firewall mutations as part of this task. Use unit, protocol and mocked HTTP tests. If a real appliance test is essential to resolve a question, stop and obtain explicit owner approval with a scoped disposable test plan.
- Do not add a permissive confirmation bypass to accommodate clients that cannot support the negotiated protocol.
- Do not treat MCP annotations, filtered tool registration or Compose defaults as the effective firewall authorization boundary. The Sophos administrator profile and network/API access controls remain authoritative.
- Do not change TLS verification, redirects, write retry policy or secret handling incidentally.
- Do not add a rate limiter without a documented algorithm, configured policy, cancellation behavior and measurable tests.
- Do not add telemetry, logs, Syslog, SIEM or remote HTTP exposure under these issues.

## 10. Integration and merge policy

The Lead merges only when all of the following are true:

- The PR closes the intended issue and matches its acceptance criteria.
- The independent reviewer has completed a substantive review.
- All review findings are resolved or explicitly accepted by the Lead with reasons.
- Focused and full required tests pass.
- Required CI checks are green.
- The diff contains no unrelated migration, release or refactor work.
- Dependent work has been rebased/integrated against the current target and re-tested.

Merge in dependency order. After each merge, verify the resulting main state and update the task board/issue. Do not close an issue merely because a PR was opened; close it only after the fix is merged and the acceptance criteria are satisfied.

If blocked:

1. Keep the issue open.
2. Record the blocker, exact evidence, affected dependency and attempted resolution.
3. State the smallest decision or owner action required.
4. Continue only with independent tasks whose assumptions are unaffected.

**Release boundary:** do not create a release tag, publish/promote a stable image, or announce a new version. This work closes implementation issues; release authorization remains a separate owner decision. Make a package version change only if a specific issue or required packaging contract demands it, and document the reason.

## 11. Completion criteria and final report

The execution is complete when:

- All ten issues have a verified outcome: merged and closed, or explicitly blocked with evidence and owner action.
- Every implementation PR has been reviewed and merged in dependency order.
- The final integrated main passes the repository's required CI and test gates.
- No destructive operation can bypass the correct confirmation path.
- Metadata, schemas, domain selection, catalog behavior and runtime configuration agree with the actual implementation.
- No release publication or out-of-scope migration work was performed.

The Lead's final report to the owner must be in Spanish and include:

1. A table of issues #54–#63 with final state, PR URL and merge commit where applicable.
2. Team members and the tasks each actually completed.
3. The key technical decisions, especially SDK support, MRTR, catalog size and the #63 rate-policy decision.
4. Exact test/CI commands and observed results. Separate passed, failed, skipped and unavailable checks.
5. Any residual risks, deferred work or owner action.
6. Explicit confirmation that no live destructive firewall operation or unauthorized release publication occurred.

Do not report success for work that was merely assigned, attempted, reviewed or opened as a PR. Only verified merged outcomes count as completed.
