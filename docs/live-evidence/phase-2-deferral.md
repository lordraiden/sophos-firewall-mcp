# Live evidence deferral — phase 2 domain tools (#27–#31, #35)

**Date:** 15 November 2026
**Decision:** the repository owner chose to keep live tests read-only and to defer live
write validation to phase 3 (#32). The lab API key is read-only; no POST, PATCH or DELETE
was sent to the appliance during phase 2.

## What was verified without the appliance

| Domain | OperationIds exercised | Evidence |
|---|---|---|
| Firewall (#27) | 12 | RESPX contract tests, model tests, discovery/annotation tests, read-only-mode test |
| NAT (#28) | 12 | idem |
| Addresses, groups, MAC, country, services (#29) | 37 | idem |
| Users and live sessions (#30) | 6 | idem, plus password-redaction tests |
| Network architecture, VPN, status (#31) | 46 | idem, plus VLAN pre-read tests (zero write requests on refusal) |
| Audit (#35) | 0 new operations | idem, per-check and verdict tests |

The only live evidence in the repository remains the read-only endpoint smoke test of
15 November 2026 (`api-smoke-2026-11-15.md`), which predates these tools.

## Deferred, with reason

| Area | Why deferred | Owner | Prerequisite |
|---|---|---|---|
| NAT create/update/move and PATCH merge semantics | read-only key; writes forbidden | #32 | write-capable key + disposable-object plan |
| VPN and SSL VPN read paths | read-only key; firmware build unknown | #32 | same |
| Routing, DHCP, DNS, neighbor reads | read-only key; firmware build unknown | #32 | same |
| MAC and country objects | read-only key; writes forbidden | #32 | same |
| IPv6 firewall/NAT/address paths | read-only key; no IPv6 objects created | #32 | same |
| VLAN interface writes | read-only key; a wrong write can interrupt management | #32 | write key + maintenance window + parent-interface plan |
| Audit findings against a real rule base | needs the full read set on the appliance | #32 | read-only key (already available) |

## What a live run must record

Follow `docs/live-evidence/README.md`: appliance model, SFOS build, administrator profile
and permissions, API allowlist source, date, every operationId exercised with PASS/FAIL,
and an explicit deferral entry for anything not run. A mock cannot prove firmware
compatibility, and no phase-2 tool claims it.
