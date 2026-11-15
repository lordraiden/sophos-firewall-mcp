# Phase 5 — Output contract, remaining findings, live coverage and SFOS 23 positioning

**Status:** in progress (15 Nov 2026). **Base:** `main` after 0.5.0 (`15c859e`).
**Objective:** close the remaining phase-4 findings, make the output surface as consistent as the input
surface, extend live coverage to the 24 SKIPs, and make the SFOS 23 support unmistakable. Deliver
**0.6.0** (breaking: output naming), prepared but not published without owner approval.

## Decisions

| # | Decision |
|---|---|
| D1 | Outputs unify on **camelCase (wire-faithful)**. 119 tools already do it; outputs are projections of the appliance payload. 23 tools change (NAT 18 + 5 mixed). Convention: inputs snake_case (the model writes them), outputs the Sophos wire names (the model reads them). |
| D2 | M11: default `page_size` 10 for every list tool + a description sentence with the approximate size. |
| D3 | M12: `position` on list outputs (page offset + index); get-by-id returns `position: null`. |
| D4 | M13: derived `kind` (`snat`/`dnat`/`unknown`). |
| D5 | M14: NAT projections use `ObjectRef` objects like firewall. |
| D6 | M15: document the keyset ceiling; no undeclared inputs. |
| D7 | M16: the four unpaginated lists return `pages: null`. |
| D8 | L1: field descriptions on `Pages`. |
| D9 | L6: map the epoch sentinel to `null`, documented. |
| D10 | L7: investigate the duplicated text block; document if the SDK controls it. |
| D11 | L3/M9: description fixes. |
| D12 | 403: owner-dependent (read-only key); otherwise documented deferral. |
| D13 | Ambiguous writes: mock-only; documented. |
| D14 | Appliance model: owner-dependent. |
| D15 | SKIPs: live validation only for safe disposable types; VPN objects deferred. |
| D16 | Positioning/SEO: "Sophos Firewall 23 (SFOS 23.0) MCP server — Configuration REST API" everywhere. |
| D17 | Version 0.6.0; tag/image/release only with explicit owner approval. |

## Team (Agent Teams)

| Wave | Agent | Task | Write scope |
|---|---|---|---|
| 1 | `nat-out` | M2 NAT, M13, M14, M12 NAT | `models/nat.py`, `tools/nat_rules.py`, `tests/test_nat_rules.py` |
| 1 | `users-out` | M2 users | `models/users.py`, `tools/users_auth.py`, `tests/test_users_auth.py` |
| 1 | `firewall-out` | M12 firewall | `models/firewall.py`, `tools/firewall_rules.py`, `tests/test_firewall_rules.py` |
| 1 | `network-out` | M15, M16, L8, L9, L10 | `models/network.py`, `tools/network.py`, `tools/system.py`, `models/vpn.py`, `tools/vpn.py`, tests |
| 1 | `common-out` | L1, M10 | `models/common.py`, `tools/__init__.py`, tests |
| 2 | `polish` | M11, L6, L7, L3, M9 | the domain models/tools/tests (after wave 1) |
| 3 | `live-skip` | 24 SKIPs with disposable objects | `docs/live-evidence/phase-5-skip-coverage.md` |
| 3 | `positioning` | SFOS 23 positioning, SEO, 0.6.0 notes | `README.md`, `CHANGELOG.md`, `docs/release/RELEASE-0.6.0.md`, `pyproject.toml` |
| 4 | `reviewer5` | `04-REVIEW-PROTOCOL.md` | `docs/architecture/sophos-rest-api-redesign/PHASE-5-REVIEW.md` |

The Lead owns the branch, the board, integration, the version bump, coverage regeneration, the GitHub
repository metadata (description/topics) and the merge decision.

## Live-run deviation (recorded)

The phase-5 SKIP run used the contract's bulk-delete endpoint (`deleteDhcpRelaysIpv4`,
`POST /network/dhcp/relays/ipv4/delete`) with a **single-item** body to remove the disposable DHCP
relay, because the single-object DELETE returns 401 on this firmware. It is not a bulk operation, but
it is a deviation from "no bulk delete" and is recorded here and in
`docs/live-evidence/phase-5-skip-coverage.md`.

## Acceptance

- One output convention, 0 off-convention tools; the wire body unchanged.
- M9–M16 and L1/L3/L6–L10 closed or deferred with a reason.
- SKIP coverage with baseline == final and zero leftovers.
- README, CHANGELOG, release notes, keywords and GitHub metadata name SFOS 23.
- Gates green; independent review APPROVE; PR merged; 0.6.0 prepared.

## Out of scope

Streamable HTTP (cancelled by the owner), VPN mutations, interface writes beyond VLAN, bulk delete, the
lab key rotation (owner action).
