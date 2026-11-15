# Phase 4 — live write validation (constrained, disposable objects)

**Date:** 15 November 2026 (UTC)
**Workstream:** E of [`PHASE-4-PLAN.md`](../architecture/sophos-rest-api-redesign/PHASE-4-PLAN.md)
**Server under test:** `sophos-firewall-mcp-server` 0.4.0, launched over STDIO with
`SOPHOS_READ_ONLY_MODE=false`.
**Verdict:** 21 of 23 write calls behaved as documented (7 of 8 creates, 6 of 7 updates,
8 of 8 deletes). One create failed and one update could not run, both because of a single
defect: `network_user_create` / `network_user_update` send `group` in the wrong shape (D1).
Every object created for this run was deleted and verified gone; the appliance is back to its
exact baseline.

This is the first record in this directory that contains writes. The read-only rule in
[`README.md`](README.md) §1 is superseded for this run only by an explicit owner approval
and a disposable-object plan, both recorded below.

## 1. Safety constraints and how they were enforced

The owner approved live writes under four non-negotiable constraints. Each one was enforced
mechanically, not by convention.

| Constraint | Enforcement |
|---|---|
| Create only new objects named `mcp-test-<unique-suffix>` | Every name is built from a per-run random suffix (`mcp-test-p4w24049e-*`). No existing object was ever named in a write request. |
| Never enable a firewall or NAT rule | Every rule create sends `enabled: false` explicitly. Immediately after each create the driver re-reads the rule and asserts the **applied** `enabled` is exactly `false`. If it had come back `true`, the driver would have deleted the rule in the same step and aborted the run. The guard never fired. |
| Never edit, move or delete an existing object | The delete phase iterates a fixed list of the names this run created. `firewall_rule_move_*`, `nat_rule_move_*`, `firewall_rule_clone_*` and `firewall_rule_set_enabled_*` were deliberately not called. |
| Delete everything created and verify it is gone | Each delete is followed by a `GET` of the same name; a `200` would have been recorded as `CLEANUP-FAILURE`. All eight returned `404`. A final sweep of 14 collections found zero objects containing `mcp-test`. |

Additional exclusions honoured: no bulk delete, no interface/VPN mutation, no live-user
disconnect, no IPv6 objects, no group objects.

## 2. Environment

| Field | Value |
|---|---|
| Appliance model | `unknown` — the REST contract exposes no model endpoint |
| SFOS build | `unknown` — still open (workstream F) |
| Administrator profile / permissions | Write-capable: `POST`/`PATCH`/`DELETE` were accepted. The API does not expose which administrator owns the key, so the profile name is `unknown`. |
| API allowlist source | `unknown` — not inspected for this run |
| Date | 2026-11-15 |
| Endpoint | `10.10.10.1:443`, base path `/api/firewall-config/v1` |
| Evidence source | Python driver over the official MCP SDK `Client` (STDIO), server 0.4.0; HTTP status codes taken from the server's own request log |
| Key rotation status | Not rotated (workstream G) |

The API key was read from `SOPHOS_API_KEY_FILE` and never printed, logged or written to this
document. The network-user password was generated per run, never printed, and is not
recorded here.

## 3. Baseline

Recorded before any write, by paginating each collection to exhaustion
(`pageSize=100`, `pageTotal=true`; the authoritative total is `pages.items`).

| Collection | Count |
|---|---|
| IPv4 addresses | 119 |
| FQDN addresses | 24 |
| Services | 93 |
| MAC addresses | 0 |
| Network users | 2 |
| IPv4 firewall rules | 47 |
| IPv4 NAT rules | 28 |

## 4. Operations exercised

Names below use the run suffix `p4w24049e`. `result` follows
[`README.md`](README.md) §3: `PASS` / `FAIL` / `SKIP`.

### 4.1 Create

| operationId | method + path | result | HTTP | observation | evidence |
|---|---|---|---|---|---|
| `createIpAddress` | `POST /network/addresses/ipv4` | PASS | 201 | `type: ipv4Address`, `192.0.2.10`; body echoed with server-assigned `id` | `address_create_ipv4` → `mcp-test-p4w24049e-ipv4` |
| `createIpAddress` | `POST /network/addresses/ipv4` | PASS | 201 | second address `192.0.2.20`, used as the NAT translation target | `address_create_ipv4` → `mcp-test-p4w24049e-ipv4dst` |
| `createFqdn` | `POST /network/addresses/fqdn` | PASS | 201 | `fqdn` stored verbatim | `address_create_fqdn` → `mcp-test-p4w24049e-fqdn` |
| `createService` | `POST /network/services` | PASS | 201 | `tcpOrUdp`, `tcp` 65000–65001; the appliance filled `sourcePort` 1–65535 | `service_create` → `mcp-test-p4w24049e-svc` |
| `createMacAddress` | `POST /network/addresses/mac` | PASS | 201 | single-MAC object; value normalised to upper case (see O1) | `mac_address_create` → `mcp-test-p4w24049e-mac` |
| `createNetworkUser` | `POST /authentication/users/network-users` | **FAIL** | **400** | `invalidRequest`; see defect **D1** | `network_user_create` → `mcp-test-p4w24049e-user` |
| `createFirewallRuleIpv4` | `POST /firewall/rules/ipv4` | PASS | 201 | `enabled: false`, `action: drop`, `position: bottom`; applied state verified disabled | `firewall_rule_create_ipv4` → `mcp-test-p4w24049e-fw` |
| `createNatRuleIpv4` | `POST /nat/rules/ipv4` | PASS | 201 | `enabled: false`, `position: bottom`; applied state verified disabled | `nat_rule_create_ipv4` → `mcp-test-p4w24049e-nat` |

### 4.2 Read-back

| operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|
| `getIpAddressByIdOrName` | `GET /network/addresses/ipv4/{name}` | PASS | 200 | both addresses returned; envelope is `{"address": {...}}` (see O2) |
| `getFqdnByIdOrName` | `GET /network/addresses/fqdn/{name}` | PASS | 200 | flat object |
| `getServiceByIdOrName` | `GET /network/services/{name}` | PASS | 200 | flat object, `services[]` preserved |
| `getMacAddressByIdOrName` | `GET /network/addresses/mac/{name}` | PASS | 200 | flat object, upper-case MAC |
| `getNetworkUser` | `GET /authentication/users/network-users/{name}` | SKIP | 404 | object was never created (D1) |
| `getFirewallRuleIpv4` | `GET /firewall/rules/ipv4/{name}` | PASS | 200 | `enabled: false` |
| `getNatRuleIpv4ByIdOrName` | `GET /nat/rules/ipv4/{name}` | PASS | 200 | `enabled: false` |

### 4.3 Update (PATCH, description only)

Each update changed only `description`. The read-back asserts both the new value **and**
that the omitted fields were preserved.

| operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|
| `updateIpAddressByIdOrName` | `PATCH /network/addresses/ipv4/{name}` | PASS | 200 | `description` changed; `ipv4Address` `192.0.2.10` and `name` preserved |
| `updateFqdnByIdOrName` | `PATCH /network/addresses/fqdn/{name}` | PASS | 200 | `description` changed; `fqdn` preserved |
| `updateServiceByIdOrName` | `PATCH /network/services/{name}` | PASS | 200 | `description` changed; `type` and `services[]` preserved |
| `updateMacAddressByIdOrName` | `PATCH /network/addresses/mac/{name}` | PASS | 200 | `description` changed; `macAddress` preserved (upper case, see O1) |
| `updateNetworkUser` | `PATCH /authentication/users/network-users/{name}` | SKIP | 404 | object was never created (D1) |
| `updateFirewallRuleIpv4` | `PATCH /firewall/rules/ipv4/{name}` | PASS | 200 | `description` changed; `action: drop` preserved; **`enabled` still `false`** |
| `updateNatRuleIpv4ByIdOrName` | `PATCH /nat/rules/ipv4/{name}` | PASS | 200 | `description` changed; **`enabled` still `false`** |

### 4.4 Delete

| operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|
| `deleteNatRuleIpv4ByIdOrName` | `DELETE /nat/rules/ipv4/{name}` | PASS | 200 | `{"deleted": true}`; follow-up `GET` 404 |
| `deleteFirewallRuleIpv4` | `DELETE /firewall/rules/ipv4/{name}` | PASS | 200 | `{"deleted": true}`; follow-up `GET` 404 |
| `deleteNetworkUser` | `DELETE /authentication/users/network-users/{name}` | PASS | 200 | returned 200 for an object that never existed (see O3) |
| `deleteMacAddressByIdOrName` | `DELETE /network/addresses/mac/{name}` | PASS | 200 | follow-up `GET` 404 |
| `deleteServiceByIdOrName` | `DELETE /network/services/{name}` | PASS | 200 | follow-up `GET` 404 |
| `deleteFqdnByIdOrName` | `DELETE /network/addresses/fqdn/{name}` | PASS | 200 | follow-up `GET` 404 |
| `deleteIpAddressByIdOrName` | `DELETE /network/addresses/ipv4/{name}` | PASS | 200 | both addresses; follow-up `GET` 404 |

### 4.5 Network-user partial validation (fixture created out of band)

`createNetworkUser` is blocked by D1, so the remaining network-user write tools were
exercised against a fixture user created with a direct REST `POST` using the object-form
`group` that the contract requires (`201`). The fixture was named `mcp-test-p4wu2ea9` and was
deleted inside the same run.

| operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|
| `getNetworkUser` | `GET /authentication/users/network-users/{name}` | PASS | 200 | read back correctly; `group` projected to the string `"Open Group"` |
| `updateNetworkUser` (with `group`) | `PATCH /authentication/users/network-users/{name}` | **FAIL** | **400** | same defect as D1 on the update path: `group` sent as a string |
| `updateNetworkUser` (description only) | `PATCH /authentication/users/network-users/{name}` | PASS | 200 | `description` changed; `display_name`, `group` and `active` preserved |
| `deleteNetworkUser` | `DELETE /authentication/users/network-users/{name}` | PASS | 200 | `{"deleted": true}`; follow-up `GET` 404 |

This isolates D1 to the `group` field: every other part of the network-user write path works.
The fixture was created and removed within the run, so it does not appear in the baseline or
the final counts.

## 5. Applied-state verification (`enabled: false`)

This is the safety-critical result of the run. The value below is the **applied** state read
back from the appliance, not the value the client sent.

| Rule | create response | `GET` read-back | after `PATCH` |
|---|---|---|---|
| `mcp-test-p4w24049e-fw` (firewall, IPv4) | `"enabled": false` | `"enabled": false` | `"enabled": false` |
| `mcp-test-p4w24049e-nat` (NAT, IPv4) | `"enabled": false` | `"enabled": false` | `"enabled": false` |

Two points are worth recording:

1. **The NAT create schema defaults `enabled` to `true`.** The tool's input model documents
   this ("contract default: true"), so a caller that omits the field would create an enabled
   rule. The adapter sent the explicit `false` and the appliance applied it. The default is
   a real hazard for callers, not for this run.
2. **A description-only `PATCH` does not re-enable a disabled rule.** Both rules stayed
   `false` after the update, so the merge patch does not fall back to the schema default.

### 5.1 `position: bottom` verification

A second, separate create/delete cycle confirmed the insertion point rather than assuming it:

| Rule | rule-base size after create | index of the created rule | last? |
|---|---|---|---|
| firewall IPv4 | 48 | 47 (0-based) | yes |
| NAT IPv4 | 29 | 28 (0-based) | yes |

Both rules were `enabled: false` in the same cycle and were deleted immediately afterwards
(verified `404`).

## 6. Defects

### D1 — `network_user_create` and `network_user_update` send `group` as a string

**Severity:** high for the network-user write path; the create tool is unusable against a
real appliance.

**Tool:** `network_user_create` (`createNetworkUser`), `network_user_update`
(`updateNetworkUser`).

**Input:** `{"name": "mcp-test-p4w24049e-user", "display_name": "mcp test user",
"password": "<generated>", "group": "Open Group", "active": false, "description": "..."}`.

**Observed:** `HTTP 400` — *"the firewall rejected the request as invalid; check the field
values (HTTP 400) [POST /authentication/users/network-users] [error: invalidRequest]"*.

**Root cause.** The contract models `group` as an object with a required `name` member:

```yaml
# firewall_config_openapi.yaml, createNetworkUser requestBody
group:
  type: object
  description: Referenced user group (request).
  properties:
    name:
      type: string
      format: sfos-object-name
      minLength: 1
      maxLength: 256
  required:
  - name
```

The MCP input model types it as a bare string (`models/users.py`:
`UserGroupName = Annotated[str, ...]`), so `_create_body` serialises a string. The body the
server actually builds is:

```json
{"name": "mcp-test-x", "displayName": "mcp test", "group": "Open Group", "password": "<redacted>"}
```

**Evidence that the shape, not the appliance, is at fault.** A direct REST probe against the
same appliance isolated the two variables:

| Request body | Result |
|---|---|
| `"group": "Open Group"` | `400 {"error":"invalidRequest","message":"Invalid group."}` |
| `"group": {"name": "Open Group"}` | `201` with the created user |

The same probe showed a second, independent rejection for a password that violates the
appliance's complexity policy (`400 {"error":"invalidInputPassword","message":"Invalid
password."}`); the policy read from
`GET /authentication/password-complexity/network-users` is `enabled: true, minLength: 10,
enforceMixedCase: true, enforceNumbers: true, enforceSpecialCharacters: true`. With a
policy-compliant password the object-form request succeeded, which proves the `group` shape
is the blocking difference.

**The unit test encodes the wrong contract.** `tests/test_users_auth.py`
(`test_network_user_create_sends_only_the_required_fields`, and the fuller
`test_network_user_create_posts_the_documented_body`) asserts `"group": "users"` in the
request body, so the suite locks in the defect and cannot catch it.

**Expected behaviour:** `201` with the created user, and `group` serialised as
`{"name": "<group>"}` in both the create and update bodies.

**Impact:** `network_user_create` always fails against a real appliance. `network_user_update`
fails whenever `group` is part of the patch; a description-only patch works (verified in §4.5).

**Not fixed here.** Per the task constraints a defect is recorded, not repaired, without Lead
approval.

### D2 — the appliance's validation reason is discarded from write errors

**Severity:** medium (diagnosability).

**Observed:** for the same rejected request the appliance answers with a specific code and
message — `{"error":"invalidInputPassword","message":"Invalid password."}` or
`{"error":"invalidRequest","message":"Invalid group."}` — but the tool returns the generic
*"the firewall rejected the request as invalid; check the field values (HTTP 400) [error:
invalidRequest]"*. The caller cannot tell which field is wrong, and a wrong password and a
wrong `group` shape are indistinguishable.

**Expected behaviour:** surface the appliance's `error` code (and a sanitized `message`) in
the tool error. Neither is secret; the sanitization that matters is for credentials and
response bodies, not for the validation code.

**Note:** this is the reason D1 was hard to diagnose from the tool surface alone; the direct
REST probe was needed to separate the two causes.

## 7. Observations (not defects)

| # | Observation | Impact |
|---|---|---|
| O1 | MAC addresses are normalised to upper case: sent `02:de:ad:be:ef:01`, stored and returned `02:DE:AD:BE:EF:01`. | A caller comparing the returned value to its input must compare case-insensitively. Not a server defect. |
| O2 | Response envelopes are inconsistent across object reads: `address_get_ipv4` returns `{"address": {...}}` while `address_get_fqdn`, `service_get`, `mac_address_get`, `network_user_get`, `firewall_rule_get_ipv4` and `nat_rule_get_ipv4` return the object flat. | A client must special-case IPv4 address reads. Worth folding into the 0.5.0 surface unification (workstream C). |
| O3 | `network_user_delete` reports success for an object that does not exist: `DELETE /authentication/users/network-users/mcp-test-p4w24049e-user` returned `200` even though the create had failed with `400`. | The tool cannot distinguish "deleted" from "never existed". Low severity (idempotent delete is defensible), but it weakens cleanup verification for this collection. |
| O4 | `active: false` is not honoured on create: a direct REST create with `"active": false` returned `"active": true`. | Appliance behaviour, not an MCP defect. It could not be checked through the tool because of D1. |
| O5 | NAT rule network selections encode "not selected" inconsistently: `original_source_networks.any` came back `true` while `original_destination_networks.any` came back `null` (not `false`) when a selection was used. | The output model tolerates it; a strict `oneOf` validator would not. Minor contract deviation. |

## 8. Cleanup confirmation

**Baseline == final.** Counts and the full sorted name list of every touched collection were
compared before and after the run; both are identical.

| Collection | Baseline | Final | Names identical |
|---|---|---|---|
| IPv4 addresses | 119 | 119 | yes |
| FQDN addresses | 24 | 24 | yes |
| Services | 93 | 93 | yes |
| MAC addresses | 0 | 0 | yes |
| Network users | 2 | 2 | yes |
| IPv4 firewall rules | 47 | 47 | yes |
| IPv4 NAT rules | 28 | 28 | yes |

**Every created object is gone.** Each delete returned `200` and the follow-up `GET` returned
`404`:

| Object | Delete | Follow-up `GET` |
|---|---|---|
| `mcp-test-p4w24049e-nat` | 200 | 404 |
| `mcp-test-p4w24049e-fw` | 200 | 404 |
| `mcp-test-p4w24049e-user` | 200 | 404 (never created) |
| `mcp-test-p4w24049e-mac` | 200 | 404 |
| `mcp-test-p4w24049e-svc` | 200 | 404 |
| `mcp-test-p4w24049e-fqdn` | 200 | 404 |
| `mcp-test-p4w24049e-ipv4dst` | 200 | 404 |
| `mcp-test-p4w24049e-ipv4` | 200 | 404 |

**Final sweep.** All 14 collections were paginated to exhaustion and searched for the string
`mcp-test` (case-insensitive): **0 matches**. The swept collections were IPv4/IPv6 addresses,
FQDN addresses, MAC addresses, services, service groups, IPv4/FQDN address groups, network
users, authentication users, IPv4/IPv6 firewall rules and IPv4/IPv6 NAT rules.

**Nothing remains on the appliance from this run.** No cleanup failure occurred.

## 9. What this run does not prove

| Not validated | Reason |
|---|---|
| `createNetworkUser` | Blocked by D1; the rest of the network-user path was validated with a fixture (§4.5) |
| `updateNetworkUser` with `group` | Fails with D1; the description-only update passed (§4.5) |
| `firewall_rule_set_enabled_ipv4/ipv6` | Deliberately not exercised: it would enable a rule |
| `firewall_rule_move_ipv4`, `nat_rule_move_ipv4` | Out of scope: moving mutates the existing rule base |
| `firewall_rule_clone_ipv4/ipv6` | Out of scope: clones an existing rule |
| `address_group_*`, `service_group_*` create/update/delete | Not in the agreed disposable-object list |
| `network_interface_*_vlan` | Excluded by the owner's constraints |
| `live_user_disconnect` | Excluded by the owner's constraints |
| IPv6 variants of every write tool | No IPv6 objects in the agreed list |
| Bulk delete | Excluded by the owner's constraints |
| Ambiguous-write behaviour (timeout, then reconcile) | Not exercised; no timeout occurred |
| Effective `403` denial for a read-only profile | The write key is write-capable; denial was not tested |

The results apply to this appliance only. The SFOS build is still unknown, so nothing here
generalises to another firmware version.

## 10. Reproduction

The run was driven over STDIO with the official MCP SDK `Client`, one `call_tool` per
operation, with the server started as:

```text
SOPHOS_HOST=10.10.10.1
SOPHOS_PORT=443
SOPHOS_API_KEY_FILE=<path to the write key>
SOPHOS_VERIFY_SSL=false
SOPHOS_READ_ONLY_MODE=false
```

The driver is not committed: it is a throwaway harness, and the record above is the evidence.
To reproduce D1 without any write, the serialised body can be inspected locally:

```python
from sophos_firewall_mcp.models.users import NetworkUserCreateInput
from sophos_firewall_mcp.tools.users_auth import _create_body

req = NetworkUserCreateInput(
    name="mcp-test-x", display_name="mcp test",
    password="<policy-compliant>", group="Open Group",
)
print(_create_body(req))   # -> {'name': ..., 'displayName': ..., 'group': 'Open Group', ...}
```

`group` is a string; the contract requires `{"name": "Open Group"}`.
