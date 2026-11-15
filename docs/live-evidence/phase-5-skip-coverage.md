# Phase 5 — live coverage of the 24 phase-4 SKIPs (disposable objects)

**Date:** 15 November 2026 (UTC), run window 17:37–17:38
**Workstream:** P5-7 of the phase-5 plan
**Server under test:** `sophos-firewall-mcp-server` **0.5.0**, installed binary in
`.agents/mcp-venv`, launched over STDIO with `SOPHOS_READ_ONLY_MODE=false` (152 tools,
54 mutations).
**Verdict:** **6 of the 24 phase-4 SKIPs became PASS** with real objects. **1** was attempted
and is blocked by the appliance itself (`dhcp_relay_get_ipv4` returns `401` on a real,
listed relay). **17** remain deferred for scope or connectivity reasons (§6). One new
output-contract defect was found (**P5-D1**, the DNS host entry address is dropped by the
projection) and one phase-4 finding is corrected (**M9**: the DHCP relay sub-resource is
`401` for every object, not only for an unknown UUID). Every object created for this run was
deleted and verified gone; the appliance is back to its exact baseline (§8).

This record follows the format in [`README.md`](README.md) §3. It is append-only: it adds a
new dated record and does not rewrite the phase-4 files.

## 1. Safety constraints and how they were enforced

The phase-4 write-validation constraints ([`phase-4-write-validation.md`](phase-4-write-validation.md) §1)
were reused unchanged. Each one was enforced mechanically by the driver, not by convention.

| Constraint | Enforcement |
|---|---|
| Create only new objects named `mcp-test-<unique-suffix>` | Every name is built from a per-run random suffix (`mcp-test-p5s6ac825-*`). No existing object was ever named in a write request. |
| Never enable a firewall or NAT rule | Both rule creates send `enabled: false` explicitly. The driver asserts the **applied** `enabled` from the create response, then again from the get-by-name and get-by-id read-backs. If any had come back `true`, the driver would have deleted the rule in the same step and aborted the cycle. The guard never fired. |
| Never edit, move or delete an existing object | The delete phase iterates only the names this run created. `firewall_rule_move_*`, `nat_rule_move_*`, `firewall_rule_clone_*` and `firewall_rule_set_enabled_*` were not called. |
| Delete everything created and verify it is gone | Each delete is followed by a `GET` of the same name; a `200` would have been recorded as `CLEANUP-FAILURE`. All returned `404`. A final sweep of 17 collections found zero objects containing `mcp-test` (§8). |

Additional exclusions honoured: no interface, zone, gateway, route, IPsec or SSL VPN
mutation; no live-user disconnect; no `network_user` write; no bulk delete.

**One documented deviation.** The DHCP relay single-object `DELETE` returns `401` on this
firmware (§7, P5-O1), so the relay fixture was removed through the contract's own delete
endpoint (`POST /network/dhcp/relays/ipv4/delete`) with **exactly one item — the name of the
object this run had just created**. It is not a bulk operation: the request body named one
object, the response confirmed `deleted: true` for that one object, and the collection was
empty afterwards. No other object was in scope.

## 2. Environment

| Field | Value |
|---|---|
| Appliance model | `unknown` — the Configuration REST API exposes no model endpoint; the appliance hostname is `SophosXGHome` |
| SFOS build | **SFOS 23.0.0 GA-Build371** (owner-provided on 2026-11-15; the API exposes no version endpoint). No general firmware compatibility is claimed beyond this build. |
| Administrator profile / permissions | Write-capable: `POST` and `DELETE` were accepted on every family exercised. The API does not expose which administrator owns the key, so the profile name is `unknown`. |
| API allowlist source | `unknown` — not exposed by the API |
| Date | 2026-11-15 (UTC), run window 17:37–17:38 |
| Endpoint | `10.10.10.1:443`, base path `/api/firewall-config/v1`; the key is never recorded |
| TLS | Appliance self-signed certificate; `SOPHOS_VERIFY_SSL=false` for this lab run only |
| Server build | `sophos-firewall-mcp-server` **0.5.0** (installed binary, `.agents/mcp-venv`), 152 tools, 54 mutations |
| MCP protocol | 2026-07-28 (official Python SDK `Client`, STDIO) |
| Evidence source | Throwaway STDIO driver (not committed) plus three focused probes; HTTP statuses taken from the server's own `httpx` request log |
| Key rotation status | Not rotated after the run; the owner rotates it when the lab work ends |

The API key was read from `SOPHOS_API_KEY_FILE` and never printed, logged or written to this
document.

## 3. Baseline

Recorded before any write, by paginating each collection to exhaustion
(`page_size=100`, `page_total=true`; the authoritative total is `pages.total`).

| Collection | Count |
|---|---|
| IPv6 addresses | 3 |
| IPv6 address groups | 0 |
| IPv6 firewall rules | 0 |
| IPv6 NAT rules | 0 |
| MAC addresses | 0 |
| DHCP relays (IPv4) | 0 |
| DNS host entries | 0 |
| Static neighbours (IPv4) | 0 |

These are exactly the phase-4 counts, so the appliance had not drifted between the two runs
for the collections this run touches.

## 4. Operations exercised

Names below use the run suffix `p5s6ac825`. `result` follows [`README.md`](README.md) §3:
`PASS` / `FAIL` / `SKIP`. The three fixtures marked *out of band* were created with a direct
REST `POST` because the server exposes **no create tool** for DHCP relays, DNS host entries
or static neighbours; the MCP get-by-id path is what this run measures.

### 4.1 Create

| operationId | method + path | result | HTTP | observation | evidence |
|---|---|---|---|---|---|
| `createIpv6Address` | `POST /network/addresses/ipv6` | PASS | 201 | `type: ipv6Address`, `2001:db8:5:1::10`; server-assigned `id` | `address_create_ipv6` → `mcp-test-p5s6ac825-ipv6` |
| `createIpv6Address` | `POST /network/addresses/ipv6` | PASS | 201 | group member `2001:db8:5:1::11` | `address_create_ipv6` → `mcp-test-p5s6ac825-ipv6m` |
| `createIpv6AddressGroup` | `POST /network/address-groups/ipv6` | PASS | 201 | member reference `{"name": …}` accepted; `ipv6Addresses[]` preserved | `address_group_create_ipv6` → `mcp-test-p5s6ac825-ipv6grp` |
| `createFirewallRuleIpv6` | `POST /firewall/rules/ipv6` | PASS | 201 | `enabled: false`, `action: drop`, `position: bottom`; applied state verified disabled | `firewall_rule_create_ipv6` → `mcp-test-p5s6ac825-fw6` |
| `createNatRuleIpv6` | `POST /nat/rules/ipv6` | PASS | 201 | `enabled: false`, `position: bottom`; applied state verified disabled | `nat_rule_create_ipv6` → `mcp-test-p5s6ac825-nat6` |
| `createMacAddress` | `POST /network/addresses/mac` | PASS | 201 | single-MAC object; the value was sent upper case and read back unchanged | `mac_address_create` → `mcp-test-p5s6ac825-mac` |
| `createDhcpRelayIpv4` | `POST /network/dhcp/relays/ipv4` | PASS | 201 | *out of band*; `interface: {"name": "DMZ - Services"}` (see P5-O2) | direct REST → `mcp-test-p5s6ac825-relay` |
| `createDnsHostEntry` | `POST /network/dns/host-entries` | PASS | 201 | *out of band*; `hostEntries[0].ipv4.ipv4Address` stored nested | direct REST → `mcp-test-p5s6ac825-dns` |
| `createStaticNeighborIpv4` | `POST /network/neighbors/static/ipv4` | PASS | 201 | *out of band*; `interface: {"name": "DMZ - Services"}` (see P5-O2) | direct REST → `mcp-test-p5s6ac825-neigh` |

### 4.2 Read-back by name and by id

This is the core of the run: every created object was read back twice, once with its name and
once with the server-assigned UUID. Both returned `200` and the same projected object.

| operationId | method + path | result | HTTP (name / id) | observation |
|---|---|---|---|---|
| `getIpv6AddressByIdOrName` | `GET /network/addresses/ipv6/{idOrName}` | PASS | 200 / 200 | `{"address": {…}}` envelope; `ipv6Address` `2001:db8:5:1::10` |
| `getIpv6AddressByIdOrName` (member) | `GET /network/addresses/ipv6/{idOrName}` | PASS | 200 / 200 | `ipv6Address` `2001:db8:5:1::11` |
| `getIpv6AddressGroupByIdOrName` | `GET /network/address-groups/ipv6/{idOrName}` | PASS | 200 / 200 | flat object; `ipv6Addresses: [{"name": "mcp-test-p5s6ac825-ipv6m"}]` |
| `getFirewallRuleIpv6` | `GET /firewall/rules/ipv6/{idOrName}` | PASS | 200 / 200 | flat object; `enabled: false`, `ipFamily: "ipv6"`, `ruleType: "firewall"` |
| `getNatRuleIpv6ByIdOrName` | `GET /nat/rules/ipv6/{idOrName}` | PASS | 200 / 200 | flat object; `enabled: false` |
| `getMacAddressByIdOrName` | `GET /network/addresses/mac/{idOrName}` | PASS | 200 / 200 | `{"address": {…}}` envelope; `macAddress` `02:DE:AD:BE:EF:11` |
| `getDhcpRelayIpv4` | `GET /network/dhcp/relays/ipv4/{id}` | **SKIP** | **401** (by id) | appliance rejects the sub-resource; the tool accepts only a UUID, so a by-name read is not possible at all — see §4.4 and P5-O1 |
| `getDnsHostEntryById` | `GET /network/dns/host-entries/{idOrName}` | PASS | 200 / 200 | flat object; **host entry address lost** — see P5-D1 |
| `getStaticNeighborIpv4` | `GET /network/neighbors/static/ipv4/{idOrName}` | PASS | 200 / 200 | flat object; `ipv4Address` `10.10.15.250`, `macAddress` `02:DE:AD:BE:EF:12` |

The get-by-id result for each created object, with the UUID the appliance assigned:

| Object | UUID | get by name | get by id | projection |
|---|---|---|---|---|
| `mcp-test-p5s6ac825-ipv6` | `9b345df5-ede7-5b1b-8626-4c38729ffca2` | 200 | 200 | `{"address": {…}}` |
| `mcp-test-p5s6ac825-ipv6m` | `d976126c-43c8-55cf-a5b3-e750c5beeceb` | 200 | 200 | `{"address": {…}}` |
| `mcp-test-p5s6ac825-ipv6grp` | `80791c84-060c-5b64-8d82-17265c210853` | 200 | 200 | flat |
| `mcp-test-p5s6ac825-fw6` | `7504bb5c-456e-5140-bdec-3a29b9d0f750` | 200 | 200 | flat |
| `mcp-test-p5s6ac825-nat6` | `c3014920-0629-5672-82a6-9fbe0a48f284` | 200 | 200 | flat |
| `mcp-test-p5s6ac825-mac` | `025a6645-cb19-572a-b31e-e5b0a0d1a61f` | 200 | 200 | `{"address": {…}}` |
| `mcp-test-p5s6ac825-relay` | `80b33b4b-535f-406c-911b-f6b246a43464` | not possible (UUID-only tool) | **401** | not projected |
| `mcp-test-p5s6ac825-dns` | `33712f4a-3979-50d2-b7ae-147b3c5e2240` | 200 | 200 | flat, address lost (P5-D1) |
| `mcp-test-p5s6ac825-neigh` | `1ea904db-61f5-5f4a-be75-5b57ec656f6b` | 200 | 200 | flat |

### 4.3 Delete

| operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|
| `deleteIpv6AddressByIdOrName` | `DELETE /network/addresses/ipv6/{idOrName}` | PASS | 200 | `{"deleted": true}`; follow-up `GET` 404 |
| `deleteIpv6AddressGroupByIdOrName` | `DELETE /network/address-groups/ipv6/{idOrName}` | PASS | 200 | `{"deleted": true}`; follow-up `GET` 404 |
| `deleteFirewallRuleIpv6` | `DELETE /firewall/rules/ipv6/{idOrName}` | PASS | 200 | `{"deleted": true}`; follow-up `GET` 404 |
| `deleteNatRuleIpv6ByIdOrName` | `DELETE /nat/rules/ipv6/{idOrName}` | PASS | 200 | `{"deleted": true}`; follow-up `GET` 404 |
| `deleteMacAddressByIdOrName` | `DELETE /network/addresses/mac/{idOrName}` | PASS | 200 | `{"deleted": true}`; follow-up `GET` 404 |
| `deleteDhcpRelayByIdIpv4` | `DELETE /network/dhcp/relays/ipv4/{idOrName}` | **FAIL** | **401** | no MCP tool exists for this operation; the direct REST probe returned `401` for both the name and the UUID. Removed through the delete endpoint instead (§4.4) |
| `deleteDnsHostEntryByIdOrName` | `DELETE /network/dns/host-entries/{idOrName}` | PASS | 200 | *out of band*; `{"deleted": true}`; follow-up `GET` 404 |
| `deleteStaticNeighborIpv4ByIdOrName` | `DELETE /network/neighbors/static/ipv4/{idOrName}` | PASS | 200 | *out of band*; `{"deleted": true}`; follow-up `GET` 404 |

### 4.4 The DHCP relay attempt (blocked by the appliance)

The relay fixture was created successfully (`201`) and listed by `dhcp_relay_list_ipv4`, so
the object existed. Every single-object request against it then returned `401`:

| Request | Status | Body |
|---|---|---|
| `GET /network/dhcp/relays/ipv4/{name}` | **401** | `{"error": "unauthenticated", "message": "Token missing or invalid."}` |
| `GET /network/dhcp/relays/ipv4/{uuid}` | **401** | same |
| `DELETE /network/dhcp/relays/ipv4/{name}` | **401** | same |
| `DELETE /network/dhcp/relays/ipv4/{uuid}` | **401** | same |
| `GET /network/dhcp/relays/ipv4` (collection) | 200 | the relay is listed |
| `POST /network/dhcp/relays/ipv4` (create) | 201 | object created |
| `POST /network/dhcp/relays/ipv4/delete` (one item) | 200 | `{"items": [{"item": {"name": …}, "deleted": true}]}` |

The same token authenticates the collection read and the create, so this is not a credential
problem: the relay sub-resource route itself rejects the request. A control probe confirms the
route exists rather than being absent — an unknown path returns `404 "404 page not found"`,
while `/network/dhcp/relays/ipv4/does-not-exist` and `/network/dhcp/relays/ipv6/does-not-exist`
both return the same `401 unauthenticated`.

**Consequence:** `dhcp_relay_get_ipv4` cannot succeed on this firmware. The tool accepts only a
UUID (P5-O3), and that UUID returns `401` for a real, listed object. The SKIP is therefore not
a gap in the run; it is an appliance limitation, now with a precise cause (P5-O1).

## 5. Applied-state verification (`enabled: false`)

This is the safety-critical result of the run. The values are the **applied** state read back
from the appliance, not the values the client sent.

| Rule | create response | `GET` by name | `GET` by id |
|---|---|---|---|
| `mcp-test-p5s6ac825-fw6` (firewall, IPv6) | `"enabled": false` | `"enabled": false` | `"enabled": false` |
| `mcp-test-p5s6ac825-nat6` (NAT, IPv6) | `"enabled": false` | `"enabled": false` | `"enabled": false` |

The IPv6 NAT create schema also defaults `enabled` to `true` (the same hazard phase-4 §5
recorded for IPv4). The adapter sent the explicit `false` and the appliance applied it, so the
guard never had to fire. Both rules were created with `position: bottom` and deleted in the
same cycle. The insertion point itself was **not** re-verified: the IPv6 rule output contract
exposes no `position` field, so unlike phase-4 §5.1 there is no read-back that could confirm
it.

## 6. SKIP coverage: the 24 phase-4 SKIPs

`PASS` means the get-by-id path was exercised against a real object created for this run.
`BLOCKED` means an object was created and the appliance refused the read. `DEFERRED` means no
object was created, with the reason in the last column.

| # | phase-4 SKIP | now | evidence / reason |
|---|---|---|---|
| 1 | `firewall_rule_get_ipv6` | **PASS** | IPv6 rule created disabled, read by name and by id, deleted |
| 2 | `nat_rule_get_ipv6` | **PASS** | IPv6 NAT rule created disabled, read by name and by id, deleted |
| 3 | `address_group_get_ipv6` | **PASS** | IPv6 group with a real member, read by name and by id, deleted |
| 4 | `mac_address_get` | **PASS** | single-MAC object, read by name and by id, deleted |
| 5 | `custom_gateway_get_ipv4` | DEFERRED | gateway mutation: connectivity risk, excluded by the task |
| 6 | `wan_gateway_get_ipv6` | DEFERRED | gateway mutation: connectivity risk, excluded by the task |
| 7 | `custom_gateway_get_ipv6` | DEFERRED | gateway mutation: connectivity risk, excluded by the task |
| 8 | `unicast_route_get_ipv4` | DEFERRED | route mutation: connectivity risk, excluded by the task |
| 9 | `unicast_route_get_ipv6` | DEFERRED | route mutation: connectivity risk, excluded by the task |
| 10 | `sdwan_route_get_ipv4` | DEFERRED | route mutation: connectivity risk, excluded by the task |
| 11 | `sdwan_route_get_ipv6` | DEFERRED | route mutation: connectivity risk, excluded by the task |
| 12 | `dhcp_server_get_ipv6` | DEFERRED | no create tool; DHCP server mutations are excluded from the server |
| 13 | `dhcp_relay_get_ipv4` | **BLOCKED** | object created and listed; sub-resource returns `401` (P5-O1) |
| 14 | `dhcp_relay_get_ipv6` | DEFERRED | no create tool; the IPv6 sub-resource shows the same `401` signature |
| 15 | `dns_host_entry_get` | **PASS** | fixture created out of band, read by name and by id, deleted |
| 16 | `dns_request_route_get` | DEFERRED | no create tool; not in the agreed disposable-object list |
| 17 | `static_neighbor_get_ipv4` | **PASS** | fixture created out of band, read by name and by id, deleted |
| 18 | `static_neighbor_get_ipv6` | DEFERRED | the agreed list covers the IPv4 neighbour only |
| 19 | `ipsec_failover_group_get` | DEFERRED | VPN mutation: connectivity risk, excluded by the task |
| 20 | `ipsec_policy_based_connection_get_ipv4` | DEFERRED | VPN mutation: connectivity risk, excluded by the task |
| 21 | `ipsec_route_based_connection_get_ipv4` | DEFERRED | VPN mutation: connectivity risk, excluded by the task |
| 22 | `sslvpn_bookmark_group_get` | DEFERRED | VPN mutation: connectivity risk, excluded by the task |
| 23 | `sslvpn_bookmark_get` | DEFERRED | VPN mutation: connectivity risk, excluded by the task |
| 24 | `sslvpn_clientless_policy_get` | DEFERRED | VPN mutation: connectivity risk, excluded by the task |

**Tally: 6 PASS, 1 BLOCKED, 17 DEFERRED.** The phase-4 split of 71 PASS / 24 SKIP / 3 FAIL
becomes **77 PASS / 18 SKIP** for the read-only surface, with the 18 SKIPs now classified as
1 appliance-blocked and 17 deferred. The three phase-4 FAILs were fixed in 0.5.0 and are not
re-measured here.

**Supplementary (not a SKIP conversion):** `address_get_ipv6` was already PASS in phase 4,
but only by UUID. This run also read an IPv6 address **by name** (`200`), so both identifier
forms are now covered for that tool.

## 7. Defects and observations

### P5-D1 — `dns_host_entry_get` and `dns_host_entry_list` drop the host entry address

**Severity:** medium (output contract). The tool returns a schema-valid object with the
payload silently missing, which is the failure mode phase 4 called out as worse than an error.

**Tool:** `dns_host_entry_get` (`getDnsHostEntryById`), and `dns_host_entry_list`
(`getAllDnsHostEntries`) — both project through `models.DnsHostEntry`.

**Evidence.** A fixture was created with a nested IPv4 host entry and read back twice, once
with a direct REST `GET` and once through the tool:

```text
GET /network/dns/host-entries/mcp-test-p5d904810-dns   -> 200
{"id": "c83ed35b-…", "name": "mcp-test-p5d904810-dns", "domain": "p5d904810.invalid",
 "enableReverseResolution": false,
 "hostEntries": [{"ipv4": {"ipv4Address": "192.0.2.11"},
                  "ttl": 60, "weight": 1, "publishOnWan": false}], …}

dns_host_entry_get {"request": {"id_or_name": "mcp-test-p5d904810-dns"}}  -> 200
{"id": "c83ed35b-…", "name": "mcp-test-p5d904810-dns", "domain": "p5d904810.invalid",
 "enableReverseResolution": false,
 "hostEntries": [{"ttl": 60, "weight": 1, "publishOnWan": false,
                  "ipv4Address": null, "ipv4Interface": null,
                  "ipv6Address": null, "ipv6Interface": null}], …}
```

The appliance stores and returns the address under `hostEntries[].ipv4.ipv4Address`; the
output model declares flat `ipv4Address` / `ipv4Interface` / `ipv6Address` / `ipv6Interface`
members (`models/network.py`, `DnsHostEntryRecord`), so every address and interface is
projected as `null`. The `ttl`, `weight` and `publishOnWan` members survive because they are
flat in both shapes.

**Expected behaviour:** the projection should read the nested `ipv4` / `ipv6` object and
surface the address (either flattened or as the nested object the appliance sends).

**Impact:** a caller cannot see which address a DNS host entry points to. The object is
otherwise correct, so the defect is invisible to schema validation — exactly the class the
phase-4 run was designed to catch.

**Not fixed here:** this record is evidence only; the fix belongs to a follow-up task.

### P5-O1 — the DHCP relay sub-resource returns `401` for every object (corrects phase-4 M9)

**Severity:** medium for the tool (it can never succeed on this firmware); the appliance
behaviour, not a server defect.

Phase 4 recorded M9 as "an unknown UUID returns 401, so the endpoint may require a permission
the read-only profile lacks". The corrected observation, from a **real, listed** relay:

- `GET /network/dhcp/relays/ipv4/{name}` → `401 unauthenticated`
- `GET /network/dhcp/relays/ipv4/{uuid}` → `401 unauthenticated`
- `DELETE /network/dhcp/relays/ipv4/{name}` and `/{uuid}` → `401 unauthenticated`
- `GET /network/dhcp/relays/ipv4` (collection) → `200`, the relay is listed
- `POST /network/dhcp/relays/ipv4` (create) → `201`

The same token authenticates the collection and the create, so the sub-resource route is the
problem, not the credential or the object. A control probe rules out "route missing": an
unknown path returns `404 "404 page not found"`, while the relay sub-resource returns `401`
for a non-existent name too, in both the IPv4 and the IPv6 family.

**Impact:** `dhcp_relay_get_ipv4` and `dhcp_relay_get_ipv6` cannot be exercised on SFOS 23.0.0
GA-Build371. The tool's error message ("authentication failed: the API key is missing, invalid
or expired") is misleading here — the key is valid — but the server cannot distinguish the
appliance's mislabelled `401` from a real authentication failure.

### P5-O2 — the interface reference must be the logical name, not the hardware name

**Severity:** low (contract documentation). The checked-in OpenAPI documents the wrong value
for two create bodies.

| Operation | Contract says | Appliance accepts |
|---|---|---|
| `createDhcpRelayIpv4` | `interface.name`: "Hardware name of the interface" | `"DMZ - Services"` (logical name); `"Port3"` → `500 interfaceDoesNotExist` |
| `createStaticNeighborIpv4` | `interface.name`: "Physical interface of the neighbor" | `"DMZ - Services"` (logical name); `"Port3"` → `400 "Invalid interface."` |

Both were isolated by probing the same body with `Port3` (the hardware name the contract
documents) and `DMZ - Services` (the logical name): the hardware name is rejected and the
logical name is accepted. The MCP server exposes no create tool for either type, so this does
not affect the tool surface today, but it will matter for anyone building these bodies from
the contract.

### P5-O3 — `dhcp_relay_get_ipv4` accepts only a UUID, while the contract path is `{idOrName}`

**Severity:** low (contract inconsistency). The operation is `getDhcpRelayByIdIpv4` on
`/network/dhcp/relays/ipv4/{idOrName}`, and its description says "based on the ID or name",
but the path parameter schema is `format: uuid`. The tool follows the schema and requires
`request.id` (a UUID); a name is rejected at input validation with the UUID pattern message.
The tool is consistent with the schema and inconsistent with the operation name and
description; the contract should pick one.

### P5-O4 — response envelopes are still inconsistent (extends phase-4 O2)

**Severity:** low. Within this one run, two tools returned an `{"address": {…}}` envelope and
five returned the object flat:

| Tool | Shape |
|---|---|
| `address_get_ipv6` | `{"address": {…}}` |
| `mac_address_get` | `{"address": {…}}` |
| `address_group_get_ipv6` | flat |
| `firewall_rule_get_ipv6` | flat |
| `nat_rule_get_ipv6` | flat |
| `dns_host_entry_get` | flat |
| `static_neighbor_get_ipv4` | flat |

Phase-4 O2 recorded this for IPv4 addresses; the IPv6 and MAC families behave the same way,
so a client must special-case three tools, not one.

### P5-O5 — the output naming split is visible within one run (phase-4 M2, still open)

**Severity:** low. `firewall_rule_get_ipv6` returns camelCase (`ruleType`, `logTraffic`,
`sourceZones`, `destinationZones`, `servicesOrGroups`) while `nat_rule_get_ipv6` returns
snake_case (`linked_firewall_rule`, `original_services_or_groups`,
`load_balancing_method`, `original_source_networks`). A caller reading both rule families
must handle two naming conventions. This is the open M2 item, now confirmed on the IPv6
family as well.

## 8. Cleanup confirmation

**Baseline == final.** Counts and the full sorted name list of every touched collection were
compared before and after the run; both are identical.

| Collection | Baseline | Final | Names identical |
|---|---|---|---|
| IPv6 addresses | 3 | 3 | yes |
| IPv6 address groups | 0 | 0 | yes |
| IPv6 firewall rules | 0 | 0 | yes |
| IPv6 NAT rules | 0 | 0 | yes |
| MAC addresses | 0 | 0 | yes |
| DHCP relays (IPv4) | 0 | 0 | yes |
| DNS host entries | 0 | 0 | yes |
| Static neighbours (IPv4) | 0 | 0 | yes |

**Every created object is gone.** Each delete returned `200` and the follow-up `GET` returned
`404` (the relay was verified through the collection, which is the only readable path):

| Object | Delete | Follow-up read |
|---|---|---|
| `mcp-test-p5s6ac825-ipv6` | 200 | 404 |
| `mcp-test-p5s6ac825-ipv6m` | 200 | 404 |
| `mcp-test-p5s6ac825-ipv6grp` | 200 | 404 |
| `mcp-test-p5s6ac825-fw6` | 200 | 404 |
| `mcp-test-p5s6ac825-nat6` | 200 | 404 |
| `mcp-test-p5s6ac825-mac` | 200 | 404 |
| `mcp-test-p5s6ac825-relay` | 200 (delete endpoint, one item) | collection empty |
| `mcp-test-p5s6ac825-dns` | 200 | 404 |
| `mcp-test-p5s6ac825-neigh` | 200 | 404 |

**Final sweep.** A fresh server process read 17 collections (13 paginated to exhaustion, 4
unpaginated) and searched for the string `mcp-test` (case-insensitive): **0 matches**. The swept collections were
IPv4/IPv6 addresses, IPv4/IPv6 address groups, IPv4/IPv6 firewall rules, IPv4/IPv6 NAT rules,
MAC addresses, DNS host entries, DNS request routes, IPv4/IPv6 static neighbours, IPv4/IPv6
DHCP relays and IPv4/IPv6 DHCP servers.

**Nothing remains on the appliance from this run.** No cleanup failure occurred. The three
focused probes (interface shape, relay sub-resource, DNS projection) created four objects in
total and removed every one inside the same probe; their collections were empty afterwards.

## 9. What this run does not prove

| Not validated | Reason |
|---|---|
| The 17 deferred get-by-id paths (§6) | No object was created: connectivity risk (gateways, routes, IPsec, SSL VPN) or no create tool (DHCP server, DNS request route, IPv6 relay, IPv6 neighbour) |
| `dhcp_relay_get_ipv4` | The appliance returns `401` on the sub-resource for a real object (P5-O1) |
| `dhcp_relay_get_ipv6` | No IPv6 relay was created; the sub-resource shows the same `401` signature for a non-existent name |
| Update (`PATCH`) on any of the nine object types | Out of scope for this task; phase-4 write validation covers the IPv4 families |
| `firewall_rule_set_enabled_*`, `*_move_*`, `firewall_rule_clone_*` | Deliberately not exercised: they would enable or reorder rules |
| Bulk delete | Excluded by the safety rules; the one delete-endpoint call named a single object |
| IPv6 static neighbour, IPv6 DHCP relay, IPv6 DHCP server | Not in the agreed disposable-object list |
| General firmware compatibility | One appliance on SFOS 23.0.0 GA-Build371, 15 November 2026 |

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
The three out-of-band fixtures were created with a direct REST `POST` to the same base path
(`/api/firewall-config/v1`) using the same Bearer token, because the server exposes no create
tool for DHCP relays, DNS host entries or static neighbours.

To reproduce P5-D1 without any write, the projection can be inspected locally: the appliance
shape is `hostEntries[].ipv4.ipv4Address`, while `models.DnsHostEntryRecord` declares flat
`ipv4Address` / `ipv4Interface` / `ipv6Address` / `ipv6Interface` members, so a nested payload
projects to four `null`s.
