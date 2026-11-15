# Phase 4 — dogfooding feedback: the released 0.4.0 server against the lab

**Scope:** exercise the **released** server (`sophos-firewall-mcp-server` 0.4.0, installed
from the published tag into `.agents/mcp-venv`) against the real lab appliance over STDIO,
read-only, and record what is wrong with it. This is an adversarial pass: the goal is to
find defects, not to confirm that the happy path returns 200.

**Only `GET` requests were sent.** No `POST`, `PATCH`, `DELETE`, bulk delete, move,
disconnect, login/logout or interface/VPN change was attempted. The lab key belongs to a
read-only administrator and the server was started with `SOPHOS_READ_ONLY_MODE=true`, so the
54 mutation tools are never registered and cannot be called by the run.

This file follows the record format in [`README.md`](README.md). It is append-only: a later
run adds a new dated section instead of rewriting this one.

## 1. Environment

| Field | Value |
|---|---|
| Appliance model | `unknown` — the Configuration REST API exposes no model endpoint; the appliance hostname is `SophosXGHome` |
| SFOS build | `unknown` — the API exposes no version endpoint (`GET /administration/system-settings` returns only `hostname`, `loginDisclaimer`, `updatedAt`); no firmware compatibility is claimed |
| Administrator profile / permissions | `Read only Admin` (47 permissions, all `readOnly`), inferred from the administrator list; the API does not expose which administrator created the key |
| API allowlist source | `unknown` — not exposed by the API |
| Date | 2026-11-15 (UTC), run window 15:57–16:10 |
| Endpoint | `10.10.10.1:443`, base path `/api/firewall-config/v1`; the key is never recorded |
| TLS | Appliance self-signed certificate; `SOPHOS_VERIFY_SSL=false` for this lab run only |
| Server build | `sophos-firewall-mcp-server` **0.4.0** (published tag `v0.4.0`), 98 read-only tools, 0 mutations |
| MCP protocol | 2026-07-28 (official Python SDK `Client`, STDIO) |
| Evidence source | Ad-hoc STDIO driver scripts (official MCP Python SDK `Client`), not committed; the method is reproducible from §2 |
| Key rotation status | Not rotated after the run; the owner rotates it when the lab work ends |

**The appliance is live and changed during the run.** The IPv4 rule count went from 47
(15:59) to 48 (16:04) and the service count from 93 to 94. Counts below are the values
observed at the time of each call; they are not a stable baseline.

## 2. Method

1. Enumerated the 98 read-only tools with their published `inputSchema`, `outputSchema`,
   descriptions and annotations.
2. Called every list tool with `page=1`, `pageSize=10`, `pageTotal=true`, using the
   parameter spelling each tool declares.
3. Called every get-by-id tool twice: once with the `name` and once with the `id` of the
   first object returned by the matching list tool.
4. Called the five no-argument settings/status tools with `{}` and the three composites with
   realistic inputs.
5. Validated every captured `structuredContent` against the tool's published
   `outputSchema` with `jsonschema` (0 violations).
6. Ran adversarial probes: invalid/edge identifiers, pagination bounds, mutually exclusive
   filters, unknown enum values, missing `request` wrapper, unknown fields, bad API key,
   unreachable host, and a 48-case zone × service matrix for `explain_connectivity`.

## 3. Result

| Metric | Value |
|---|---|
| Read-only tools exercised | **98** (the full read-only surface) |
| PASS | **71** |
| SKIP (no object of that kind on the appliance) | **24** |
| FAIL (wrong result or misleading behaviour on a realistic input) | **3** |
| Output-schema violations | **0** |
| Distinct defects recorded | **31** (1 blocker, 4 high, 16 medium, 10 low) |

The three FAILs are not HTTP failures: the appliance answered 200 and the tool projected a
schema-valid object. They fail because the **content is wrong or the advertised parameter
does nothing**, which is worse for an agent than an error.

## 4. Per-tool results

One row per read-only MCP tool. `PASS` means the appliance returned the documented status
and the tool projected a schema-valid, plausible object. `SKIP` means the appliance holds no
object of that kind, so the get-by-id operation could not be exercised; it is a deferral,
not a pass. `FAIL` means the tool returned a wrong result or a misleading message for a
realistic input; the defect id points at §5.

### Firewall rules

| MCP tool | result | input | observation |
|---|---|---|---|
| `firewall_rule_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 10; `pages` present; 48 rules total |
| `firewall_rule_list_ipv6` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0; `pages` present |
| `firewall_rule_get_ipv4` | PASS | `{"request": {"idOrName": "WAN to DMZ34.2 - TORRENT"}}` | object-rooted; 1221 chars; **no `position`** (M12) |
| `firewall_rule_get_ipv6` | SKIP | — | no object of this kind on the appliance |

### NAT rules

| MCP tool | result | input | observation |
|---|---|---|---|
| `nat_rule_list_ipv4` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 10; `pages` present; 28 rules total |
| `nat_rule_get_ipv4` | PASS | `{"request": {"id_or_name": "safeline-mgmt to vector"}}` | object-rooted; 1261 chars; **no SNAT/DNAT kind** (M13) |
| `nat_rule_list_ipv6` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 0; `pages` present |
| `nat_rule_get_ipv6` | SKIP | — | no object of this kind on the appliance |

### Addresses and groups

| MCP tool | result | input | observation |
|---|---|---|---|
| `address_list_ipv4` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 10; 119 total |
| `address_get_ipv4` | PASS | `{"request": {"id_or_name": "<uuid>"}}` | PASS by UUID; **name `##ALL_IPSEC_RW` rejected** before I/O (M3) |
| `address_list_ipv6` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 3 |
| `address_get_ipv6` | PASS | `{"request": {"id_or_name": "<uuid>"}}` | PASS by UUID; **name `##ALL_IPSEC_RW6` rejected** before I/O (M3) |
| `address_list_fqdn` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 10; 24 total |
| `address_get_fqdn` | PASS | `{"request": {"id_or_name": "*.ati.com"}}` | object-rooted; 195 chars |
| `address_group_list_ipv4` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 4 |
| `address_group_get_ipv4` | PASS | `{"request": {"id_or_name": "Internet IPv4 group"}}` | object-rooted; 955 chars |
| `address_group_list_ipv6` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 0 |
| `address_group_get_ipv6` | SKIP | — | no object of this kind on the appliance |
| `address_group_list_fqdn` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 4 |
| `address_group_get_fqdn` | PASS | `{"request": {"id_or_name": "<uuid>"}}` | PASS by UUID; **name with `/` rejected** before I/O (M3) |
| `mac_address_list` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 0 |
| `mac_address_get` | SKIP | — | no object of this kind on the appliance |
| `country_group_list` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 8 |
| `country_group_get` | PASS | `{"request": {"id_or_name": "Africa"}}` | object-rooted; 2402 chars |

### Services

| MCP tool | result | input | observation |
|---|---|---|---|
| `service_list` | **FAIL** | `{"request": {"type": "icmp"}}` | **`type` filter is a silent no-op**: all four enum values return the same 94 services (H2) |
| `service_get` | PASS | `{"request": {"id_or_name": "8080"}}` | object-rooted; 393 chars |
| `service_group_list` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 1 |
| `service_group_get` | PASS | `{"request": {"id_or_name": "PPTP_GROUP"}}` | object-rooted; 307 chars |

### Authentication users

| MCP tool | result | input | observation |
|---|---|---|---|
| `user_list` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 8; snake_case fields (M2) |
| `network_user_list` | PASS | `{"request": {"page": 1, "page_size": 10, "page_total": true}}` | `items` = 2; snake_case fields (M2) |
| `network_user_get` | PASS | `{"request": {"id_or_name": "miriam"}}` | object-rooted; 1296 chars |

### Live users

| MCP tool | result | input | observation |
|---|---|---|---|
| `live_user_list` | PASS | `{}` | `items` = 0; `pages.size` = 50, `total` = null; description names an absent tool (L2) |

### Network architecture

| MCP tool | result | input | observation |
|---|---|---|---|
| `network_interface_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 10; 19 total |
| `network_interface_get` | PASS | `{"request": {"idOrName": "DMZ - Services"}}` | object-rooted; 638 chars |
| `zone_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 5 |
| `zone_get` | PASS | `{"request": {"idOrName": "LAN"}}` | object-rooted; 668 chars |
| `gateway_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 1 (WAN gateway) |
| `wan_gateway_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 1 |
| `wan_gateway_get_ipv4` | PASS | `{"request": {"idOrName": "WAN - Port 1"}}` | object-rooted; 671 chars |
| `custom_gateway_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `custom_gateway_get_ipv4` | SKIP | — | no object of this kind on the appliance |
| `gateway_list_ipv6` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `wan_gateway_list_ipv6` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `wan_gateway_get_ipv6` | SKIP | — | no object of this kind on the appliance |
| `custom_gateway_list_ipv6` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `custom_gateway_get_ipv6` | SKIP | — | no object of this kind on the appliance |
| `unicast_route_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `unicast_route_get_ipv4` | SKIP | — | no object of this kind on the appliance |
| `unicast_route_list_ipv6` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `unicast_route_get_ipv6` | SKIP | — | no object of this kind on the appliance |
| `sdwan_route_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `sdwan_route_get_ipv4` | SKIP | — | no object of this kind on the appliance |
| `sdwan_route_list_ipv6` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `sdwan_route_get_ipv6` | SKIP | — | no object of this kind on the appliance |
| `dhcp_server_list_ipv4` | PASS | `{"request": {}}` | `items` = 2; **no `pages`** (M16) |
| `dhcp_server_get_ipv4` | PASS | `{"request": {"idOrName": "LAN Home - DHCP"}}` | object-rooted; 2621 chars |
| `dhcp_server_list_ipv6` | PASS | `{"request": {}}` | `items` = 0; **no `pages`** (M16) |
| `dhcp_server_get_ipv6` | SKIP | — | no object of this kind on the appliance |
| `dhcp_lease_list_ipv4` | PASS | `{}` | `items` = 21; keyset `pages` with no way to pass `nextKey` (M15) |
| `dhcp_lease_list_ipv6` | PASS | `{}` | `items` = 0; `pages.size` = 0, `maxSize` = 0 |
| `dhcp_relay_list_ipv4` | PASS | `{"request": {}}` | `items` = 0; **no `pages`** (M16) |
| `dhcp_relay_get_ipv4` | SKIP | — | no relay object; an unknown UUID returns **401** (M9) |
| `dhcp_relay_list_ipv6` | PASS | `{"request": {}}` | `items` = 0; **no `pages`** (M16) |
| `dhcp_relay_get_ipv6` | SKIP | — | no object of this kind on the appliance |
| `dns_settings_get` | PASS | `{}` | object-rooted; 499 chars |
| `dns_host_entry_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `dns_host_entry_get` | SKIP | — | no object of this kind on the appliance |
| `dns_request_route_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `dns_request_route_get` | SKIP | — | no object of this kind on the appliance |
| `static_neighbor_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `static_neighbor_get_ipv4` | SKIP | — | no object of this kind on the appliance |
| `static_neighbor_list_ipv6` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `static_neighbor_get_ipv6` | SKIP | — | no object of this kind on the appliance |

### Network status

| MCP tool | result | input | observation |
|---|---|---|---|
| `network_status_dns_protection` | PASS | `{}` | `{"status": "notConfigured", "updatedAt": …}` |
| `network_status_cellular_wan` | PASS | `{}` | `{"noOfModemsDetected": 0, "modem": null}` |

### IPsec VPN

| MCP tool | result | input | observation |
|---|---|---|---|
| `ipsec_profile_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 9 |
| `ipsec_profile_get` | PASS | `{"request": {"idOrName": "DefaultHeadOffice"}}` | object-rooted; 1465 chars |
| `ipsec_failover_group_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0; opaque `filter`/`sort` accepted |
| `ipsec_failover_group_get` | SKIP | — | no object of this kind on the appliance |
| `ipsec_connection_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `ipsec_policy_based_connection_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `ipsec_policy_based_connection_get_ipv4` | SKIP | — | no object of this kind on the appliance |
| `ipsec_route_based_connection_list_ipv4` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `ipsec_route_based_connection_get_ipv4` | SKIP | — | no object of this kind on the appliance |
| `ipsec_live_connection_list_ipv4` | PASS | `{}` | `items` = 0; `pages.size` = 1000 (L9) |
| `ipsec_remote_access_settings_get` | PASS | `{}` | all fields null, `connectionState: "unset"` (L10) |

### SSL VPN

| MCP tool | result | input | observation |
|---|---|---|---|
| `sslvpn_remote_access_policy_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 1 |
| `sslvpn_remote_access_policy_get` | PASS | `{"request": {"idOrName": "Remote SSL VPN Policy"}}` | object-rooted; 1552 chars |
| `sslvpn_bookmark_group_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `sslvpn_bookmark_group_get` | SKIP | — | no object of this kind on the appliance |
| `sslvpn_bookmark_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `sslvpn_bookmark_get` | SKIP | — | no object of this kind on the appliance |
| `sslvpn_clientless_policy_list` | PASS | `{"request": {"page": 1, "pageSize": 10, "pageTotal": true}}` | `items` = 0 |
| `sslvpn_clientless_policy_get` | SKIP | — | no object of this kind on the appliance |
| `sslvpn_global_settings_get` | PASS | `{}` | object-rooted; 1066 chars; no credentials returned |

### Audit (composite)

| MCP tool | result | input | observation |
|---|---|---|---|
| `audit_firewall_rules` | **FAIL** | `{"request": {"ip_family": "ipv6"}}` | **94 false `unused-object` findings** with `rules_examined = 0` (H1); severity-blind truncation (M4); built-in noise (M5) |
| `explain_connectivity` | **FAIL** | `{"request": {"source": {"zone": "LAN"}, "destination": {"zone": "WAN"}, "service": {"name": "SSH"}, "ip_family": "ipv4"}}` | **false `denied` verdict** from a rule whose service list does not match (B1); `no-route` for internet destinations (H4) |
| `find_object_usage` | PASS | `{"request": {"object_type": "service", "identifier": "8080"}}` | 2 references, `reference_count` = 2, truncation flags correct; rejects `#`/`/` names (M3) |

## 5. Issues

Severity: **blocker** = a confident wrong answer that an agent will act on; **high** = a
wrong or misleading answer in a common path; **medium** = a real usability or correctness
gap with a workaround; **low** = cosmetic or documentation noise.

### B1 — blocker — `explain_connectivity` returns a false `denied` verdict when a rule's service criterion does not match

**Tool:** `explain_connectivity`
**Input:** `{"request": {"source": {"zone": "LAN"}, "destination": {"zone": "WAN"}, "service": {"name": "SSH"}, "ip_family": "ipv4"}}`
**Observed:**

```json
{
  "verdict": "denied",
  "verdict_reason": "firewall rule 'DNS to WAN - BLOCK' at position 10 has action 'drop'",
  "decisive_rule": {
    "name": "DNS to WAN - BLOCK",
    "position": 10,
    "action": "drop",
    "matched_fields": ["sourceZones", "destinationZones", "sourceNetworks", "destinationNetworks"]
  }
}
```

The decisive rule's `servicesOrGroups` is `{"services": [{"name": "DNS"}, {"name": "DNS - DoT (853)"}]}`
(verified with `firewall_rule_get_ipv4`). The flow's service is SSH, so the rule's service
criterion is **false** — and `matched_fields` correctly omits `servicesOrGroups` — yet the
rule is still treated as decisive and the verdict is `denied`.

A 48-case matrix (12 zone pairs × 4 service names, `ip_family=ipv4`) produced 4 decisive
verdicts, **3 of them false**:

| source → destination | service | verdict | decisive rule | `servicesOrGroups` matched? |
|---|---|---|---|---|
| LAN → WAN | `HTTPS` | `denied` | `DNS to WAN - BLOCK` | **no** |
| LAN → WAN | `SSH` | `denied` | `DNS to WAN - BLOCK` | **no** |
| LAN → WAN | `NoSuchService` | `denied` | `DNS to WAN - BLOCK` | **no** |
| LAN → WAN | `DNS` | `denied` | `DNS to WAN - BLOCK` | yes |

A **non-existent service name** (`NoSuchService`) is reported as denied by a DNS-only block
rule. An agent will tell the operator that SSH/HTTPS is blocked by a rule that does not
block it. The same missing check applies to an `accept` rule, so the bug can also produce a
false `allowed`; no such rule is reachable first on this appliance, so only the `denied`
direction was observed live.

**Root cause (code reading, `src/sophos_firewall_mcp/tools/audit.py::_evaluate_rules`):**
the loop skips a rule only when a **zone** criterion is `False`:

```python
if zone_source is False or zone_destination is False:
    continue
...
service = _service_match(rule.servicesOrGroups, request.service)
```

`_service_match` returns `False` when the service name is not in the rule's service list and
the rule has no service groups, but that `False` is never used to skip the rule. The same
pattern exists in `_evaluate_nat` (`if value is True: … elif value is None: …` — a `False`
criterion is ignored rather than excluding the rule); it is latent on this appliance because
the NAT rules with specific services also have unresolved networks.

**Expected:** a rule whose service criterion is definitively `False` must be skipped, exactly
like a zone mismatch. The verdict must come from the next matching rule, or be
`not-verifiable`/`no-matching-rule`. A regression test should assert that a flow whose
service is absent from a rule's service list is never decided by that rule.

### H1 — high — `audit_firewall_rules` `ip_family` produces false `unused-object` findings

**Tool:** `audit_firewall_rules`
**Input:** `{"request": {"checks": ["unused-object"], "ip_family": "ipv6"}}`
**Observed:** 94 findings, `rules_examined = 0`, `nat_rules_examined = 0`, including:

```json
{
  "check": "unused-object",
  "severity": "low",
  "summary": "Service '8080' is unused",
  "evidence": {"object_name": "8080", "object_type": "service", "ip_family": null,
               "detail": "No scanned firewall rule, NAT rule or group references this object, so it can be reviewed for removal."}
}
```

`8080` **is** referenced by an IPv4 firewall rule: the default audit (no `ip_family`) does
not report it, and `find_object_usage` for `8080` returns 2 references. With
`ip_family=ipv6` the rule scan reads only the IPv6 rule base (0 rules), so every object
referenced only by IPv4 rules is reported as unused.

The same call also reports the built-in `##ALL_RW6`, `##ALL_IPSEC_RW6` and
`##ALL_SSLVPN_RW6` as removable.

**Expected:** the `unused-object` check must scan the references of **both** families
regardless of `ip_family`, or be listed in `not_verifiable` when the rule scan is restricted
to one family. Reporting an in-use service as removable is the worst possible audit output.

### H2 — high — `service_list` `type` filter is a silent no-op

**Tool:** `service_list`
**Input:** `{"request": {"type": "icmp", "page_size": 100, "page_total": true}}` (and `ip`,
`icmpv6`, `tcpOrUdp`, and no filter)
**Observed:** every variant returns the **same 94 services** with mixed types:

| `type` | items | `pages.items` | returned `type` values |
|---|---|---|---|
| `icmp` | 94 | 94 | `icmp`, `icmpv6`, `ip`, `tcpOrUdp` |
| `ip` | 94 | 94 | `icmp`, `icmpv6`, `ip`, `tcpOrUdp` |
| `icmpv6` | 94 | 94 | `icmp`, `icmpv6`, `ip`, `tcpOrUdp` |
| `tcpOrUdp` | 94 | 94 | `icmp`, `icmpv6`, `ip`, `tcpOrUdp` |
| *(none)* | 94 | 94 | `icmp`, `icmpv6`, `ip`, `tcpOrUdp` |

The client does send the parameter (`GET /network/services?type=icmp&page=1&pageSize=100&pageTotal=true`
→ 200); the appliance ignores it. The tool advertises the filter in its schema and its
description ("`type` filters by the contract enum"), so an agent asking for ICMP services
concludes there are 94 of them.

**Expected:** filter client-side on the projected `type`, or remove the parameter, or state
in the description that the appliance ignores it. A filter that silently returns everything
is worse than no filter.

### H3 — high — HTTP 401 is reported as a permission problem

**Tool:** any (reproduced with `network_status_dns_protection`)
**Input:** server started with `SOPHOS_API_KEY=definitely-not-a-valid-key`
**Observed:**

```
Error executing tool network_status_dns_protection: the Sophos administrator associated
with this API key is not allowed to perform this operation; check its profile permissions
(HTTP 401) [GET /network/dns/protection/status] [error: unauthenticated]
```

The message is self-contradictory: "not allowed to perform this operation" (authorization)
next to `unauthenticated` (authentication). The first thing a new user hits when the key is
wrong sends the agent to change the administrator profile instead of fixing the key.

**Expected:** split the two cases. 401 → "authentication failed: the API key is missing or
invalid (HTTP 401 unauthenticated)". 403 → the current permission message. The
`SophosAuthError` class already covers both statuses, so the mapping needs the status.

### H4 — high — `explain_connectivity` reports `no-route` for internet destinations on an appliance with a WAN default route

**Tool:** `explain_connectivity`
**Input:** `{"request": {"source": {"ip": "10.10.10.50"}, "destination": {"ip": "8.8.8.8"}, "service": {"protocol": "tcp", "port": 443}}}`
**Observed:**

```json
"routing": {
  "decision": "no-route",
  "destination": "8.8.8.8",
  "route_name": null, "gateway": null, "gateway_ip": null, "interface": null,
  "note": "no configured static unicast route matches the destination; dynamic routing is not evaluated"
}
```

The appliance has exactly one gateway, `WAN - Port 1` (`gateway_list_ipv4`, `type: "wan"`,
interface `WAN`, `192.168.144.1`), and zero static unicast routes
(`unicast_route_list_ipv4` → `items: []`). The WAN gateway **is** the default route, so
`no-route` is wrong for any internet destination.

**Root cause (code reading, `_routing_for`):** the function only iterates `routes` (static
unicast routes) and uses `gateways` solely to name the gateway of a matched route. The
`default-route` decision is therefore unreachable unless a static unicast route with prefix
`/0` exists.

**Expected:** treat the active WAN gateway as the default route (decision `default-route`,
`gateway: "WAN - Port 1"`), or say explicitly that the default route is the WAN gateway and
is not modelled. The description already promises "routed over the configured static unicast
routes **and gateways**".

### M1 — medium — input parameter naming is split across the surface (tracked as M1 / 0.5.0)

**Tools:** all list tools
**Observed:** neither spelling works everywhere; the wrong spelling is a hard
`extra_forbidden` error, not a silent default.

| domain | declared | `page_size` accepted | `pageSize` accepted |
|---|---|---|---|
| firewall rules (`firewall_rule_list_*`) | `pageSize`, `pageTotal` | **no** | yes |
| NAT rules (`nat_rule_list_*`) | `page_size`, `page_total` | yes | **no** |
| addresses, groups, MAC, country, services, users (`ListQuery`) | `page_size`, `page_total` | yes | **no** |
| network, routing, DHCP, DNS, neighbours, VPN (`FilteredPageInput`) | `pageSize`, `pageTotal` | yes | yes |

The get tools are split the same way: `idOrName` (firewall, network, VPN), `id_or_name`
(NAT, addresses, services, users), `id` (DHCP relays, UUID only).

**Evidence:** `firewall_rule_list_ipv4` with `{"page_size": 10}` →
`request.page_size Extra inputs are not permitted`; `address_list_ipv4` with
`{"pageSize": 10}` → `request.pageSize Extra inputs are not permitted`.

**Expected:** one spelling on the published surface with the other accepted as an alias
(workstream C). Until then, an agent that learns `page_size` from `address_list_ipv4` cannot
call `firewall_rule_list_ipv4` without a retry.

### M2 — medium — output field naming is split across domains

**Observed:** the projected objects use two conventions for the same concepts:

| domain | convention | example fields |
|---|---|---|
| firewall rules, addresses, groups, services, interfaces, zones, gateways, DHCP servers, leases, IPsec profiles, SSL VPN policies | camelCase | `createdAt`, `updatedAt`, `destinationNetworks`, `linkedFirewallRule` |
| NAT rules, users, network users | snake_case | `created_at`, `updated_at`, `linked_firewall_rule`, `original_services_or_groups` |

An agent that reads `created_at` from a NAT rule and looks for it on a firewall rule gets
`null`/missing. This is the output-side counterpart of M1 and is **not** covered by the
input-naming workstream.

**Expected:** one convention on the output surface (the contract's camelCase is the natural
choice), with the other accepted nowhere.

### M3 — medium — `find_object_usage` and the get tools reject identifiers that the list tools return

**Tools:** `find_object_usage`, `address_get_ipv4`, `address_get_ipv6`, `address_group_get_fqdn`
**Input:** `{"request": {"object_type": "address", "identifier": "##ALL_RW"}}`
**Observed:**

```
Error executing tool find_object_usage: 1 validation error for find_object_usageArguments
request.identifier
  Value error, object identifier must be usable as a single URL path segment; it must not contain '#' …
```

`address_list_ipv4` returns `##ALL_RW`, `##ALL_IPSEC_RW` and `##ALL_SSLVPN_RW` as ordinary
items, and `address_group_list_fqdn` returns `FQDN Group - Pipeline/parsing errors`. Both are
rejected by the get tools and by `find_object_usage`.

For the get tools this is defensible (the name goes into a URL path). For
`find_object_usage` it is not: the tool resolves the identifier from **list output**, never
from a URL, so any name the list returns should be accepted.

**Expected:** `find_object_usage` accepts any name the list returns (or documents "use the
UUID for names containing `#` or `/`"). The get tools should mention the UUID fallback in
the error message.

### M4 — medium — `audit_firewall_rules` truncation is severity-blind

**Tool:** `audit_firewall_rules`
**Input:** `{"request": {"max_findings": 13}}` and `{"request": {"max_findings": 14}}`
**Observed:** findings are emitted grouped by check (`any-any` → `disabled` → `shadowed` →
`no-logging` → `unused-object`), not sorted by severity. With `max_findings=13` or `14` the
**medium** `shadowed` finding is dropped while three **low** `disabled` findings are kept:

| `max_findings` | returned | `shadowed` present | `findings_truncated` |
|---|---|---|---|
| 13 | 13 | **no** | true |
| 14 | 14 | **no** | true |
| 16 | 16 | yes | true |

**Expected:** sort by severity (blocker → high → medium → low) before applying
`max_findings`, so truncation drops the least important findings.

### M5 — medium — `audit_firewall_rules` `unused-object` floods the output with built-in objects

**Tool:** `audit_firewall_rules`
**Input:** `{"request": {}}`
**Observed:** 100 findings (truncated), of which **82 are `unused-object`** (37 addresses,
45 services). Of those 82, **60 are objects the operator cannot remove**:

- 6 built-in `##` objects: `##ALL_RW`, `##ALL_IPSEC_RW`, `##ALL_SSLVPN_RW` and the IPv6 equivalents
- 18 auto-generated `#Port*` objects: `#Port2`, `#Port3`, `#Port3.20` … `#Port3.50`
- 36 built-in services: `AH`, `AOL`, `BGP`, `DHCP`, `FTP`, `PING`, `POP3`, …

The remaining 22 are genuinely user-created and unused (13 `HOST - *`/`DNS - *` addresses and
9 custom services such as `HTTP (8080)` and `Tailscale Server`), which is the signal the
check is for. Each finding carries `detail: "… so it can be reviewed for removal."`, which
is wrong for the 60 system objects. The 13 medium findings (`any-any`, `shadowed`) are
buried under them, and the 100-finding cap is consumed by noise.

**Expected:** exclude built-in/auto-generated objects from `unused-object` (or mark them
`removable: false` and sort them last). The check should report user-created objects only.

### M6 — medium — `audit_firewall_rules` `rule_name_contains` barely reduces the output

**Tool:** `audit_firewall_rules`
**Input:** `{"request": {"rule_name_contains": "zzz-no-match"}}`
**Observed:** 100 findings, 51,991 chars, **all `unused-object`**. The filter correctly
removes the rule-scoped findings, but the non-rule-scoped `unused-object` findings are
unaffected, so a filter that matches nothing still returns a 52 KB report.

**Expected:** when `rule_name_contains` is set, restrict the report to rule-scoped checks
(or say in the description that `unused-object` is unaffected). An agent asking "audit rule
X" should not receive 100 unrelated object findings.

### M7 — medium — `explain_connectivity` is `not-verifiable` for most real flows and hides the candidate rules

**Tool:** `explain_connectivity`
**Input:** four realistic flows (LAN→internet 443, LAN→internet udp/53, LAN→DMZ 53, zone→zone HTTPS)
**Observed:** all four return `verdict: "not-verifiable"`, `firewall_rules: []`,
`decisive_rule: null`, with a reason such as:

> rule 'INT/DMZ to DMZ.30.2 - DNS ACCESS DMZ' at position 8 matches the zones but its
> destinationZones, sourceNetworks, destinationNetworks, servicesOrGroups reference objects
> whose membership this analysis does not resolve

The rule is named only in prose; there is no structured field with its id or position, so
the agent cannot follow up with `firewall_rule_get_ipv4` without parsing the sentence.

**Expected:** include the candidate rules the scan examined (name, id, position, which
criteria matched and which were unresolved) in a structured field. The tool already reads
the address, group and service collections in `audit_firewall_rules` and
`find_object_usage`; resolving membership here would make the flagship tool usable.

### M8 — medium — zone→zone without `ip_family` is `not-verifiable` even when the IPv6 rule base is empty

**Tool:** `explain_connectivity`
**Input:** `{"request": {"source": {"zone": "LAN"}, "destination": {"zone": "WAN"}, "service": {"name": "HTTPS"}}}`
**Observed:** `verdict: "not-verifiable"`, reason "the IP family is ambiguous (both endpoints
are zones), and the IPv4 and IPv6 rule bases do not agree; set ip_family to analyse one of
them". The IPv6 rule base is **empty** (0 rules), so the natural answer is IPv4. Adding
`"ip_family": "ipv4"` resolves the flow correctly (`denied`, rule `DNS to WAN - BLOCK`).

**Expected:** default to the family that has rules, or say "the IPv6 rule base is empty, so
the IPv4 rule base was used".

### M9 — medium — `dhcp_relay_get_ipv4` with an unknown UUID returns 401 `unauthenticated`

**Tool:** `dhcp_relay_get_ipv4`
**Input:** `{"request": {"id": "00000000-0000-0000-0000-000000000000"}}`
**Observed:** the appliance answers **401 Unauthorized** (`[error: unauthenticated]`) for a
UUID that does not exist, and the tool maps it to the permission message of H3. Every other
get tool returns 404 `resourceNotFound` for a missing object.

**Expected:** at minimum, fix the 401 message (H3). Ideally, note in the tool description
that this endpoint may answer 401 for a missing object, so an agent does not conclude that
the key is broken. The endpoint could not be verified with a real relay: the appliance holds
none.

### M10 — medium — the `request` wrapper is not explained anywhere

**Tools:** all 94 tools that take arguments
**Input:** `{"ip_family": "ipv4"}` instead of `{"request": {"ip_family": "ipv4"}}`
**Observed:** `Error executing tool audit_firewall_rules: 1 validation error for
audit_firewall_rulesArguments request Field required`. The descriptions describe the inner
fields ("Inputs: optional ip_family, …") and never mention the wrapper, which is unusual for
MCP (flat arguments are the norm).

**Expected:** state the wrapper in every description, or flatten the arguments. The current
error is cryptic for an agent that followed the description.

### M11 — medium — list and audit outputs are large enough to threaten a model context

**Observed** (default call, no arguments, and the maximum page size; the two columns were
measured minutes apart and the live appliance gained a rule in between, which is why the
default and maximum are not identical for the firewall rules):

| tool | default output | `pageSize=100` output | approx. tokens (default) |
|---|---|---|---|
| `firewall_rule_list_ipv4` | 72,580 chars | 72,576 chars | ~18,000 |
| `audit_firewall_rules` | 53,362 chars | — | ~13,300 |
| `nat_rule_list_ipv4` | 43,879 chars | 43,875 chars | ~11,000 |
| `service_list` | 28,121 chars | 50,605 chars | ~7,000 |
| `network_interface_list` | 16,180 chars | 16,176 chars | ~4,000 |
| `explain_connectivity` | 15,429 chars | — | ~3,900 |

The default `pageSize` is 50. For the firewall rules (48), NAT rules (28) and interfaces
(19) the appliance holds fewer objects than that, so the "default" call returns the whole
collection; for services (94) and addresses (119) it returns the first 50. Two or three such
calls fill a small context.

**Expected:** a smaller default page size for the heavy domains, a documented guidance to
use `pageSize`, or a projection/`fields` parameter. At minimum, say in the description that
a full page of firewall rules is ~70 KB.

### M12 — medium — firewall and NAT rule objects expose no evaluation `position`

**Tools:** `firewall_rule_list_ipv4`, `firewall_rule_get_ipv4`, `nat_rule_list_ipv4`, `nat_rule_get_ipv4`
**Observed:** the projected rule has `id`, `name`, `action`, `enabled`, zones, networks,
services, timestamps — but no `position`. `audit_firewall_rules` and `find_object_usage`
both report `position` for the same rules (`"position": 10`), so the information exists in
the server but is not on the rule object.

**Expected:** include `position` in the rule projection. Evaluation order is the first thing
a firewall analysis needs, and today it can only be obtained by running a full audit.

### M13 — medium — NAT rule objects have no SNAT/DNAT discriminator

**Tool:** `nat_rule_get_ipv4`
**Observed:** the object has `translated_source` and `translated_destination` (both `null`
for the sampled rule) and no field that says whether the rule is SNAT or DNAT. The
appliance's list does not expose one either (already noted in
[`api-smoke-2026-11-15.md`](api-smoke-2026-11-15.md)).

**Expected:** derive and expose a `kind` (`snat`/`dnat`/`unknown`) from which translation
field is populated, or document that it cannot be determined.

### M14 — medium — the same concept has two shapes in NAT and firewall rules

**Observed:**

- firewall rule: `"servicesOrGroups": {"any": false, "services": [{"name": "DNS"}], "serviceGroups": []}`
- NAT rule: `"original_services_or_groups": {"any": null, "services": ["DNS"], "service_groups": []}`

The firewall projection uses objects (`{"name": …}`) and camelCase; the NAT projection uses
bare strings and snake_case. An agent that writes one parser for "the services of a rule"
breaks on the other.

**Expected:** one shape for object references across domains.

### M15 — medium — `dhcp_lease_list_ipv4` returns keyset pagination that cannot be used

**Tool:** `dhcp_lease_list_ipv4`
**Input:** `{}` (the tool takes no arguments)
**Observed:** `pages: {"fromKey": "10.10.10.3", "nextKey": null, "total": null, "items": null, "size": 21, "maxSize": 21}`.
The metadata is keyset (`fromKey`/`nextKey`), but the tool exposes no input, so a non-null
`nextKey` could never be passed back. On this appliance `nextKey` is `null`, so the
truncation is latent.

**Expected:** expose `fromKey`/`nextKey` inputs, or state in the description that only the
first page is reachable and that a non-null `nextKey` means the list is incomplete.

### M16 — medium — four list tools return no `pages` metadata at all

**Tools:** `dhcp_server_list_ipv4`, `dhcp_server_list_ipv6`, `dhcp_relay_list_ipv4`, `dhcp_relay_list_ipv6`
**Observed:** the output is `{"items": []}` (17 chars) with no `pages` key, while every other
list tool returns `items` + `pages`. An agent cannot tell "empty" from "truncated", and a
generic pagination loop breaks on these four.

**Expected:** a consistent envelope. If the contract declares no pagination, return
`pages: null` explicitly (or a synthetic `{"current": 1, "size": <n>, "maxSize": <n>}`) so
the shape is uniform.

### L1 — low — `pages.total` is the page count, not the item count, and nothing says so

**Observed:** `address_list_ipv4` with `pageSize=10` returns
`pages: {"current": 1, "size": 10, "maxSize": 100, "total": 12, "items": 119}` — `total` is
the number of **pages**, `items` is the number of **items**. The published output schema
declares both as bare integers with no description, so `total: 12` reads naturally as
"12 addresses".

**Expected:** document the semantics in the `Pages` model (the field descriptions reach the
published `outputSchema`).

### L2 — low — `live_user_list` description references a tool that is not registered

**Observed:** the description ends "Use `live_user_disconnect` to terminate one session."
In read-only mode that tool is not registered (it is one of the 54 mutations), so an agent
that follows the description calls an unknown tool.

**Expected:** make the sentence conditional, or drop it in read-only mode.

### L3 — low — `audit_firewall_rules` description overstates the finding shape

**Observed:** the description says "Returns at most 100 findings, each with rule name/id,
evaluation position, severity and evidence." The 82 `unused-object` findings have
`rule_name: null`, `rule_id: null`, `position: null`.

**Expected:** say that object-scoped findings carry the object instead of the rule.

### L4 — low — validation errors leak internal model names and a pydantic URL

**Observed:** every argument-validation failure returns a raw pydantic dump:

```
Error executing tool firewall_rule_list_ipv4: 1 validation error for firewall_rule_list_ipv4Arguments
request.page_size
  Extra inputs are not permitted [type=extra_forbidden, input_value=10, input_type=int]
    For further information visit https://errors.pydantic.dev/2.14/v/extra_forbidden
```

The internal argument-model name (`firewall_rule_list_ipv4Arguments`), the pydantic version
and a documentation URL are not useful to a model, and the message is long.

**Expected:** a one-line sanitized message ("unknown argument `page_size`; this tool accepts
`pageSize`"), consistent with the sanitized transport errors.

### L5 — low — no-argument tools silently ignore unknown arguments

**Observed:** `network_status_dns_protection` with `{"bogus": 1}` returns 200 and the normal
payload, while every `request` model rejects unknown fields with `extra_forbidden`.

**Expected:** reject unknown arguments consistently, so a typo is not silently ignored.

### L6 — low — built-in objects carry the epoch as their timestamp

**Observed:** `createdAt`/`updatedAt` are `"1970-01-01T00:00:00Z"` for built-in objects
(`##ALL_RW`, `Internet IPv4 group`, `WAN - Port 1`, …). The appliance uses the epoch as a
"never" sentinel; the tool passes it through.

**Expected:** map the epoch sentinel to `null` (as the DNS settings fix already does for the
empty string), or document it.

### L7 — low — the payload is duplicated in `content` and `structuredContent`

**Observed:** every result carries the pretty-printed JSON in a `TextContent` block **and**
the same object in `structuredContent`. For `firewall_rule_list_ipv4` that is ~72 KB twice.

**Expected:** keep `structuredContent` and a short text summary, or keep the text only. A
client that concatenates both pays double.

### L8 — low — `dhcp_lease_list_ipv4` `pages.maxSize` is the item count

**Observed:** `pages.maxSize = 21` with 21 items. `maxSize` is documented as the maximum page
size elsewhere (100, or 1000 for live IPsec connections), so `21` is misleading.

**Expected:** preserve the appliance value but document that it is not a page-size bound for
this endpoint.

### L9 — low — `ipsec_live_connection_list_ipv4` returns `pages.size = 1000` with no way to page

**Observed:** `pages: {"current": 1, "size": 1000, "maxSize": 1000, "total": null, "items": null}`
and the tool takes no arguments. If more than 1000 live connections existed, the list would
be silently truncated.

**Expected:** expose the pagination the appliance accepts, or state the 1000-item ceiling.

### L10 — low — `ipsec_remote_access_settings_get` returns an all-null object when unset

**Observed:** 15 fields, all `null`, except `connectionState: "unset"`. An agent must know
that `"unset"` means "not configured".

**Expected:** a short `configured: false` flag, or a description sentence.

## 6. Corrections to the phase-3 evidence

The phase-3 matrix ([`phase-3-live-matrix.md`](phase-3-live-matrix.md)) reports "74 PASS,
24 SKIP, 0 FAIL". This run reproduces the 74/24 split but not the "0 FAIL": three tools
return wrong content on a realistic input (§5 B1, H1, H2). The phase-3 pass checked that the
appliance answered 200 and the projection validated; it did not check that the projected
content was correct.

Two specific claims in that file are contradicted by this run:

1. **§5.5** — "the network and object list inputs expose snake_case names with camelCase
   aliases (`page_size`/`pageSize`). Both are accepted where declared." Live, only the
   network/VPN `FilteredPageInput` accepts both. `address_list_ipv4` rejects `pageSize` and
   `firewall_rule_list_ipv4` rejects `page_size` (both `extra_forbidden`). The same paragraph
   also says "the firewall and NAT list inputs expose the wire names (`pageSize`,
   `pageTotal`)"; live, the NAT list inputs expose **snake_case** and reject `pageSize`. See
   M1.
2. **§2** — the `service_list` row says "PASS, `items` = 50". The list does return items, but
   its advertised `type` filter does nothing (H2), which a PASS hides.

## 7. Top fixes

Ordered by the damage an agent can do with the current behaviour:

1. **B1** — skip a rule whose service criterion is `False` in `_evaluate_rules` (and
   `_evaluate_nat`). This is the only finding that produces a confident, actionable, wrong
   answer ("your SSH is blocked by this rule").
2. **H1** — make `unused-object` family-independent, or report it as `not_verifiable` when
   `ip_family` restricts the rule scan. Never tell an operator to delete an in-use service.
3. **H2** — make `service_list`'s `type` filter work client-side, or remove it.
4. **H3** — split the 401 and 403 messages. The first error a new user sees must name the
   real cause.
5. **H4** — model the WAN gateway as the default route in `explain_connectivity`.
6. **M4/M5/M6** — sort findings by severity before truncating, exclude built-in objects from
   `unused-object`, and make `rule_name_contains` actually narrow the report.
7. **M1/M2** — finish the naming unification on both the input and the output surface.
8. **M3** — let `find_object_usage` accept every name the list tools return.
9. **M10/M11** — document the `request` wrapper and the output size, or flatten/shrink them.

## 8. What this run does not prove

- **No firmware compatibility claim.** The SFOS build is unknown; the results apply to this
  one appliance on 15 November 2026.
- **No write behaviour.** PATCH merge semantics, ambiguous-write reconciliation, permission
  denial (`403`) and every mutation remain unverified.
- **No proof that the appliance's downloadable OpenAPI matches the checked-in file.**
- **No load, concurrency or long-running behaviour.** The run is a single sequential pass.
- **The 24 SKIPs are deferrals, not passes.** The get-by-id path for IPv6 rules, IPv6 NAT
  rules, IPv6 address groups, MAC objects, custom/WAN IPv6 gateways, static unicast routes,
  SD-WAN routes, DHCP relays, DNS host entries, DNS request routes, static neighbours, IPsec
  failover groups, policy/route-based IPsec connections, SSL VPN bookmark groups, bookmarks
  and clientless policies could not be exercised because the appliance holds no object of
  that kind.
- **`dhcp_relay_get_ipv4` could not be verified with a real object.** An unknown UUID returns
  401, so the endpoint may require a permission the read-only profile lacks; this is recorded
  as M9, not as a pass.
- **The `service_list` `type` filter result is an appliance observation.** The client sends
  the parameter; the appliance ignores it. Whether another firmware honours it is unknown.

## 9. Deferrals

| Deferred operation or domain | Reason | Owner | Prerequisite |
|---|---|---|---|
| All 54 mutation tools | The lab key is read-only; a write would mutate the appliance | repository owner | A write-capable key plus a disposable-object plan approved by the owner |
| Get-by-id for the 24 empty collections listed in §8 | The appliance holds no object of that kind | phase-4 owner | Objects created on a non-production appliance |
| `dhcp_relay_get_ipv4` with a real relay | No relay object exists; an unknown UUID returns 401 | phase-4 owner | A relay object on a non-production appliance |
| `403` permission denial | Requires a write attempt | repository owner | Write key + owner approval |
| Exact SFOS build and appliance model | The API exposes neither | repository owner | Console/CLI access, or an owner-provided build string |
