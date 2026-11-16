# Live evidence — 0.7.0 against SFOS 23.0.0 GA-Build371

**Date:** 16 November 2026. **Server:** `sophos-firewall-mcp-server` 0.7.0 (112 tools, 74 read-only /
38 mutations). **Appliance:** 10.10.10.1:443, SFOS 23.0.0 GA-Build371.

## 1. The live suite on the released surface

The opt-in suite (`pytest -m live`) was migrated to 0.7.0 in the phase-8 review fixes: it expects the
74-tool read-only surface and calls every tool with flat arguments.

```
76 passed, 24 skipped, 1237 deselected
```

The 24 skips are `get`-by-id tests whose collection is empty on this appliance (no object of that kind),
not failures. The suite is read-only by construction (`read_only_mode=True`), so it cannot create the
object it needs.

## 2. Closing the safe subset of the skips

Four disposable objects were created with the write-mode server, the live suite was run while they
existed, and every object was deleted afterwards:

| Object | Created | Read back | Deleted |
|---|---|---|---|
| MAC address (`mcp-test-mac-*`) | 201 | 200 | 200 |
| IPv6 address group (`mcp-test-grp6-*`) | 201 | 200 | 200 |
| IPv6 firewall rule (`mcp-test-fw6-*`, `enabled: false`) | 201 | 200, `enabled: false` | 200 |
| IPv6 NAT rule (`mcp-test-nat6-*`) | **400 `invalidRequest`** | — | — |

With the three objects present the suite reported:

```
79 passed, 21 skipped, 1237 deselected
```

So three more `get`-by-id paths are now verified end to end: `mac_address_get`,
`address_group_get_ipv6` and `firewall_rule_get_ipv6`. Cleanup was verified: every created object was
deleted and the collections returned to their baseline.

## 3. New finding — `nat_rule_create` for IPv6 answers a generic 400

`nat_rule_create` with `ip_family: "ipv6"`, `enabled: false`, `any` services/interfaces/networks and
`translated_source: {"masq": true}` returns **HTTP 400 `invalidRequest`** with no field detail. The IPv4
equivalent was validated in phase 4. The appliance does not say which field it rejects, and the server
surfaces only the sanitized message. This is recorded as a defect candidate: either the IPv6 NAT create
needs a field the tool does not send (for example a linked firewall rule or an explicit translation
address), or the appliance rejects the `masq` translation for IPv6.

## 4. What remains skipped, and why

| Group | Tools | Why |
|---|---|---|
| No create tool in the server | `dns_host_entry_get`, `dns_request_route_get`, `dhcp_server_get_ipv6`, `dhcp_relay_get_ipv4/ipv6`, `static_neighbor_get_ipv4/ipv6` | The object must exist on the appliance; the server exposes no create for these kinds. |
| Connectivity risk | `wan_gateway_get_ipv6`, `custom_gateway_get_ipv4/ipv6`, `unicast_route_get_ipv4/ipv6`, `sdwan_route_get_ipv4/ipv6`, `ipsec_failover_group_get`, `ipsec_policy_based_connection_get_ipv4`, `ipsec_route_based_connection_get_ipv4`, `sslvpn_bookmark_group_get`, `sslvpn_bookmark_get`, `sslvpn_clientless_policy_get` | Creating one can change routing or remote access; the server exposes no mutation for them. |
| Blocked by the appliance | `nat_rule_get_ipv6` | The create returns 400 (section 3). |

## 5. Not verified

- The 403 path: the lab key has full permissions, so a real permission denial cannot be produced without
  a restricted key.
- Ambiguous writes: mock-only; a live timeout on a real write was not induced.
- The appliance model: the API does not expose it.
