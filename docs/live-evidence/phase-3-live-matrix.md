# Live evidence — phase 3 read-only matrix (15 November 2026)

**Scope:** read-only verification of the complete 152-tool MCP surface against the lab
appliance, for issue [#32](https://github.com/lordraiden/sophos-firewall-mcp/issues/32)
(T34). **Only `GET` requests were sent.** No `POST`, `PATCH`, `DELETE`, bulk delete, move,
disconnect, login/logout or interface/VPN change was attempted. The lab key belongs to a
read-only administrator and the suite forces `SOPHOS_READ_ONLY_MODE=true`, so the 54
mutation tools are never registered and cannot be called by the run.

This file follows the record format in [`README.md`](README.md). It is append-only: a later
run adds a new dated section instead of rewriting this one.

## 1. Environment

| Field | Value |
|---|---|
| Appliance model | `unknown` — the Configuration REST API exposes no model endpoint; the appliance hostname is `SophosXGHome` |
| SFOS build | `unknown` — the API exposes no version endpoint (`GET /administration/system-settings` returns only `hostname`, `loginDisclaimer`, `updatedAt`); no firmware compatibility is claimed |
| Administrator profile / permissions | `Read only Admin` (47 permissions, all `readOnly`), inferred from the administrator list; the API does not expose which administrator created the key |
| API allowlist source | `unknown` — not exposed by the API; configured in Administration → API access (maximum 64 entries) |
| Date | 2026-11-15 (UTC) |
| Endpoint | `10.10.10.1:443`, base path `/api/firewall-config/v1`; the key is never recorded |
| TLS | Appliance self-signed certificate; `SOPHOS_VERIFY_SSL=false` for this lab run only |
| Evidence source | `pytest -m live -q tests/live/` (`tests/live/test_live_reads.py`), plus the raw `GET` probes cited in §4 |
| Key rotation status | Not rotated after the run; the owner rotates it when the lab work ends |
| MCP protocol | 2026-07-28 (SDK v2.3.0, `mode="auto"`); the legacy `initialize` handshake was also verified in `tests/test_mcp_e2e.py` |

### Command

```bash
SOPHOS_HOST=10.10.10.1 SOPHOS_PORT=443 \
SOPHOS_API_KEY="<read-only key from LAB-ACCESS.md>" \
SOPHOS_VERIFY_SSL=false SOPHOS_READ_ONLY_MODE=true \
uv run --no-sync pytest -m live -q tests/live/
```

### Tooling note

MCP Inspector is not installed on this host and is not required: the official MCP Python
SDK v2 `Client` is the reference implementation of the protocol and is what
`tests/test_mcp_e2e.py` uses for discovery, schema, annotation, `isError`, cancellation and
STDIO verification. The STDIO transport is additionally driven by hand (raw JSON-RPC on
stdin, every stdout line parsed as JSON-RPC) to prove that stdout carries only the protocol.

### Result

| Metric | Value |
|---|---|
| Read-only tools exercised | **98** (the full read-only surface; the 54 mutations are not registered) |
| PASS | **74** |
| SKIP (no object of that kind on this appliance) | **24** |
| FAIL | **0** (after the two fixes in §4) |
| Extra live assertions | read-only surface = 98 tools and 0 mutations; `pageTotal=true` pagination metadata |

## 2. Per-domain results

One row per read-only MCP tool. `PASS` means the appliance returned the documented status
and the tool projected an object-rooted output. `SKIP` means the appliance holds no object
of that kind, so the get-by-id operation could not be exercised; it is a deferral, not a
pass. The `items` column records the number of objects the list operation returned on this
appliance.

### Firewall rules

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `firewall_rule_list_ipv4` | `getAllFirewallRulesIpv4` | `GET /firewall/rules/ipv4` | PASS | 200 | `items` = 47 |
| `firewall_rule_get_ipv4` | `getFirewallRuleIpv4` | `GET /firewall/rules/ipv4/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `firewall_rule_list_ipv6` | `getAllFirewallRulesIpv6` | `GET /firewall/rules/ipv6` | PASS | 200 | `items` = 0 |
| `firewall_rule_get_ipv6` | `getFirewallRuleIpv6` | `GET /firewall/rules/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |

### NAT rules

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `nat_rule_list_ipv4` | `getAllNatRulesIpv4` | `GET /nat/rules/ipv4` | PASS | 200 | `items` = 28 |
| `nat_rule_get_ipv4` | `getNatRuleIpv4ByIdOrName` | `GET /nat/rules/ipv4/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `nat_rule_list_ipv6` | `getAllNatRulesIpv6` | `GET /nat/rules/ipv6` | PASS | 200 | `items` = 0 |
| `nat_rule_get_ipv6` | `getNatRuleIpv6ByIdOrName` | `GET /nat/rules/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |

### Addresses and address groups

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `address_list_ipv4` | `getAllIpAddresses` | `GET /network/addresses/ipv4` | PASS | 200 | `items` = 50 |
| `address_get_ipv4` | `getIpAddressByIdOrName` | `GET /network/addresses/ipv4/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `address_list_ipv6` | `getAllIpv6Addresses` | `GET /network/addresses/ipv6` | PASS | 200 | `items` = 3 |
| `address_get_ipv6` | `getIpv6AddressByIdOrName` | `GET /network/addresses/ipv6/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `address_list_fqdn` | `getAllFqdns` | `GET /network/addresses/fqdn` | PASS | 200 | `items` = 24 |
| `address_get_fqdn` | `getFqdnByIdOrName` | `GET /network/addresses/fqdn/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `address_group_list_ipv4` | `getAllIpv4AddressGroups` | `GET /network/address-groups/ipv4` | PASS | 200 | `items` = 4 |
| `address_group_get_ipv4` | `getIpv4AddressGroupByIdOrName` | `GET /network/address-groups/ipv4/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `address_group_list_ipv6` | `getAllIpv6AddressGroups` | `GET /network/address-groups/ipv6` | PASS | 200 | `items` = 0 |
| `address_group_get_ipv6` | `getIpv6AddressGroupByIdOrName` | `GET /network/address-groups/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `address_group_list_fqdn` | `getAllFqdnGroups` | `GET /network/address-groups/fqdn` | PASS | 200 | `items` = 4 |
| `address_group_get_fqdn` | `getFqdnGroupByIdOrName` | `GET /network/address-groups/fqdn/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `mac_address_list` | `getAllMacAddresses` | `GET /network/addresses/mac` | PASS | 200 | `items` = 0 |
| `mac_address_get` | `getMacAddressByIdOrName` | `GET /network/addresses/mac/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `country_group_list` | `getAllCountryGroups` | `GET /network/address-groups/country` | PASS | 200 | `items` = 8 |
| `country_group_get` | `getCountryGroupByIdOrName` | `GET /network/address-groups/country/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |

### Services and service groups

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `service_list` | `getAllServices` | `GET /network/services` | PASS | 200 | `items` = 50 |
| `service_get` | `getServiceByIdOrName` | `GET /network/services/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `service_group_list` | `getAllServiceGroups` | `GET /network/service-groups` | PASS | 200 | `items` = 1 |
| `service_group_get` | `getServiceGroupByIdOrName` | `GET /network/service-groups/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |

### Authentication users

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `user_list` | `getUsers` | `GET /authentication/users` | PASS | 200 | `items` = 8 |
| `network_user_list` | `getNetworkUsers` | `GET /authentication/users/network-users` | PASS | 200 | `items` = 2 |
| `network_user_get` | `getNetworkUser` | `GET /authentication/users/network-users/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |

### Live users

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `live_user_list` | `getLiveUsers` | `GET /authentication/live-users` | PASS | 200 | `items` = 0 |

### IPsec VPN

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `ipsec_profile_list` | `getProfiles` | `GET /ipsec-vpn/profiles` | PASS | 200 | `items` = 9 |
| `ipsec_profile_get` | `getProfile` | `GET /ipsec-vpn/profiles/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `ipsec_failover_group_list` | `getFailovergroups` | `GET /ipsec-vpn/site-to-site/failover-groups` | PASS | 200 | `items` = 0 |
| `ipsec_failover_group_get` | `getFailovergroup` | `GET /ipsec-vpn/site-to-site/failover-groups/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `ipsec_connection_list_ipv4` | `listIpsecConnectionsIpv4` | `GET /ipsec-vpn/site-to-site/connections/ipv4` | PASS | 200 | `items` = 0 |
| `ipsec_policy_based_connection_list_ipv4` | `listIpsecPolicyBasedConnectionsIpv4` | `GET /ipsec-vpn/site-to-site/connections/policy-based/ipv4` | PASS | 200 | `items` = 0 |
| `ipsec_policy_based_connection_get_ipv4` | `getPolicyBasedIpsecConnectionIpv4` | `GET /ipsec-vpn/site-to-site/connections/policy-based/ipv4/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `ipsec_route_based_connection_list_ipv4` | `listIpsecRouteBasedConnectionsIpv4` | `GET /ipsec-vpn/site-to-site/connections/route-based/ipv4` | PASS | 200 | `items` = 0 |
| `ipsec_route_based_connection_get_ipv4` | `getRouteBasedIpsecConnectionIpv4` | `GET /ipsec-vpn/site-to-site/connections/route-based/ipv4/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `ipsec_live_connection_list_ipv4` | `getIpsecSiteToSiteLiveConnectionsIpv4` | `GET /ipsec-vpn/site-to-site/live-connections/ipv4` | PASS | 200 | `items` = 0 |
| `ipsec_remote_access_settings_get` | `getIpsecRemoteAccessVpnSettings` | `GET /ipsec-vpn/remote-access/settings` | PASS | 200 | documented envelope; object-rooted output |

### SSL VPN

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `sslvpn_remote_access_policy_list` | `getRemoteAccessPolicies` | `GET /ssl-vpn/remote-access/policies` | PASS | 200 | `items` = 1 |
| `sslvpn_remote_access_policy_get` | `getRemoteAccessPolicy` | `GET /ssl-vpn/remote-access/policies/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `sslvpn_bookmark_group_list` | `listBookmarkGroups` | `GET /ssl-vpn/clientless/bookmark-groups` | PASS | 200 | `items` = 0 |
| `sslvpn_bookmark_group_get` | `getBookmarkGroup` | `GET /ssl-vpn/clientless/bookmark-groups/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `sslvpn_bookmark_list` | `getBookmarks` | `GET /ssl-vpn/clientless/bookmarks` | PASS | 200 | `items` = 0 |
| `sslvpn_bookmark_get` | `getBookmark` | `GET /ssl-vpn/clientless/bookmarks/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `sslvpn_clientless_policy_list` | `listClientlessPolicies` | `GET /ssl-vpn/clientless/policies` | PASS | 200 | `items` = 0 |
| `sslvpn_clientless_policy_get` | `getClientlessPolicy` | `GET /ssl-vpn/clientless/policies/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `sslvpn_global_settings_get` | `getSslvpnGlobalSettings` | `GET /ssl-vpn/global-settings` | PASS | 200 | documented envelope; object-rooted output |

### Network architecture

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `network_interface_list` | `listNetworkInterfaces` | `GET /network/interfaces/network-interfaces` | PASS | 200 | `items` = 19 |
| `network_interface_get` | `getNetworkInterface` | `GET /network/interfaces/network-interfaces/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `zone_list` | `getAllZones` | `GET /network/zones` | PASS | 200 | `items` = 5 |
| `zone_get` | `getZone` | `GET /network/zones/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `gateway_list_ipv4` | `getGatewaysIpv4` | `GET /routing/gateways/ipv4` | PASS | 200 | `items` = 1 |
| `wan_gateway_list_ipv4` | `getWanGatewaysIpv4` | `GET /routing/gateways/wan/ipv4` | PASS | 200 | `items` = 1 |
| `wan_gateway_get_ipv4` | `getWanGatewayIpv4ByIdOrName` | `GET /routing/gateways/wan/ipv4/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `custom_gateway_list_ipv4` | `getCustomGatewaysIpv4` | `GET /routing/gateways/custom/ipv4` | PASS | 200 | `items` = 0 |
| `custom_gateway_get_ipv4` | `getCustomGatewayIpv4ByIdOrName` | `GET /routing/gateways/custom/ipv4/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `gateway_list_ipv6` | `getGatewaysIpv6` | `GET /routing/gateways/ipv6` | PASS | 200 | `items` = 0 |
| `wan_gateway_list_ipv6` | `getWanGatewaysIpv6` | `GET /routing/gateways/wan/ipv6` | PASS | 200 | `items` = 0 |
| `wan_gateway_get_ipv6` | `getWanGatewayIpv6ByIdOrName` | `GET /routing/gateways/wan/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `custom_gateway_list_ipv6` | `getCustomGatewaysIpv6` | `GET /routing/gateways/custom/ipv6` | PASS | 200 | `items` = 0 |
| `custom_gateway_get_ipv6` | `getCustomGatewayIpv6ByIdOrName` | `GET /routing/gateways/custom/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `unicast_route_list_ipv4` | `getUnicastRoutesIPv4` | `GET /routing/static-unicast-routes/ipv4` | PASS | 200 | `items` = 0 |
| `unicast_route_get_ipv4` | `getUnicastRouteIPv4` | `GET /routing/static-unicast-routes/ipv4/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `unicast_route_list_ipv6` | `getUnicastRoutesIPv6` | `GET /routing/static-unicast-routes/ipv6` | PASS | 200 | `items` = 0 |
| `unicast_route_get_ipv6` | `getUnicastRouteIPv6` | `GET /routing/static-unicast-routes/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `sdwan_route_list_ipv4` | `listSdwanRoutesIpv4` | `GET /sd-wan/routes/ipv4` | PASS | 200 | `items` = 0 |
| `sdwan_route_get_ipv4` | `getSdwanRouteIpv4` | `GET /sd-wan/routes/ipv4/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `sdwan_route_list_ipv6` | `listSdwanRoutesIpv6` | `GET /sd-wan/routes/ipv6` | PASS | 200 | `items` = 0 |
| `sdwan_route_get_ipv6` | `getSdwanRouteIpv6` | `GET /sd-wan/routes/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `dhcp_server_list_ipv4` | `listDhcpServersIpv4` | `GET /network/dhcp/server/servers/ipv4` | PASS | 200 | `items` = 2 |
| `dhcp_server_get_ipv4` | `getDhcpServerIpv4` | `GET /network/dhcp/server/servers/ipv4/{idOrName}` | PASS | 200 | documented envelope; object-rooted output |
| `dhcp_server_list_ipv6` | `listDhcpServersIpv6` | `GET /network/dhcp/server/servers/ipv6` | PASS | 200 | `items` = 0 |
| `dhcp_server_get_ipv6` | `getDhcpServerIpv6` | `GET /network/dhcp/server/servers/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `dhcp_lease_list_ipv4` | `getDhcpLeasesIpv4` | `GET /network/dhcp/server/leases/ipv4` | PASS | 200 | `items` = 21 |
| `dhcp_lease_list_ipv6` | `getDhcpLeasesIpv6` | `GET /network/dhcp/server/leases/ipv6` | PASS | 200 | `items` = 0 |
| `dhcp_relay_list_ipv4` | `getAllDhcpRelayIpv4` | `GET /network/dhcp/relays/ipv4` | PASS | 200 | `items` = 0 |
| `dhcp_relay_get_ipv4` | `getDhcpRelayByIdIpv4` | `GET /network/dhcp/relays/ipv4/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `dhcp_relay_list_ipv6` | `getAllDhcpRelayIpv6` | `GET /network/dhcp/relays/ipv6` | PASS | 200 | `items` = 0 |
| `dhcp_relay_get_ipv6` | `getDhcpRelayByIdIpv6` | `GET /network/dhcp/relays/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `dns_settings_get` | `getDnsSettings` | `GET /network/dns/settings` | PASS | 200 | documented envelope; object-rooted output |
| `dns_host_entry_list` | `getAllDnsHostEntries` | `GET /network/dns/host-entries` | PASS | 200 | `items` = 0 |
| `dns_host_entry_get` | `getDnsHostEntryById` | `GET /network/dns/host-entries/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `dns_request_route_list` | `getAllDnsRequestRoutes` | `GET /network/dns/request-routes` | PASS | 200 | `items` = 0 |
| `dns_request_route_get` | `getDnsRequestRouteById` | `GET /network/dns/request-routes/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `static_neighbor_list_ipv4` | `getAllStaticNeighborIpv4s` | `GET /network/neighbors/static/ipv4` | PASS | 200 | `items` = 0 |
| `static_neighbor_get_ipv4` | `getStaticNeighborIpv4` | `GET /network/neighbors/static/ipv4/{idOrName}` | SKIP | — | no object of this kind on the appliance |
| `static_neighbor_list_ipv6` | `getAllStaticNeighborIpv6s` | `GET /network/neighbors/static/ipv6` | PASS | 200 | `items` = 0 |
| `static_neighbor_get_ipv6` | `getStaticNeighborIpv6` | `GET /network/neighbors/static/ipv6/{idOrName}` | SKIP | — | no object of this kind on the appliance |

### Network status

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `network_status_dns_protection` | `getDnsProtectionStatus` | `GET /network/dns/protection/status` | PASS | 200 | documented envelope; object-rooted output |
| `network_status_cellular_wan` | `getCellularWanStatus` | `GET /network/cellular-wan/modem-status` | PASS | 200 | documented envelope; object-rooted output |

### Audit (composite)

| MCP tool | operationId | method + path | result | HTTP | observation |
|---|---|---|---|---|---|
| `audit_firewall_rules` | `getAllZones`, `getAllFirewallRulesIpv4`, `getAllFirewallRulesIpv6`, `getAllNatRulesIpv4`, `getAllNatRulesIpv6`, `getAllIpAddresses`, `getAllIpv6Addresses`, `getAllFqdns`, `getAllIpv4AddressGroups`, `getAllIpv6AddressGroups`, `getAllFqdnGroups`, `getAllServices`, `getAllServiceGroups` | composite of 13 GET operations | PASS | 200 | composite read; object-rooted output |
| `explain_connectivity` | `listNetworkInterfaces`, `getAllZones`, `getAllFirewallRulesIpv4`, `getAllFirewallRulesIpv6`, `getAllNatRulesIpv4`, `getAllNatRulesIpv6`, `getGatewaysIpv4`, `getGatewaysIpv6`, `getUnicastRoutesIPv4`, `getUnicastRoutesIPv6` | composite of 10 GET operations | PASS | 200 | composite read; object-rooted output |
| `find_object_usage` | `getAllIpAddresses`, `getAllIpv6Addresses`, `getAllFqdns`, `getAllServices`, `getAllFirewallRulesIpv4`, `getAllFirewallRulesIpv6`, `getAllNatRulesIpv4`, `getAllNatRulesIpv6`, `getAllIpv4AddressGroups`, `getAllIpv6AddressGroups`, `getAllFqdnGroups`, `getAllServiceGroups` | composite of 12 GET operations | PASS | 200 | composite read; object-rooted output |


## 3. Live/contract/unsupported/deferred matrix

The generated [`docs/API-COVERAGE.md`](../API-COVERAGE.md) is the authoritative coverage
matrix; this table is the phase-3 summary the Lead folds into it.

**Counting method.** The **Operations in v1** column counts audited OpenAPI operations; the
**Live-tested** and **Contract-tested only** columns count MCP tools. The 152 tools are the
145 operation-backed tools plus the 3 read-only audit composites and the 4 firewall
composites (the composites add no operation; the firewall ones are mutations). The 54
mutation tools are therefore 50 operation-backed mutations plus the 4 firewall composites,
and the read-only column sums to 98.

| Domain | Operations in v1 | Live-tested (this run) | Contract-tested only | Unsupported / excluded | Deferred |
|---|---|---|---|---|---|
| Firewall rules | 12 | 4 read tools (list/get IPv4; list IPv6) | 12 mutations (8 operations: create/update/delete/move × IPv4/IPv6; 4 composites: set-enabled ×2, clone ×2) | bulk delete, WAF `ruleType` | IPv6 get-by-id (no IPv6 rule on the appliance); all writes |
| NAT rules | 12 | 4 read tools (list/get IPv4; list IPv6) | 8 mutations | bulk delete | IPv6 get-by-id; all writes |
| Addresses and groups | 37 | 16 read tools (IPv4/IPv6/FQDN addresses, MAC, country, address groups) | 21 mutations (address/group/MAC CRUD) | country-group mutations, MAC bulk delete | IPv6 address-group get-by-id; MAC get-by-id; all writes |
| Services | 10 | 4 read tools | 6 mutations | — | all writes |
| Authentication users | 6 | 3 read tools (`getUsers`, `getNetworkUsers`, `getNetworkUser`) | 3 mutations (network-user CRUD) | administrators, user groups, login/logout | all writes |
| Live users | 2 | 1 read tool (`getLiveUsers`) | 1 mutation (`disconnectLiveUser`) | — | disconnect (destructive) |
| IPsec VPN | 11 | 11 read tools | 0 | all VPN mutations; IPv6 site-to-site (absent from the contract) | get-by-id for failover groups and policy/route-based connections (no objects) |
| SSL VPN | 9 | 9 read tools | 0 | all SSL VPN mutations | get-by-id for bookmark groups, bookmarks and clientless policies (no objects) |
| Network architecture | 44 | 41 read tools | 3 VLAN-only writes | physical/bridge/LAG/XFRM writes; zones, gateways, routes, SD-WAN, DHCP, DNS, neighbor mutations | get-by-id for empty collections; all writes |
| Network status | 2 | 2 read tools | 0 | generic firewall-health tool (no endpoint) | — |
| Audit (composite) | 0 new | 3 composite tools | 0 | — | — |
| **Total** | **145 operations / 152 tools** | **98 read tools** | **54 mutations** | see above | see above |

## 4. Deviations found on the appliance (and fixed)

Both deviations were reproduced independently by the Lead with read-only `GET` requests and
fixed with a Lead-approved, output-model-only patch (15 Nov 2026). The regression tests are
in [`tests/test_live_deviations.py`](../../tests/test_live_deviations.py).

### 4.1 Empty address lists on the built-in internal objects

| Field | Value |
|---|---|
| Endpoint | `GET /network/addresses/ipv4?page=1&pageSize=100&pageTotal=true` and `GET /network/addresses/ipv6` |
| Observed | 200; `pages.items = 119`; exactly three IPv4 objects (`##ALL_IPSEC_RW`, `##ALL_RW`, `##ALL_SSLVPN_RW`) and their IPv6 equivalents have `type: "ipv4List"` / `"ipv6List"` with `"ipv4Addresses": []` / `"ipv6Addresses": []` |
| Contract | `getAllIpAddresses` → `ipv4AddressIpList` declares `ipv4Addresses` with `minItems: 1`; the IPv6 schema is equivalent |
| Effect before the fix | the output model rejected the whole page, so `address_list_ipv4`, `address_list_ipv6`, `address_get_ipv4`/`address_get_ipv6` (via the list), `audit_firewall_rules` and `find_object_usage` for address types all failed with a sanitized `ToolError` |
| Fix | the **output** models `Ipv4AddressIpList` / `Ipv6AddressIpList` accept an empty array; the create/update **input** models keep `min_length=1` |
| After the fix | all five tools PASS live; a genuinely malformed payload still yields the sanitized `ToolError` |

### 4.2 Empty-string timestamp on the DNS settings

| Field | Value |
|---|---|
| Endpoint | `GET /network/dns/settings` |
| Observed | 200 with `"updatedAt": ""` (empty string) |
| Contract | `updatedAt` is declared `format: date-time` |
| Effect before the fix | `dns_settings_get` failed with a sanitized `ToolError` |
| Fix | `DnsSettings.updatedAt` maps only `""` to `None` via a `field_validator(mode="before")`; any other non-date-time value still fails |
| After the fix | `dns_settings_get` PASSes live; a malformed timestamp still yields the sanitized `ToolError` |

## 5. Observations recorded but not fixed

These are real appliance behaviours that do not break a tool. They are recorded so the
coverage matrix does not imply more than was observed.

1. **`pages` metadata varies by endpoint.** Most lists return
   `{current, size, maxSize, total, items}`; `pageTotal=true` populates `total`/`items`.
   `dhcp_server_list_ipv4/ipv6` and `dhcp_relay_list_ipv4/ipv6` return no `pages` at all
   (the contract does not declare it), and `dhcp_lease_list_ipv4/ipv6` return
   `{fromKey, nextKey, total, items, size, maxSize}`. The models preserve each shape; no
   client-side pagination is invented.
2. **`ipsec_live_connection_list_ipv4` reports `maxSize: 1000`**, while every other list
   reports `maxSize: 100`. The model preserves the value; the client still caps
   `pageSize` at 100.
3. **Internal `##` objects cannot be addressed by name.** `address_get_ipv4` with
   `##ALL_RW` is rejected before I/O because the identifier is not a valid single URL path
   segment (the contract's name pattern also excludes `#`). The live test addresses those
   objects by UUID, which works. This is correct input validation, not a defect.
4. **Names containing `/` cannot be used as path segments.** `address_group_get_fqdn` for
   `FQDN Group - Pipeline/parsing errors` is rejected before I/O; the same object is
   readable by UUID. The live test falls back to the UUID.
5. **Pagination field naming differs between domains.** The firewall and NAT list inputs
   expose the wire names (`pageSize`, `pageTotal`), while the network and object list inputs
   expose snake_case names with camelCase aliases (`page_size`/`pageSize`). Both are
   accepted where declared; the inconsistency is model-facing only and is not changed in
   phase 3.
6. **`pageSize > 100` is rejected with `400 invalidPageSizeParam`** on every list, including
   the ones whose contract declares no maximum (confirmed again with `pageSize=200`). The
   client validates `1 <= pageSize <= 100` before any I/O.
7. **`page=0` is accepted by the appliance** with `current: 0` although the contract declares
   `minimum: 1`; the client rejects it before I/O.

## 6. Deferrals

| Deferred operation or domain | Reason | Owner | Prerequisite |
|---|---|---|---|
| All 54 mutation tools (firewall/NAT/address/service/user CRUD, moves, set-enabled, clone, VLAN writes, `disconnectLiveUser`) | The lab key is read-only; a write would mutate the appliance | #32 / repository owner | A write-capable key plus a disposable-object plan approved by the owner |
| IPv6 get-by-id for firewall rules, NAT rules and address groups | The appliance holds no IPv6 object of those kinds | #32 | An IPv6 object created on a non-production appliance |
| MAC address get-by-id | `getAllMacAddresses` returns 0 objects | #32 | A MAC object on a non-production appliance |
| Get-by-id for custom/WAN IPv6 gateways, static unicast routes, SD-WAN routes, DHCP relays, DNS host entries, DNS request routes, static neighbors, IPsec failover groups and policy/route-based connections, SSL VPN bookmark groups/bookmarks/clientless policies | The corresponding list operation returns 0 objects | #32 | Objects created on a non-production appliance |
| Real PATCH merge semantics on arrays (the four documented exceptions) | Requires a write key | #32 | Write key + disposable-object plan |
| Effective `403` denial for writes with a read-only profile | Requires a write attempt | #32 | Write key + owner approval |
| Ambiguous-write reconciliation (timeout then reconcile) | Requires a write | #32 | Write key + disposable-object plan |
| Exact SFOS build and appliance model | The API exposes neither | #32 | Console/CLI access to the appliance, or an owner-provided build string |
| API allowlist source | Not exposed by the API | #32 | Owner-provided Administration → API access configuration |

## 7. What this evidence does not prove

- **No firmware compatibility claim.** The SFOS build is unknown; the results apply to this
  one appliance on 15 November 2026 and must not be generalised to other builds.
- **No write behaviour.** PATCH merge semantics, ambiguous-write reconciliation, permission
  denial and every mutation remain unverified against a real appliance.
- **No proof that the appliance's downloadable OpenAPI matches the checked-in file.** The
  contract SHA in `docs/API-COVERAGE.md` is the audited file; the appliance was not asked
  for its own copy.
- **No load, concurrency or long-running behaviour.** The run is a single sequential pass.
- **No claim about the audit findings' correctness against a real rule base beyond the
  bounded output.** `audit_firewall_rules` returned findings on this appliance; whether each
  finding is operationally correct is a firewall-administration judgement, not a test.
