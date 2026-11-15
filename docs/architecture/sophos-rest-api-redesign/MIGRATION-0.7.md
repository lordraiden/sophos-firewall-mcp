# Migration to 0.7.0: the IPv4/IPv6 tool pairs collapse behind `ip_family`

**Status:** breaking change, release 0.7.0. **Scope:** 80 tool names removed, 40 tools added.

Before 0.7.0 the server published one tool per IP family: `firewall_rule_list_ipv4` and
`firewall_rule_list_ipv6`, `address_create_ipv4` and `address_create_ipv6`, and so on. That
doubled the surface, doubled the number of names a model had to choose between, and contradicted
the server's own convention: the three audit composites already took an `ip_family` argument.

0.7.0 publishes **one tool per concept** and moves the family axis into a required `ip_family`
argument. The tool count drops from 152 to 112 (40 pairs collapse; the two firewall composite
pairs collapse too), and the `tools/list` payload drops from 807,900 to 655,479 bytes.

## The `ip_family` choice

`ip_family` is **required** on every merged tool, with the enum `ipv4` | `ipv6`. It is not
defaulted, for three reasons:

1. **A default would make a destructive target a guess.** `firewall_rule_delete`,
   `nat_rule_delete`, `firewall_rule_update`, `firewall_rule_move` and
   `firewall_rule_set_enabled` all act on one family's rule base. A default of `ipv4` would
   silently delete or disable the IPv4 rule when the caller meant the IPv6 one. The server's
   safety policy is that a destructive target is never inferred: `enabled` is required on
   `firewall_rule_set_enabled` and `position` on create for the same reason.
2. **A default would hide which family a read returned.** `firewall_rule_list` and
   `address_list` return one family's page; a caller that omitted the family would not know
   which collection it read.
3. **The family is a path selector, not a body member.** The adapter strips `ip_family` before
   the request is sent, so the wire body is byte-identical to the pre-0.7 per-family tool. A
   default would make the published schema say the argument is optional while the runtime
   still had to choose a path.

The three audit composites (`audit_firewall_rules`, `explain_connectivity`,
`find_object_usage`) keep their existing optional `ip_family`: they are read-only and can span
both families, so omitting it means "both". That is the one documented difference, and it is
intentional.

## Migration table

Every removed name maps to one new tool plus the `ip_family` value that reproduces the old
behaviour. The six IPv4-only IPsec tools (`ipsec_connection_list_ipv4`,
`ipsec_live_connection_list_ipv4`, `ipsec_policy_based_connection_get_ipv4`,
`ipsec_policy_based_connection_list_ipv4`, `ipsec_route_based_connection_get_ipv4`,
`ipsec_route_based_connection_list_ipv4`) are unchanged: the API has no IPv6 counterpart.

| Removed tool | New tool | `ip_family` |
|---|---|---|
| `address_create_ipv4` | `address_create` | `ipv4` |
| `address_create_ipv6` | `address_create` | `ipv6` |
| `address_delete_ipv4` | `address_delete` | `ipv4` |
| `address_delete_ipv6` | `address_delete` | `ipv6` |
| `address_get_ipv4` | `address_get` | `ipv4` |
| `address_get_ipv6` | `address_get` | `ipv6` |
| `address_group_create_ipv4` | `address_group_create` | `ipv4` |
| `address_group_create_ipv6` | `address_group_create` | `ipv6` |
| `address_group_delete_ipv4` | `address_group_delete` | `ipv4` |
| `address_group_delete_ipv6` | `address_group_delete` | `ipv6` |
| `address_group_get_ipv4` | `address_group_get` | `ipv4` |
| `address_group_get_ipv6` | `address_group_get` | `ipv6` |
| `address_group_list_ipv4` | `address_group_list` | `ipv4` |
| `address_group_list_ipv6` | `address_group_list` | `ipv6` |
| `address_group_update_ipv4` | `address_group_update` | `ipv4` |
| `address_group_update_ipv6` | `address_group_update` | `ipv6` |
| `address_list_ipv4` | `address_list` | `ipv4` |
| `address_list_ipv6` | `address_list` | `ipv6` |
| `address_update_ipv4` | `address_update` | `ipv4` |
| `address_update_ipv6` | `address_update` | `ipv6` |
| `custom_gateway_get_ipv4` | `custom_gateway_get` | `ipv4` |
| `custom_gateway_get_ipv6` | `custom_gateway_get` | `ipv6` |
| `custom_gateway_list_ipv4` | `custom_gateway_list` | `ipv4` |
| `custom_gateway_list_ipv6` | `custom_gateway_list` | `ipv6` |
| `dhcp_lease_list_ipv4` | `dhcp_lease_list` | `ipv4` |
| `dhcp_lease_list_ipv6` | `dhcp_lease_list` | `ipv6` |
| `dhcp_relay_get_ipv4` | `dhcp_relay_get` | `ipv4` |
| `dhcp_relay_get_ipv6` | `dhcp_relay_get` | `ipv6` |
| `dhcp_relay_list_ipv4` | `dhcp_relay_list` | `ipv4` |
| `dhcp_relay_list_ipv6` | `dhcp_relay_list` | `ipv6` |
| `dhcp_server_get_ipv4` | `dhcp_server_get` | `ipv4` |
| `dhcp_server_get_ipv6` | `dhcp_server_get` | `ipv6` |
| `dhcp_server_list_ipv4` | `dhcp_server_list` | `ipv4` |
| `dhcp_server_list_ipv6` | `dhcp_server_list` | `ipv6` |
| `firewall_rule_clone_ipv4` | `firewall_rule_clone` | `ipv4` |
| `firewall_rule_clone_ipv6` | `firewall_rule_clone` | `ipv6` |
| `firewall_rule_create_ipv4` | `firewall_rule_create` | `ipv4` |
| `firewall_rule_create_ipv6` | `firewall_rule_create` | `ipv6` |
| `firewall_rule_delete_ipv4` | `firewall_rule_delete` | `ipv4` |
| `firewall_rule_delete_ipv6` | `firewall_rule_delete` | `ipv6` |
| `firewall_rule_get_ipv4` | `firewall_rule_get` | `ipv4` |
| `firewall_rule_get_ipv6` | `firewall_rule_get` | `ipv6` |
| `firewall_rule_list_ipv4` | `firewall_rule_list` | `ipv4` |
| `firewall_rule_list_ipv6` | `firewall_rule_list` | `ipv6` |
| `firewall_rule_move_ipv4` | `firewall_rule_move` | `ipv4` |
| `firewall_rule_move_ipv6` | `firewall_rule_move` | `ipv6` |
| `firewall_rule_set_enabled_ipv4` | `firewall_rule_set_enabled` | `ipv4` |
| `firewall_rule_set_enabled_ipv6` | `firewall_rule_set_enabled` | `ipv6` |
| `firewall_rule_update_ipv4` | `firewall_rule_update` | `ipv4` |
| `firewall_rule_update_ipv6` | `firewall_rule_update` | `ipv6` |
| `gateway_list_ipv4` | `gateway_list` | `ipv4` |
| `gateway_list_ipv6` | `gateway_list` | `ipv6` |
| `nat_rule_create_ipv4` | `nat_rule_create` | `ipv4` |
| `nat_rule_create_ipv6` | `nat_rule_create` | `ipv6` |
| `nat_rule_delete_ipv4` | `nat_rule_delete` | `ipv4` |
| `nat_rule_delete_ipv6` | `nat_rule_delete` | `ipv6` |
| `nat_rule_get_ipv4` | `nat_rule_get` | `ipv4` |
| `nat_rule_get_ipv6` | `nat_rule_get` | `ipv6` |
| `nat_rule_list_ipv4` | `nat_rule_list` | `ipv4` |
| `nat_rule_list_ipv6` | `nat_rule_list` | `ipv6` |
| `nat_rule_move_ipv4` | `nat_rule_move` | `ipv4` |
| `nat_rule_move_ipv6` | `nat_rule_move` | `ipv6` |
| `nat_rule_update_ipv4` | `nat_rule_update` | `ipv4` |
| `nat_rule_update_ipv6` | `nat_rule_update` | `ipv6` |
| `sdwan_route_get_ipv4` | `sdwan_route_get` | `ipv4` |
| `sdwan_route_get_ipv6` | `sdwan_route_get` | `ipv6` |
| `sdwan_route_list_ipv4` | `sdwan_route_list` | `ipv4` |
| `sdwan_route_list_ipv6` | `sdwan_route_list` | `ipv6` |
| `static_neighbor_get_ipv4` | `static_neighbor_get` | `ipv4` |
| `static_neighbor_get_ipv6` | `static_neighbor_get` | `ipv6` |
| `static_neighbor_list_ipv4` | `static_neighbor_list` | `ipv4` |
| `static_neighbor_list_ipv6` | `static_neighbor_list` | `ipv6` |
| `unicast_route_get_ipv4` | `unicast_route_get` | `ipv4` |
| `unicast_route_get_ipv6` | `unicast_route_get` | `ipv6` |
| `unicast_route_list_ipv4` | `unicast_route_list` | `ipv4` |
| `unicast_route_list_ipv6` | `unicast_route_list` | `ipv6` |
| `wan_gateway_get_ipv4` | `wan_gateway_get` | `ipv4` |
| `wan_gateway_get_ipv6` | `wan_gateway_get` | `ipv6` |
| `wan_gateway_list_ipv4` | `wan_gateway_list` | `ipv4` |
| `wan_gateway_list_ipv6` | `wan_gateway_list` | `ipv6` |

## What else changes

- **The request body is unchanged.** `ip_family` is stripped before the wire body is built, so
  `firewall_rule_create` with `ip_family: "ipv4"` sends exactly the body
  `firewall_rule_create_ipv4` sent before 0.7.0.
- **The output shape is unchanged.** The merged output models carry the union of the two family
  projections (for example `GatewayOutput` has both `ipv4Address` and `ipv6Address`; the family
  that was read populates exactly one). `firewall_rule_*` outputs already carried `ipFamily`, and
  the merged model keeps it.
- **`dhcp_lease_list` now takes an argument.** It was two no-argument tools
  (`dhcp_lease_list_ipv4`/`_ipv6`); it is now one tool whose only argument is `ip_family`. The
  no-argument tool count drops from 8 to 6.
- **The two firewall composites collapse too.** `firewall_rule_set_enabled_ipv4`/`_ipv6` become
  `firewall_rule_set_enabled`, and `firewall_rule_clone_ipv4`/`_ipv6` become
  `firewall_rule_clone`; both take `ip_family`.
- **The audit composites are unchanged.** `audit_firewall_rules`, `explain_connectivity` and
  `find_object_usage` keep their names and their optional `ip_family`.

## Example

Before 0.7.0:

```json
{"name": "firewall_rule_list_ipv6",
 "arguments": {"request": {"page": 1, "page_size": 10}}}
```

From 0.7.0:

```json
{"name": "firewall_rule_list",
 "arguments": {"request": {"ip_family": "ipv6", "page": 1, "page_size": 10}}}
```

A caller that used both family tools now calls the merged tool twice, once per `ip_family`
value. The `docs/API-COVERAGE.md` matrix records the merged tool name on both the IPv4 and the
IPv6 operation row.
