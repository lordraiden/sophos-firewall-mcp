# Release 0.7.0 — the IPv4/IPv6 collapse and flat arguments

**Status:** prepared, **not published** — pending explicit owner approval. **Previous release:** 0.6.0
(output contract, SFOS 23 positioning). **Target appliance:** Sophos Firewall 23, **SFOS 23.0.0
GA-Build371**.

## 1. Release notes

### 1.1 Summary

0.7.0 is the breaking release that the MCP standards review scheduled for 0.7/1.0
([`MCP-STANDARDS-REVIEW.md`](../architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW.md) §4,
items 13–16). It makes two breaking changes to the published surface and two additive safety changes:

- **The 40 IPv4/IPv6 tool pairs collapse into one tool per concept** behind a required `ip_family`
  argument (item 13, findings M5/H1).
- **Tool arguments are published flat** instead of inside a `request` wrapper (item 14, finding H2).
- **The four highest-blast-radius deletes ask the client to confirm** when the client supports
  elicitation (item 15, finding L4).
- **`openWorldHint` is set per tool** instead of `true` everywhere (item 16, finding L5).

The surface drops from 152 tools to **112** (107 one-to-one + 5 composites): **74 read-only / 38
mutations**, **7 no-argument / 105 argument tools**. The `tools/list` catalog drops from 807,920 to
**622,787 bytes** (−185,133, −22.9%), roughly **156k tokens** at ~4 bytes per token. The published
input surface drops from 222,419 to 199,114 bytes (−10.5%), and **0 tools publish a `request`
property**.

The wire body sent to the appliance is unchanged in both directions: `ip_family` is stripped before
the request is built, and the flat arguments are the same fields the wrapper carried. The output
**payload** for a given family is unchanged; the published output **schema** is the union of both
families, so 40 of the 80 merged pairs publish a wider schema (e.g. `address_get` publishes 8 address
variants instead of 4). A client that generates types from `outputSchema` must regenerate them.

**Measured on this branch** (`feat/mcp-0.7-breaking`): the counts come from the registered surface
(`create_server(...).list_tools()`), the catalog size from the raw JSON-RPC `tools/list` response line
over STDIO including the trailing newline, and the input-schema size from `json.dumps` of every
published `inputSchema`. The catalog numbers are measured on three trees: `origin/main` (pre-0.7,
807,920), `b22731a` (after the IPv4/IPv6 collapse, before the flatten, 655,034) and HEAD (622,787).
The migration table is
[`MIGRATION-0.7.md`](../architecture/sophos-rest-api-redesign/MIGRATION-0.7.md).

### 1.2 Breaking changes

#### 1.2.1 One tool per concept, with a required `ip_family`

Before 0.7.0 the server published one tool per IP family — `firewall_rule_list_ipv4` and
`firewall_rule_list_ipv6`, `address_create_ipv4` and `address_create_ipv6`, and so on. That doubled
the surface, doubled the number of names a model had to choose between, and contradicted the server's
own convention: the three audit composites already took an `ip_family` argument.

0.7.0 publishes **one tool per concept** and moves the family axis into a required `ip_family`
argument (`ipv4` | `ipv6`). **80 tool names are removed** and 40 merged tools are added; the two
firewall composite pairs (`firewall_rule_set_enabled_ipv4`/`_ipv6`,
`firewall_rule_clone_ipv4`/`_ipv6`) collapse too.

`ip_family` is **required, not defaulted**, for three reasons:

1. **A default would make a destructive target a guess.** `firewall_rule_delete`, `nat_rule_delete`,
   `firewall_rule_update`, `firewall_rule_move` and `firewall_rule_set_enabled` all act on one
   family's rule base. A default of `ipv4` would silently delete or disable the IPv4 rule when the
   caller meant the IPv6 one. The server's safety policy is that a destructive target is never
   inferred: `enabled` is required on `firewall_rule_set_enabled` and `position` on create for the
   same reason.
2. **A default would hide which family a read returned.** `firewall_rule_list` and `address_list`
   return one family's page; a caller that omitted the family would not know which collection it read.
3. **The family is a path selector, not a body member.** The adapter strips `ip_family` before the
   request is sent, so the wire body is byte-identical to the pre-0.7 per-family tool.

The three audit composites (`audit_firewall_rules`, `explain_connectivity`, `find_object_usage`) keep
their existing optional `ip_family`: they are read-only and can span both families, so omitting it
means "both". That is the one documented difference, and it is intentional.

The six IPv4-only IPsec tools (`ipsec_connection_list_ipv4`, `ipsec_live_connection_list_ipv4`,
`ipsec_policy_based_connection_get_ipv4`, `ipsec_policy_based_connection_list_ipv4`,
`ipsec_route_based_connection_get_ipv4`, `ipsec_route_based_connection_list_ipv4`) are unchanged: the
API has no IPv6 counterpart.

**Migration table.** Every removed name maps to one new tool plus the `ip_family` value that
reproduces the old behaviour. Reproduced from
[`MIGRATION-0.7.md`](../architecture/sophos-rest-api-redesign/MIGRATION-0.7.md):

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

A caller that used both family tools now calls the merged tool twice, once per `ip_family` value.

#### 1.2.2 Flat arguments

Every tool that takes arguments now publishes the request model's own fields at the top level of
`inputSchema`; the `request` wrapper is gone from all 112 tools. The wrapper was the MCP SDK's
single-argument convention, not a requirement of the protocol, and it was a per-call failure mode: a
model's prior is flat, so a call that put the fields at the top level was rejected.

- **0 tools publish a `request` property**, and the wrapper sentence is gone from every description.
- The published input surface drops from **222,419 to 199,114 bytes** (−10.5%).
- A tool whose request is a union of shapes publishes a root `oneOf` of the closed variants
  (`firewall_rule_create`/`_update`, `nat_rule_create`/`_update`, `address_create`/`_update`,
  `address_group_create`/`_update`), because flattening a union into one object would lose the
  per-variant required fields; `mac_address_create` publishes an `anyOf` because the API declares no
  discriminator for it. The discriminator (`ip_family` or `type`) selects the variant.
- The handler, its signature and the wire body are untouched. The closed argument model
  (`additionalProperties: false`) and the sanitized errors are unchanged, and an unknown argument is
  still rejected by name: `invalid arguments: bogus is not an accepted argument; accepted arguments
  are ip_family, id_or_name`.

Before 0.7.0:

```json
{"name": "firewall_rule_list_ipv6",
 "arguments": {"request": {"page": 1, "page_size": 10}}}
```

From 0.7.0:

```json
{"name": "firewall_rule_list",
 "arguments": {"ip_family": "ipv6", "page": 1, "page_size": 10}}
```

### 1.3 Added

- **Confirmation for the four highest-blast-radius deletes (L4).** `firewall_rule_delete`,
  `nat_rule_delete`, `network_user_delete` and `network_interface_delete_vlan` ask the client to
  confirm before the appliance is touched, through the MCP elicitation capability. The question names
  the object and the rule base; a declined or cancelled answer aborts the call with a `ToolError` and
  nothing is deleted. The affordance is additive, never a new precondition: it is skipped — and the
  delete proceeds exactly as before — when the client declared no `elicitation` capability or the
  transport has no back-channel, which is the normal case for a non-interactive client.
- **`openWorldHint` is set per tool (L5).** 6 tools publish `true` and 106 publish `false`. The hint
  describes the tool's interaction domain, not how much its data can be trusted: this server talks to
  exactly one configured appliance and no tool accepts a URL, host or endpoint, so a tool that reads
  or writes that appliance's own configuration is closed. The 6 open tools are the ones whose result
  is produced by entities the appliance does not own and cannot enumerate: `dhcp_lease_list`,
  `ipsec_live_connection_list_ipv4`, `live_user_disconnect`, `live_user_list`,
  `network_status_cellular_wan` and `network_status_dns_protection`. `tests/test_tool_surface.py` pins
  the set so a change stays deliberate.

### 1.4 Fixed

- **H2 — the `request` wrapper failure mode is gone.** A flat call is now the correct call, so a model
  no longer has to learn a convention that contradicts the MCP specification's own examples.
- **M5/H1 — the doubled surface is gone.** One tool per concept instead of two, so a model no longer
  chooses between `_ipv4` and `_ipv6` variants of the same operation, and the catalog is 185,133
  bytes smaller (807,920 → 622,787).
- **Argument errors name the field and the rule, without a union tag.** A model-level validator now
  renders its own message (`name_contains and name_not_equals are mutually exclusive`) instead of
  pydantic's `Value error, ` prefix, and a union tag is stripped from the reported location (`bogus is
  not an accepted argument`, not `ipv4.bogus ...`).
- **`live_user_list` is a no-argument tool.** Its request model is deliberately empty, so with flat
  arguments it publishes no properties at all, like the other six no-argument tools.

### 1.5 Known limitations

- **Elicitation applies to handshake clients only.** `mcp` 2.3.0 refuses a standalone
  server-to-client request on the modern (`2026-07-28`) per-request path
  (`mcp/server/runner.py:552-593`, `_NoServerRequestsDispatchContext`), so the confirmation is
  available to a client that negotiated a handshake version (`2024-11-05` … `2025-11-25`, the STDIO
  default) and is silently skipped on the modern path. The modern path would need the
  `InputRequiredResult` round trip that `mcp` 2.3.0 only wires for `Resolve` parameters
  (`mcp/server/mcpserver/resolve.py:10-30`, `:96`), which would change every handler signature; that
  is deliberately out of scope for this release. A non-interactive client is unaffected either way.
- **Firmware compatibility is limited to the tested build.** The live evidence applies to **SFOS 23.0.0
  GA-Build371** only. The Configuration REST API exposes no version endpoint, so the server cannot
  detect the firmware it is talking to and makes no claim for any other SFOS build, including later
  23.0 maintenance builds and SFOS 24. Verify the behaviour you depend on against your own appliance.
- **Live write validation is limited** to the object kinds exercised on the lab appliance; ambiguous
  write reconciliation, a real `403` denial, bulk delete and interface/VPN mutations remain unverified.
- **Accepted regressions** are unchanged: no system information, no service status and no log query,
  because the Configuration REST API exposes no endpoint for them.
- **Audit tools are configuration analysis, not packet tests**; `explain_connectivity` reports
  `method: config-analysis` and `not-verifiable` when the configuration lacks the evidence.
- **Pagination is one page per call**; the server never fetches every page automatically.

## 2. Rollback to 0.6.0

The server is stateless: rolling back changes no appliance configuration and no stored data.

1. Re-deploy the previous image `ghcr.io/lordraiden/sophos-firewall-mcp:0.6.0` (or the `0.6` alias).
2. If you run from source, check out `v0.6.0` and reinstall.
3. Clients that adopted the merged tool names must go back to the family-specific names
   (`firewall_rule_list_ipv4` / `firewall_rule_list_ipv6`, …); 0.6.0 does not accept `ip_family`.
4. Clients that adopted flat arguments must wrap them in `request` again; 0.6.0 rejects a flat call
   with `request is required`.
5. No other behaviour changes: the wire body and the output payload for a given family are the same
   in both releases. The published output schema is wider in 0.7.0 (the union of both families for 40
   of the 80 merged pairs), so a client that generates types from `outputSchema` must regenerate them.

## 3. Publication checklist

- [x] `pyproject.toml` and `uv.lock` both say `0.7.0` (`pyproject.toml:3`, `uv.lock:1228`).
- [x] `CHANGELOG.md` has the `[0.7.0]` entry; `README.md` reflects 0.7.0 (this PR).
- [x] `docs/API-COVERAGE.md` regenerates without a diff
      (`uv run --no-sync python scripts/generate_coverage.py --check`).
- [ ] Independent review **APPROVE**.
- [ ] CI green on the merge commit (tests 3.11–3.14, lint, image build, dependency audit, semgrep).
- [ ] Tag `v0.7.0` on the merge commit; the `release` job publishes `0.7.0`, `0.7` and `latest`.
- [ ] GitHub release with these notes.
- [ ] Post-publish: image tags present; the container build + STDIO smoke test ran green in CI on the
      same commit.

## 4. Approval record

**Not approved yet.** 0.7.0 is prepared on `feat/mcp-0.7-breaking` and must not be tagged, published or
promoted to `latest` without explicit owner approval. The approval is recorded here once given,
together with the independent review verdict.
