# Live evidence — protocol and record format

This directory records what was actually observed on a real Sophos Firewall
appliance. Contract tests, mocks and OpenAPI validation cannot prove firmware
behaviour, permissions or real PATCH semantics: only a live run can, and only
for the build that was tested.

- [`api-smoke-2026-11-15.md`](api-smoke-2026-11-15.md) — read-only smoke test
  of 15 November 2026.
- `<domain>.md` — one record file per domain, created by the domain issues
  (#27–#32).

## 1. Safety rules (non-negotiable)

1. **The lab key is read-only.** Live tests perform `GET` requests only. They
   never write: no `POST`, `PATCH`, `DELETE`, bulk delete, move, disconnect,
   login/logout or modem action. A write test requires a separate write key and
   a disposable-object plan approved by the owner; until then it is deferred.
2. **Never put secrets in a record.** No API key, no `Authorization` header, no
   full remote body containing credentials. Record the endpoint as
   `host:port` only.
3. **Live tests are opt-in.** The default test run skips them; CI must pass with
   every live test skipped.
4. **One file per domain, append-only.** Add a new dated section for each run;
   do not rewrite earlier evidence. If a previous observation was wrong, record
   the correction with its date and evidence.
5. **Never claim compatibility from a mock, an OpenAPI validation or a release
   note.** If a live test cannot run, record an explicit deferral with reason,
   owner and prerequisite instead of claiming support.

## 2. Opt-in protocol (`pytest -m live`)

Live tests are marked with the `live` marker and are skipped unless the lab
connection is configured. A test is enabled only when all of the following are
set:

- `SOPHOS_HOST`
- `SOPHOS_PORT`
- `SOPHOS_API_KEY` or `SOPHOS_API_KEY_FILE` (exactly one source)

The marker is registered in `pyproject.toml` (`[tool.pytest.ini_options]`
`markers`), so `pytest -m live` selects the live tests without an unknown-mark
warning.

Reference pattern for a live test module:

```python
import os

import pytest

_LIVE_READY = bool(
    os.getenv("SOPHOS_HOST")
    and os.getenv("SOPHOS_PORT")
    and (os.getenv("SOPHOS_API_KEY") or os.getenv("SOPHOS_API_KEY_FILE"))
)

live = pytest.mark.skipif(
    not _LIVE_READY,
    reason="live appliance credentials are not configured",
)


@pytest.mark.live
@live
async def test_get_firewall_rule_ipv4() -> None:
    # GET only; assert the documented status and response shape.
    ...
```

Commands:

```bash
# Default run: live tests are skipped, CI stays green.
uv run pytest -q

# Opt-in run against the lab (read-only key from LAB-ACCESS.md).
SOPHOS_HOST=10.10.10.1 SOPHOS_PORT=443 \
SOPHOS_API_KEY="<read-only key>" SOPHOS_VERIFY_SSL=false \
uv run pytest -m live -q
```

Rules for live tests:

- Assert only documented behaviour (status code, response envelope, pagination
  metadata). Do not assert on volatile values such as timestamps or counters.
- Do not print request headers, the API key or full response bodies.
- Do not retry a write; there are no writes.
- A live test that cannot run is skipped **and** recorded as a deferral (see
  §3), not silently omitted.

## 3. Record format: `docs/live-evidence/<domain>.md`

The file name uses the canonical domain key from
[`docs/API-COVERAGE.md`](../API-COVERAGE.md) §3: `firewall_rules`, `nat_rules`,
`addresses`, `services`, `auth_users`, `live_users`, `ipsec_vpn`, `ssl_vpn`,
`network_status`, `network`, `audit`, `admin_system`, `other`.

Every record starts with the mandatory environment table:

| Field | Value |
|---|---|
| Appliance model | Exact model (for example `XGS 2100`), or `unknown` |
| SFOS build | Exact build (for example `SFOS 23.0 GA Build 371`), or `unknown` |
| Administrator profile / permissions | Profile name and the effective per-feature permissions (for example `Read only Admin`, 47 read-only permissions) |
| API allowlist source | The IP/host entry or range configured in Administration → API access |
| Date | ISO date of the run (UTC) |
| Endpoint | `host:port` and base path only; never the key |
| Evidence source | Command, test id or script used for the run |
| Key rotation status | Whether the key was rotated after the run |

Then the operation table, one row per exercised operation. It lists the
operationIds exercised in this run, with pass/fail per operation:

| operationId | method + path | result | HTTP status | observation | evidence |
|---|---|---|---|---|---|
| `getAllFirewallRulesIpv4` | `GET /firewall/rules/ipv4` | PASS | 200 | `items`/`pages` present; 47 rules with `pageTotal=true` | `pytest -m live -q tests/live/test_firewall_live.py` |

`result` is one of:

- `PASS` — the appliance behaved as the contract documents.
- `FAIL` — the appliance behaved differently; describe the difference.
- `SKIP` — not exercised in this run; the reason belongs in the deferral table.

A deviation from the contract must also be recorded in the live-observations
section of `docs/API-COVERAGE.md` and, if it changes a decision, in the curated
file.

### Explicit deferral

When a live test cannot run, record it instead of claiming support:

| Deferred operation or domain | Reason | Owner | Prerequisite |
|---|---|---|---|
| `deleteFirewallRuleIpv4` | Lab key is read-only; a write test would mutate the appliance | #27 owner | Write key plus a disposable-object plan approved by the owner |

The same deferral must appear in the domain block of `docs/API-COVERAGE.md` so
the coverage matrix never implies firmware support that was not observed.

## 4. Current evidence

| File | Scope | Result |
|---|---|---|
| [`api-smoke-2026-11-15.md`](api-smoke-2026-11-15.md) | Read-only smoke test: authentication, 20+ endpoints, pagination, error envelopes | API reachable, Bearer accepted, `live-users` pagination observed; SFOS build unknown; no writes attempted |
| [`phase-2-deferral.md`](phase-2-deferral.md) | Phase-2 deferral record for the domain tools (#27–#31, #35) | Contract-tested only; live writes deferred to #32 |
| [`phase-3-live-matrix.md`](phase-3-live-matrix.md) | Phase-3 read-only matrix: all 98 read-only tools across the six domain families | 74 PASS, 24 SKIP (no object of that kind), 0 FAIL after two fixed deviations; SFOS build unknown; no writes attempted |

Open items that live evidence must still resolve:

- Exact SFOS build of the target appliance.
- Real PATCH behaviour on arrays (the four documented exceptions).
- Effective permission denial (`403`) for writes with a read-only profile.
- Ambiguous-write behaviour (timeout then reconcile).
- Whether the appliance's downloadable OpenAPI differs from the checked-in file.

## 5. What live tests must never do

- Mutate the appliance with the read-only key.
- Store, print or commit the API key.
- Turn a skipped test into a claim of support.
- Treat an HTML error page, a plain-text `405` or a front-end `403` as a JSON
  API error; sanitize and map per operation.
- Generalise a result to other firmware builds.
