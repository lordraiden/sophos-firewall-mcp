# Live evidence — the lab API key can write (16 Nov 2026)

**Date:** 16 November 2026
**Appliance:** Sophos Firewall 23, **SFOS 23.0.0 GA-Build371**, model **SFVH** (virtual), `10.10.10.1:443`
**Credential:** the shared lab API key described in
[`LAB-ACCESS.md`](../architecture/sophos-rest-api-redesign/LAB-ACCESS.md). No key material is recorded
here.
**Scope:** one disposable object, created and removed in the same session.

## What was done

While investigating an unrelated `403` response, a single disposable MAC address object named
`mcp-test-403-probe` was created through the Configuration REST API and then deleted. Both calls
succeeded.

| Operation | Result |
|---|---|
| `POST /network/mac-addresses` (create `mcp-test-403-probe`) | succeeded |
| `DELETE /network/mac-addresses/mcp-test-403-probe` | succeeded |
| Read-back after the delete | object absent |

The object was a test artefact only. It was removed before the session ended and nothing else on the
appliance was modified.

## What this proves

**The active lab API key has write capability.** A credential that the documentation described as
read-only created and deleted a configuration object. The "read-only" characterisation in
`LAB-ACCESS.md` was an inference from the administrator profile's display name, not a verified
property, and it is withdrawn.

## What this does **not** prove

- **Which administrator owns the key.** The Configuration REST API does not expose the association
  between a key and the administrator that created it. `admin_mcp` remains an unverified inference.
- **The effective per-module permission scope.** One successful create/delete on MAC addresses does
  not establish what the credential can do elsewhere.
- **Whether the previously exposed key has been revoked.** No revocation evidence exists in the
  repository.
- **That write access is denied anywhere.** No denial was tested, and none should be tested with a
  destructive request.

## Why the 15 November record is unchanged

[`api-smoke-2026-11-15.md`](api-smoke-2026-11-15.md) recorded a **read-only** smoke test and said
explicitly that writes were not tested in that run. That statement remains accurate for that run and
is not rewritten here. This note is a separate, later observation with a different scope.

## Status

**Unresolved.** The containment action is credential rotation by the owner, tracked in
[#75](https://github.com/lordraiden/sophos-firewall-mcp/issues/75) (closed as an owner action) and
[#85](https://github.com/lordraiden/sophos-firewall-mcp/issues/85) (this documentation correction).
Until the owner supplies non-secret evidence of the revocation date, the verified administrator and
the effective permission scope, the credential must be treated as **read and write**.
