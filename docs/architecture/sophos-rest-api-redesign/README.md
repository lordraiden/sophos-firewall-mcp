# Sophos REST API redesign

Documentación de diseño para reemplazar la integración XML del proyecto por una implementación basada exclusivamente en Sophos Firewall REST API.

## Documentos

- [Plan técnico](./PLAN.md): decisión arquitectónica, correspondencia funcional, diseño recomendado, fases, issues, pruebas, seguridad y riesgos.
- [Referencias](./REFERENCES.md): URLs de la especificación del repositorio, documentación oficial de Sophos, SDK MCP, estándares y herramientas evaluadas.

## Estado

- **Diseño:** propuesto.
- **Implementación:** no iniciada por este documento.
- **Issues de ejecución:** nueve issues abiertas (#24–#32), agrupadas mediante prefijos [M1], [M2] y [M3] en sus títulos.
- **Siguiente paso:** ejecutar [#24 — OpenAPI audit and API coverage](https://github.com/lordraiden/sophos-firewall-mcp/issues/24) y registrar el inventario validado en `docs/API-COVERAGE.md`.

La especificación OpenAPI incluida en el repositorio es el contrato que debe auditarse en la Fase 0. Las referencias web documentan el contexto y las prácticas de implementación, pero no sustituyen la inspección del YAML versionado ni las pruebas contra el firmware de destino.

## GitHub execution issues

| Group | Issue | Scope |
|---|---|---|
| M1 | [#24 — OpenAPI audit and API coverage](https://github.com/lordraiden/sophos-firewall-mcp/issues/24) | Audit the checked-in specification, map every operation, and record the architecture decision. |
| M1 | [#25 — Typed Sophos REST client](https://github.com/lordraiden/sophos-firewall-mcp/issues/25) | Replace the XML transport with a typed asynchronous REST client. |
| M1 | [#26 — MCP server foundation](https://github.com/lordraiden/sophos-firewall-mcp/issues/26) | Rebuild lifecycle, context, registration, schemas, structured outputs, and error handling. |
| M2 | [#27 — Firewall rules](https://github.com/lordraiden/sophos-firewall-mcp/issues/27) | IPv4/IPv6 rule operations and ordering where supported. |
| M2 | [#28 — NAT rules](https://github.com/lordraiden/sophos-firewall-mcp/issues/28) | NAT operations for supported IP families. |
| M2 | [#29 — Network addresses and services](https://github.com/lordraiden/sophos-firewall-mcp/issues/29) | Address objects, groups, services, and service groups. |
| M2 | [#30 — Network users and sessions](https://github.com/lordraiden/sophos-firewall-mcp/issues/30) | Network users, live sessions, and supported session actions. |
| M2 | [#31 — VPN and network interfaces](https://github.com/lordraiden/sophos-firewall-mcp/issues/31) | Supported VPN configuration/state and interfaces. |
| M3 | [#32 — Hardening and release](https://github.com/lordraiden/sophos-firewall-mcp/issues/32) | End-to-end validation, security, packaging, documentation, and release readiness. |

The issue titles use milestone prefixes to group the work. The dependency chain is #24 → #25 → #26; issues #27–#31 depend on the foundation, and #32 depends on the complete set. Each issue links back to this plan and the reference register.
