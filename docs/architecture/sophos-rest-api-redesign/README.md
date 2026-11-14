# Sophos REST API redesign

Documentación de diseño y ejecución para reemplazar la integración XML por Sophos Firewall Configuration REST API, directamente contra el appliance.

## Documentos

- [Plan técnico revisado](./PLAN.md): arquitectura, contrato API, seguridad, decisiones MCP actuales, cobertura funcional, pruebas y nueve issues.
- [Referencias](./REFERENCES.md): URLs del YAML del repositorio, documentación oficial Sophos, operaciones endpoints, RFC y SDK MCP.

## Estado

- **Diseño:** revisado el 14 de noviembre de 2026. El YAML local está parseado: OpenAPI 3.0.0, info.version 1.0.0, 384 paths y 700 operaciones.
- **Implementación:** no completada.
- **Issues:** nueve issues abiertas (#24–#32), agrupadas con [M1], [M2] y [M3].
- **Siguiente paso:** completar [#24 — OpenAPI audit and API coverage](https://github.com/lordraiden/sophos-firewall-mcp/issues/24), empezando por validar el YAML local y su correspondencia con SFOS objetivo.

La especificación OpenAPI versionada es el contrato inicial. El portal Sophos y la documentación del firmware son referencias de contraste; no sustituyen el YAML concreto ni las pruebas de operación real.

## GitHub execution issues

| Grupo | Issue | Alcance |
|---|---|---|
| M1 | [#24 — OpenAPI audit and API coverage](https://github.com/lordraiden/sophos-firewall-mcp/issues/24) | Auditar todas las operaciones y schemas y decidir arquitectura. |
| M1 | [#25 — Typed Sophos REST client](https://github.com/lordraiden/sophos-firewall-mcp/issues/25) | Sustituir el cliente XML por REST tipado, seguro y asíncrono. |
| M1 | [#26 — MCP server foundation](https://github.com/lordraiden/sophos-firewall-mcp/issues/26) | SDK v2, lifespan, contexto, schemas, errores y stdio. |
| M2 | [#27 — Firewall rules](https://github.com/lordraiden/sophos-firewall-mcp/issues/27) | Reglas IPv4/IPv6; operaciones individuales y movimiento. |
| M2 | [#28 — NAT rules](https://github.com/lordraiden/sophos-firewall-mcp/issues/28) | Reglas NAT IPv4/IPv6. |
| M2 | [#29 — Network addresses and services](https://github.com/lordraiden/sophos-firewall-mcp/issues/29) | Direcciones, grupos, servicios y referencias. |
| M2 | [#30 — Network users and live sessions](https://github.com/lordraiden/sophos-firewall-mcp/issues/30) | Usuarios de red, paginación, sesiones y desconexión. |
| M2 | [#31 — VPN, interfaces and read-only status](https://github.com/lordraiden/sophos-firewall-mcp/issues/31) | VPN, interfaces y diagnósticos read-only seleccionados. |
| M3 | [#32 — Hardening and release](https://github.com/lordraiden/sophos-firewall-mcp/issues/32) | Seguridad, validación, despliegue y preparación de release. |

## Dependencias

- #24 → #25 → #26.
- #27–#31 dependen de #24, #25 y #26.
- #32 depende de la finalización/revisión de #24–#31.

Las issues referencian este plan, la bibliografía y el YAML versionado. El primer trabajo debe inventariar el contrato; los agentes no deben inferir operaciones REST por semejanza con XML o la interfaz web.
