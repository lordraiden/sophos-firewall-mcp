# Sophos REST API redesign

Documentación de diseño y ejecución para reemplazar la integración XML por Sophos Firewall Configuration REST API, directamente contra el appliance.

## Documentos

- [Plan técnico revisado (MCP output schemas, permisos Sophos y límites de resultados)](./PLAN.md): arquitectura, contrato API, seguridad, decisiones MCP actuales, cobertura funcional, pruebas y nueve issues.
- [Referencias](./REFERENCES.md): URLs del YAML del repositorio, documentación oficial Sophos, operaciones endpoints, RFC y SDK MCP.
- [Acceso al laboratorio](./LAB-ACCESS.md): endpoint del appliance, API key de solo lectura, variables de entorno y advertencias. Credencial en claro por decisión del propietario; solo laboratorio.
- [Informe de auditoría independiente](./INDEPENDENT_REVIEW_REPORT.md): revisión de 15 de noviembre de 2026 con baseline verificado, tabla de conformidad MCP/Sophos, hallazgos, cambios realizados en el plan y las issues, y evidencia pendiente del appliance.
- [ADR-001 — REST client and model-generation strategy](../ADR-001-rest-client-strategy.md): decisión de cliente REST (HTTPX + Pydantic manual) con la POC acotada que la respalda, el baseline del contrato medido desde el fichero y la instrucción normativa para #25.
- [API coverage](../../API-COVERAGE.md): inventario generado de las 700 operaciones con decisiones curadas por dominio, excepciones PATCH, paginación, identificadores y protocolo de verificación en vivo.
- [Prompt de revisión independiente](./INDEPENDENT_REVIEW_PROMPT.md): auditoría exhaustiva de la planificación y las issues frente al contrato Sophos, la especificación MCP y el SDK Python oficial.
- [Prompts de ejecución](./execution/README.md): maestro, fases 1–3 y protocolo de revisión para ejecutar el plan con subagentes y Agent Teams de DSH.

## Estado

- **Diseño:** auditado el 15 de noviembre de 2026. El YAML local está parseado y verificado: OpenAPI 3.0.0, info.version 1.0.0, 384 paths, 700 operaciones con operationId único, 32 esquemas de componente, 76 `$ref` locales (0 externos), 134 PATCH con `application/json` y ninguna con `application/merge-patch+json`. Ver [INDEPENDENT_REVIEW_REPORT.md](./INDEPENDENT_REVIEW_REPORT.md) para el baseline completo y las correcciones aplicadas.
- **Implementación:** fase 1 (fundación REST) implementada en la rama `migration/phase-1-foundation`: cliente REST tipado, fundación MCP (lifespan, `AppContext`, registro modular, modo read-only), [ADR-001](../ADR-001-rest-client-strategy.md) y [matriz de cobertura](../../API-COVERAGE.md). Pendiente de revisión independiente y de aprobación del propietario; no fusionada.
- **Issues:** diez issues abiertas (#24–#32 y #35), agrupadas con [M1], [M2] y [M3]. Las nueve originales fueron corregidas el 15 de noviembre de 2026 a partir de la auditoría, y el alcance v1 se amplió por decisión del propietario (ver ADR-001 §10).
- **Siguiente paso:** revisión independiente de la fase 1 y aprobación; después, fase 2 (#27–#31 y #35) sobre la fundación publicada.

La especificación OpenAPI versionada es el contrato inicial. La documentación oficial Sophos añade requisitos de permisos de perfil, allowlist y Device Access; el portal y la documentación del firmware son referencias de contraste, no sustituyen el YAML concreto ni las pruebas de operación real. En MCP, las anotaciones son hints, no controles de acceso, y los resultados deben ser DTOs tipados, acotados y compatibles.

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
