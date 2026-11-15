# Ejecución de la migración REST con subagentes y Agent Teams

Este directorio contiene los prompts para ejecutar el plan de migración de Sophos Firewall MCP usando **subagentes** y **Agent Teams** de DeepSeek Harness (DSH).

## Por qué se divide en fases

Las nueve issues **no se pueden ejecutar de una vez** con calidad:

1. **#24 decide el contrato** (ADR de cliente, cobertura, protocolo live). #25 y #26 no pueden empezar sin esa decisión.
2. **#25 define la interfaz del cliente** y **#26 la consume**; si se hacen a la vez sin contrato, se contradicen.
3. **#27–#31 comparten la fundación** (`AppContext`, registro de herramientas, errores). Sin ella, cada agente inventa su propia capa.
4. **#32 depende de que todas las anteriores estén cerradas** y además exige aprobación del propietario para publicar.
5. Una sola sesión no tiene contexto suficiente para 700 operaciones + 9 issues + revisión; la calidad cae y los agentes se pisan.

Por eso: **3 fases secuenciales + 1 revisión independiente por fase**.

| Fase | Issues | Prompt | Salida |
|---|---|---|---|
| 1 — Fundación | #24, #25, #26 | [`01-PHASE-1-FOUNDATION.md`](./01-PHASE-1-FOUNDATION.md) | ADR, `API-COVERAGE.md`, cliente REST, fundación MCP, tests |
| 2 — Herramientas de dominio | #27, #28, #29, #30, #31 | [`02-PHASE-2-DOMAIN-TOOLS.md`](./02-PHASE-2-DOMAIN-TOOLS.md) | 5 PRs de dominio + cobertura + tests |
| 3 — Hardening y release | #32 | [`03-PHASE-3-HARDENING-RELEASE.md`](./03-PHASE-3-HARDENING-RELEASE.md) | CI, Docker, docs, evidencia, release preparada |
| Revisión | transversal | [`04-REVIEW-PROTOCOL.md`](./04-REVIEW-PROTOCOL.md) | Informe adversarial por fase |

Cada prompt de fase **empieza leyendo** [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md), que contiene el contexto y las reglas comunes. No dupliques contexto en cada fase: si cambia una regla, se cambia en el maestro.

## Cómo usarlos

1. Abre una sesión DSH nueva en el workspace del repositorio, con **Agent Teams activado**.
2. Pega el contenido de `01-PHASE-1-FOUNDATION.md` como primer mensaje (o pide "lee y ejecuta este prompt").
3. El Lead creará el equipo, el tablero de tareas y ejecutará la fase.
4. Al terminar, ejecuta `04-REVIEW-PROTOCOL.md` como sesión independiente (o pídeselo al Lead como revisor separado).
5. Solo si la revisión pasa y el propietario aprueba el merge, empieza la fase 2.
6. Repite con `02` y `03`.

**No encadenes fases automáticamente**: cada fase termina en un PR y una puerta de aprobación humana.

## Equipo recomendado

| Fase | Miembros | Propiedad de escritura |
|---|---|---|
| 1 | `contract`, `client`, `foundation`, `reviewer` | `docs/API-COVERAGE.md`, `docs/architecture/ADR-001-*`, `scripts/coverage*`, `src/sophos_firewall_mcp/client.py`, `config.py`, `server.py`, `context.py`, `tests/` |
| 2 | `firewall`, `nat`, `objects`, `users`, `vpn`, `reviewer` | `src/sophos_firewall_mcp/tools/<dominio>.py`, `tests/test_<dominio>.py`, `docs/api-coverage/<dominio>.md` |
| 3 | `hardening`, `release`, `reviewer` | `.github/`, `Dockerfile`, `docker-compose.yml`, `README.md`, `.env.example`, `pyproject.toml`, `uv.lock` |

El Lead no escribe código de dominio: coordina, revisa diffs, integra y decide. El `reviewer` nunca escribe en `src/`.

## Reglas de oro (resumen)

1. **Leer antes de escribir**: PLAN, REFERENCES, LAB-ACCESS, informe de auditoría, issue y contrato OpenAPI.
2. **Contrato primero**: #25 publica la interfaz; #26 y #27–#31 la consumen.
3. **Escrituras disjuntas**: un dueño por fichero; los ficheros compartidos los toca solo su dueño.
4. **Una rama por fase**, sin `checkout`/`rebase` por parte de los compañeros; commits con rutas explícitas.
5. **La clave del laboratorio es de solo lectura**: prohibido escribir en el firewall.
6. **Nada se fusiona ni se publica sin aprobación del propietario.**
7. **Evidencia sobre afirmaciones**: operationId, código de estado y prueba; nada de "debería funcionar".
8. **Revisión independiente** antes de cada merge.
9. **Recoger y verificar** todos los resultados antes de responder.
10. **Escalar** cuando falte una decisión o credencial; no inventar.

## Estado de partida

- Auditoría independiente completada: [`INDEPENDENT_REVIEW_REPORT.md`](../INDEPENDENT_REVIEW_REPORT.md).
- Plan corregido: [`PLAN.md`](../PLAN.md).
- Issues #24–#32 corregidas y abiertas.
- Laboratorio verificado en vivo (solo lectura): [`LAB-ACCESS.md`](../LAB-ACCESS.md) y [`docs/live-evidence/api-smoke-2026-11-15.md`](../../../live-evidence/api-smoke-2026-11-15.md).
- Implementación: **no iniciada**.
