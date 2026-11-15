# 01 — Fase 1: Fundación REST (#24, #25, #26)

> **Antes de empezar:** lee y aplica [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md). Este prompt asume sus reglas (equipo, tablero, git, verificación, escalación).

## Objetivo de la fase

Convertir el contrato OpenAPI en una base implementable y dejar el servidor MCP listo para que cinco agentes añadan herramientas de dominio sin tocar la fundación.

**Issues:** [#24](https://github.com/lordraiden/sophos-firewall-mcp/issues/24) (auditoría/ADR/cobertura), [#25](https://github.com/lordraiden/sophos-firewall-mcp/issues/25) (cliente REST), [#26](https://github.com/lordraiden/sophos-firewall-mcp/issues/26) (fundación MCP).

**No entra:** herramientas de dominio (#27–#31), hardening/release (#32), cambios de CI/Docker (fase 3), escrituras contra el laboratorio.

## Resultado esperado

- `docs/architecture/ADR-001-rest-client-strategy.md` con la decisión de cliente (generado vs manual) y su evidencia.
- `docs/API-COVERAGE.md` generado de forma determinista desde el YAML, con decisiones curadas por dominio.
- `scripts/generate_coverage.py` reproducible y con comprobación de SHA.
- `src/sophos_firewall_mcp/client.py` REST-only, tipado, con configuración validada y errores tipados.
- `src/sophos_firewall_mcp/server.py` con lifespan, `AppContext`, registro modular y `SOPHOS_READ_ONLY_MODE`.
- Tests de cliente y fundación; `pytest`, `mypy`, `flake8`, `black` en verde.
- PR de fase abierto, sin fusionar.

## Equipo y propiedad de escritura

| Miembro | Tarea | Escribe (exclusivo) | No toca |
|---|---|---|---|
| `contract` | #24 | `docs/API-COVERAGE.md`, `docs/architecture/ADR-001-rest-client-strategy.md`, `scripts/generate_coverage.py`, `docs/live-evidence/README.md` | `src/`, `tests/`, `pyproject.toml` |
| `client` | #25 | `src/sophos_firewall_mcp/client.py`, `config.py`, `errors.py`, `tests/test_client.py`, `tests/test_config.py` | `server.py`, `tools/`, `pyproject.toml` |
| `foundation` | #26 | `src/sophos_firewall_mcp/server.py`, `context.py`, `tools/__init__.py`, `tests/test_server.py`, `tests/test_context.py` | `client.py`, `config.py`, `tools/<dominio>.py` |
| `reviewer` | revisión | nada (solo informe) | todo |
| Lead | integración | `pyproject.toml`, `uv.lock`, rama, commits de integración | código de dominio |

Si alguien necesita un cambio en un fichero ajeno, lo pide por `send_message`; no lo edita.

## Grafo de tareas

```text
T1 [#24 ADR + estrategia de cliente]  ──► T2 [#25 cliente REST] ──► T3 [#26 fundación MCP]
T4 [#24 cobertura + generador]  (paralela, bloquea fase 2)
T5 [revisión independiente]  (bloqueada por T2, T3, T4)
```

- **T1 bloquea T2**: sin decisión de cliente no se implementa el transporte.
- **T2 bloquea T3**: #26 consume la interfaz pública de #25.
- **T4 no bloquea T2/T3**, pero sí la fase 2 y #32.
- **T5** se lanza cuando T2, T3 y T4 estén `completed`.

## Paso a paso

### Paso 0 — Preflight (Lead)

1. `git status` limpio; crea la rama `migration/phase-1-foundation` desde `main`.
2. Verifica el entorno: `uv sync` (si el lock necesita regeneración, regístralo y decide con el propietario; usa `--locked` solo cuando esté al día), `uv run pytest -q` (debe pasar o registrar el fallo de partida).
3. Comprueba que el laboratorio responde **solo lectura** con `LAB-ACCESS.md`; no ejecutes escrituras.
4. Crea las tareas T1–T5 en el tablero con `write_scopes` y `blocked_by`.
5. Crea a `contract`, `client`, `foundation` y `reviewer` con `subagent` (prompts autocontenidos).
6. Envía a cada uno su tarea y el prompt de trabajo; no los lances todos a la vez si hay dependencias.

### Paso 1 — T1: ADR y estrategia de cliente (`contract`)

Entregables:

- `ADR-001-rest-client-strategy.md` con: contexto, opciones (HTTPX+Pydantic manual, `openapi-python-client` ≥0.30.0, híbrido), evidencia de la POC, decisión, consecuencias y riesgos.
- POC acotada: parsear el documento completo, generar/implementar 5 operaciones representativas (GET simple, lista paginada, create IPv4, PATCH NAT, objeto con referencias anidadas), medir tamaño/complejidad, no fusionar código generado.
- `scripts/generate_coverage.py`: parsea el YAML, resuelve `$ref`, valida unicidad de operationId, emite `docs/API-COVERAGE.md` con una fila por operación y secciones por dominio; falla si cambia el SHA-256 sin regeneración revisada.
- `docs/API-COVERAGE.md`: hechos generados + decisiones curadas (alcance v1, exclusiones, excepciones PATCH, paginación, identificadores, estados de error).
- Protocolo `pytest -m live` documentado (solo lectura con la clave actual).

Criterios de aceptación: los de #24, con el AC medible (operationIds, esquemas, códigos, identificadores y paginación por dominio).

**Puerta:** cuando el ADR esté listo, el Lead desbloquea T2 y avisa a `client`.

### Paso 2 — T2: Cliente REST (`client`)

Entregables:

- `config.py`: settings tipados (`SOPHOS_HOST`, `SOPHOS_PORT`, `SOPHOS_API_KEY`/`_FILE` mutuamente excluyentes, `SOPHOS_VERIFY_SSL`, `SOPHOS_CA_BUNDLE`, `SOPHOS_TIMEOUT`), validación de host/puerto, sin secretos en errores.
- `errors.py`: jerarquía `SophosAPIError` → auth/validation/not-found/conflict/ambiguous-write/transport.
- `client.py`: `SophosRestClient` con `get/post/patch/delete`, base URL fija, Bearer, TLS on, timeouts, sin redirects cross-origin, sin URL/path del caller, `aclose()` y `async with`, paginación solo donde el contrato la declara, retry de lectura acotado (2 intentos, 502/503/504, backoff con jitter) y **ningún** retry ciego de escrituras.
- Tests con RESPX: URL/método/query/headers/content-type/body/status por primitiva; 401/400/404/409; timeouts/TLS/JSON malformado; redacción de la clave; rechazo de URL absoluta; cierre del pool.

Criterios: los de #25, incluida la interfaz pública documentada.

**Puerta:** publica la interfaz (métodos, excepciones, `aclose`) en el PR y avisa a `foundation`.

### Paso 3 — T3: Fundación MCP (`foundation`)

Entregables:

- `context.py`: `AppContext(client, settings, read_only)`.
- `server.py`: factory/entrypoint, lifespan que crea **un** cliente y lo cierra en `finally`, registro modular por dominio, `Context[AppContext]` inyectado, `subscriptions=False`, STDIO, logging a stderr.
- Eliminación de `_guard.py`, del router FastEmbed y del raw XML tool; sin `BaseException`.
- `SOPHOS_READ_ONLY_MODE`: no registra herramientas de mutación; test que compara la lista de tools en ambos modos.
- Errores: `ToolError` para fallos previstos, `MCPError` solo protocolo, inesperadas al SDK; `content`/`structuredContent` sin duplicar; `extra="forbid"` donde el contrato es cerrado.
- Tests: lifespan (arranque, config inválida, cierre normal y excepcional, cierre exacto una vez), identidad del contexto, lista de tools, esquemas/anotaciones, errores, cancelación, STDIO con el `Client` del SDK.

Criterios: los de #26.

### Paso 4 — T4: Cobertura (`contract`, en paralelo)

- Ejecuta `scripts/generate_coverage.py` y commitea el resultado.
- Rellena las decisiones curadas por dominio (alcance v1, exclusiones, WAF, VPN read-only, interfaces read-only, live-users, bulk delete).
- Registra las excepciones PATCH (`patchMessages`, `updateCentralFirewallReportingLogComponents`, `updateSyslogServerLogs`, `updateAlertNotificationSettings`).
- Documenta el protocolo live y el formato `docs/live-evidence/<dominio>.md`.

### Paso 5 — T5: Revisión independiente (`reviewer`)

- Crea un `reviewer` **nuevo** (no `subagent_fork`) con el diff, las issues y el plan.
- Debe verificar: contrato vs implementación, seguridad (TLS, secretos, redirects, URL fija), errores, lifecycle, tests que prueban comportamiento, nada fuera de alcance.
- Entrega un informe con hallazgos por severidad y un veredicto: aprobar / cambios requeridos.
- El Lead corrige o reasigna; no se ignora un hallazgo crítico.

### Paso 6 — Integración y cierre (Lead)

1. Revisa `git diff main...HEAD`: solo rutas de la fase.
2. Ejecuta la suite completa y los linters.
3. Comprueba que `docs/API-COVERAGE.md` se regenera sin cambios inesperados.
4. Abre el PR `migration/phase-1-foundation` → `main` con: qué, evidencia, decisiones, riesgos, pendientes.
5. **No fusiones** sin aprobación del propietario.
6. Reporta según el maestro §9.

## Criterios de salida de la fase

- [ ] ADR aprobado por el propietario (o marcado como decisión pendiente explícita).
- [ ] `API-COVERAGE.md` generado y reproducible; SHA registrado.
- [ ] Cliente REST sin XML, con tests y errores tipados.
- [ ] Fundación con lifespan, `AppContext`, registro y read-only mode.
- [ ] `pytest`, `mypy`, `flake8`, `black` en verde.
- [ ] Revisión independiente sin críticos abiertos.
- [ ] PR abierto, sin fusionar.
- [ ] Tablero sin tareas huérfanas.

## Escalación específica

- Si el ADR concluye que hace falta un cliente generado enorme, **pregunta** antes de meterlo en producción.
- Si el contrato no permite implementar una operación con seguridad, documéntalo y no la expongas.
- Si el laboratorio deja de responder, no bloquees la fase: usa mocks y registra la limitación.
