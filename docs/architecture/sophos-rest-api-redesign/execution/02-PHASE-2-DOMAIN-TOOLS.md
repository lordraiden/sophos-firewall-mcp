# 02 — Fase 2: Herramientas de dominio (#27–#31)

> **Antes de empezar:** lee y aplica [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md). **Precondición:** la fase 1 está fusionada (o al menos `AppContext`, la firma de registro y el cliente REST están disponibles en `main`).

## Objetivo de la fase

Implementar las cinco familias de herramientas de dominio sobre la fundación de la fase 1, con contratos tipados, pruebas y cobertura, **sin tocar la fundación**.

**Issues:** [#27](https://github.com/lordraiden/sophos-firewall-mcp/issues/27) firewall rules, [#28](https://github.com/lordraiden/sophos-firewall-mcp/issues/28) NAT rules, [#29](https://github.com/lordraiden/sophos-firewall-mcp/issues/29) objetos y servicios, [#30](https://github.com/lordraiden/sophos-firewall-mcp/issues/30) usuarios y sesiones, [#31](https://github.com/lordraiden/sophos-firewall-mcp/issues/31) VPN, interfaces y estado.

**No entra:** cambios en `client.py`, `config.py`, `server.py`, `context.py`, `pyproject.toml`, CI, Docker ni release. Si hace falta un cambio ahí, se pide al Lead y se hace como tarea separada.

## Preflight (Lead)

1. Verifica en `main` (o en la rama base) que existen y están documentados: `AppContext`, la firma `register_<domain>_tools(...)`, el cliente REST y la jerarquía de errores. Si no, **para**: la fase 1 no está lista.
2. Crea la rama `migration/phase-2-domain-tools`.
3. Crea las tareas T27–T31 + T32 (revisión) con `write_scopes` disjuntos y `blocked_by` vacío (la fundación ya está).
4. Crea a `firewall`, `nat`, `objects`, `users`, `vpn` y `reviewer`.
5. Asigna una tarea por agente y envía el prompt de trabajo. Los cinco pueden trabajar en paralelo porque sus ficheros son disjuntos.

## Propiedad de escritura (disjunta)

| Miembro | Issue | Escribe (exclusivo) | No toca |
|---|---|---|---|
| `firewall` | #27 | `src/sophos_firewall_mcp/tools/firewall_rules.py`, `tests/test_firewall_rules.py`, `docs/api-coverage/firewall.md` | fundación, otras tools, `API-COVERAGE.md` |
| `nat` | #28 | `tools/nat_rules.py`, `tests/test_nat_rules.py`, `docs/api-coverage/nat.md` | ídem |
| `objects` | #29 | `tools/hosts_objects.py`, `tools/services_objects.py`, `tests/test_hosts_objects.py`, `tests/test_services_objects.py`, `docs/api-coverage/objects.md` | ídem |
| `users` | #30 | `tools/users_auth.py`, `tests/test_users_auth.py`, `docs/api-coverage/users.md` | ídem |
| `vpn` | #31 | `tools/vpn.py`, `tools/system.py`, `tests/test_vpn.py`, `tests/test_system.py`, `docs/api-coverage/vpn.md` | ídem |
| `reviewer` | — | nada (informe) | todo |
| Lead | integración | `docs/API-COVERAGE.md` (ensamblado), rama, commits de integración | código de dominio |

**Regla de `API-COVERAGE.md`:** si es un solo fichero, **nadie lo edita en paralelo**. Cada dominio escribe su fragmento en `docs/api-coverage/<dominio>.md`; el Lead (o el generador de #24) los ensambla al final. Si el generador ya soporta fragmentos, usadlo.

## Patrón común para cada dominio

Cada agente debe:

1. Leer su issue completa, la sección de cobertura de su dominio y el contrato OpenAPI de las operaciones que va a implementar.
2. Implementar **solo** las operaciones del alcance v1 de la issue; el resto se documenta como diferido/excluido.
3. Usar el cliente REST compartido vía `AppContext`; **nunca** construir URLs, headers ni un cliente HTTP propio.
4. Definir DTOs de entrada/salida tipados (Pydantic), con `extra="forbid"` cuando el contrato sea cerrado; no devolver payloads crudos de Sophos.
5. Anotar cada tool: `title`, `read_only_hint`, y `destructive_hint`/`idempotent_hint` solo en escritura; `open_world_hint` decidido por herramienta (no en bloque).
6. Mapear errores a `ToolError` con mensajes sanitizados; nada de cuerpos crudos ni stack traces.
7. Paginar solo donde el contrato lo declare; una página por llamada; sin auto-paginación.
8. Escribir tests de contrato con RESPX (método, path, query, headers, body, content-type, status), tests de modelos y tests de anotaciones/descubrimiento.
9. No hacer escrituras contra el laboratorio; `pytest -m live` solo lectura y registrado en `docs/live-evidence/`.
10. Commits con rutas explícitas y mensajes `feat(<dominio>): ...` / `test(<dominio>): ...`.

## Tareas por dominio

### T27 — Firewall rules (`firewall`)

- IPv4/IPv6: list, get, create, update, delete, move.
- **`enabled` es obligatorio y el default del schema es `true`**: la entrada MCP debe exigirlo explícitamente con default `false` (o forzar la elección), enviarlo siempre y devolver el estado real.
- `position` es obligatorio en create (`after|before|bottom|top` + `referenceItem` opcional); `move` identifica la regla por **nombre**, no por `idOrName`.
- **WAF excluido en v1**: rechazar `ruleType: waf`; IPv6 no tiene discriminador.
- Bulk delete: documentado, **no expuesto**.
- Filtros `nameContains`/`nameNotEquals` y paginación documentada.

### T28 — NAT rules (`nat`)

- IPv4/IPv6: list, get, create, update, delete, move.
- **No hay discriminador SNAT/DNAT**: modelar los campos reales (`originalServicesOrGroups`, `inboundInterfaces`, `outboundInterfaces`, `originalSourceNetworks`, `originalDestinationNetworks`, `translatedSource`, `translatedDestination`, `overrideSnatForOutboundInterfaces`, …).
- Bulk delete documentado, no expuesto.
- PATCH con semántica JSON Merge Patch; preservar campos omitidos.

### T29 — Objetos y servicios (`objects`)

- Addresses IPv4/IPv6/FQDN y sus grupos; services y service groups.
- MAC y country groups: clasificados y **diferidos**.
- No mezclar familias ni reutilizar un modelo genérico; membresía y referencias exactas.
- Sin cascade delete; conflictos por objeto en uso → error claro.

### T30 — Usuarios y sesiones (`users`)

- `getUsers` (paginado, filtros), CRUD de network users, `getLiveUsers`, `disconnectLiveUser`.
- `updateNetworkUser` es **PATCH**: merge patch, `application/json`, preservar omitidos.
- `disconnectLiveUser`: `liveUserId` y `message` obligatorios (`message` 1–600); destructivo.
- Login/logout de network users: clasificados, **no registrados**.
- Administradores y user groups: fuera de alcance.
- Credenciales: write-only, nunca en salida ni logs.

### T31 — VPN, interfaces y estado (`vpn`)

- **VPN solo lectura en v1**: perfiles, failover groups, conexiones policy/route-based IPv4, live connections, remote-access settings, SSL VPN policies/bookmarks/global settings.
- **Interfaces solo lectura**: `listNetworkInterfaces`, `getNetworkInterface`; mutaciones diferidas.
- Estado: `getDnsProtectionStatus`, `getCellularWanStatus`; **no** crear un "firewall health" genérico.
- Sin IPv6 site-to-site (no existe en el contrato).
- No inferir start/stop/reconnect de la UI.

## Revisión (T32)

1. `reviewer` independiente (nuevo, no fork) revisa los cinco diffs contra las issues y el plan.
2. Para profundidad, el Lead puede lanzar un `workflow` de revisión adversarial por dominio (un agente por dominio, `pipeline`), pero el veredicto final lo firma `reviewer`.
3. Hallazgos por severidad; los críticos bloquean la integración.
4. El Lead corrige o reasigna; no se ignora un crítico.

## Integración y cierre (Lead)

1. Ensambla `docs/API-COVERAGE.md` desde los fragmentos; regenera y comprueba que no hay deriva.
2. Ejecuta la suite completa y linters.
3. Revisa que ningún agente tocó ficheros de la fundación ni de otro dominio (`git log --stat` por commit).
4. Abre **un PR de fase** `migration/phase-2-domain-tools` → `main` (o varios PRs por dominio si el propietario lo pide; con un solo worktree, el PR de fase es lo seguro).
5. No fusiones sin aprobación.
6. Reporta según el maestro §9.

## Criterios de salida

- [ ] Cinco dominios implementados con el alcance v1 exacto.
- [ ] Cada tool mapea a operationIds auditados y tiene tests de contrato.
- [ ] Anotaciones y esquemas verificados en el wire (tools/list).
- [ ] `API-COVERAGE.md` ensamblado y regenerable.
- [ ] `pytest`, `mypy`, `flake8`, `black` en verde.
- [ ] Revisión independiente sin críticos abiertos.
- [ ] PR abierto, sin fusionar.
- [ ] Sin escrituras contra el laboratorio; evidencia live solo lectura registrada o diferida.

## Escalación específica

- Si un dominio necesita una decisión de producto (WAF, mutaciones VPN, interfaces), **pregunta**; no la tomes por el agente.
- Si el contrato no permite un DTO seguro, documenta la limitación y expón solo lo verificable.
- Si dos dominios necesitan el mismo helper, el Lead decide dónde vive (capa compartida) antes de duplicarlo.
