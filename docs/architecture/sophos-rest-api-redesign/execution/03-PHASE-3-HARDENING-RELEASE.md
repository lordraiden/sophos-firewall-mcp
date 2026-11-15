# 03 — Fase 3: Hardening y release (#32)

> **Antes de empezar:** lee y aplica [`00-MASTER-PROMPT.md`](./00-MASTER-PROMPT.md). **Precondición:** fases 1 y 2 fusionadas y verificadas.

## Objetivo de la fase

Cerrar la migración: verificación end-to-end, seguridad, CI, contenedor, documentación y preparación de release. **La publicación real requiere aprobación explícita del propietario.**

**Issue:** [#32](https://github.com/lordraiden/sophos-firewall-mcp/issues/32).

## Estructura en dos puertas

| Puerta | Contenido | ¿Requiere aprobación? |
|---|---|---|
| **A — Hardening** | e2e MCP, integración live (solo lectura), seguridad, CI, Docker, docs | No; se ejecuta y se revisa |
| **B — Release** | versión, tags, GHCR, `latest`, notas de release | **Sí, explícita del propietario** |

No empieces la puerta B hasta que A esté verde y revisada.

## Preflight (Lead)

1. Confirma que `main` contiene fases 1 y 2, suite en verde y `API-COVERAGE.md` actualizado.
2. Crea la rama `migration/phase-3-hardening-release`.
3. Crea tareas T33–T38 + T39 (revisión) con `write_scopes` disjuntos.
4. Crea a `hardening`, `release` y `reviewer`.
5. Verifica que la clave del laboratorio sigue siendo de **solo lectura**; no hay escrituras en esta fase.

## Propiedad de escritura

| Miembro | Escribe (exclusivo) | No toca |
|---|---|---|
| `hardening` | `.github/workflows/`, `Dockerfile`, `docker-compose.yml`, `entrypoint.sh`, `tests/` (integración), `docs/live-evidence/` | `src/` salvo correcciones aprobadas por el Lead |
| `release` | `pyproject.toml`, `uv.lock`, `README.md`, `.env.example`, `CHANGELOG.md`, metadatos de release | workflows, Docker, `src/` |
| `reviewer` | nada (informe) | todo |
| Lead | integración, PR, decisión de publicar | — |

`pyproject.toml`/`uv.lock` son de `release`; si `hardening` necesita un cambio, lo pide.

## Tareas

### T33 — Verificación end-to-end MCP (`hardening`)

- Tests con el `Client` oficial del SDK: descubrimiento, esquemas de entrada/salida, anotaciones, `isError`, cancelación.
- Prueba de STDIO en subproceso: stdout solo protocolo, sin TTY, cierre ordenado.
- Compatibilidad: 2026-07-28 por defecto y `mode="legacy"` si se declara soporte heredado.
- MCP Inspector: smoke test de descubrimiento y llamadas representativas.
- Registra evidencia en el PR.

### T34 — Integración con el appliance (`hardening` + `reviewer`)

- Matriz en `API-COVERAGE.md`: live-tested / contract-tested / unsupported / deferred / not implemented.
- Ejecuta `pytest -m live` **solo lectura** con la clave del laboratorio; registra build, perfil, fecha y operaciones en `docs/live-evidence/`.
- No escribas reglas, NAT, interfaces, VPN ni sesiones. Si hace falta una prueba de escritura, **para y pide** clave de escritura + plan de objetos desechables.
- Documenta lo que no se pudo probar y por qué.

### T35 — Revisión de seguridad (`hardening` + `reviewer`)

- Flujo de la API key: origen, `SecretStr`, fichero vs env, permisos, montaje, redacción en logs/errores/tools.
- TLS por defecto, CA bundle, sin `verify=false` en ejemplos.
- Redirects cross-origin, proxy explícito, timeouts, cierre del pool.
- Sin secretos en imágenes, CI, artefactos ni capturas.
- Errores sanitizados; cuerpos remotos no se devuelven crudos.
- Revisa `pip-audit` sobre el lock real y `semgrep`.

### T36 — CI y pipeline (`hardening`)

- `uv sync --locked` en CI/build; `pyproject.toml` + `uv.lock` como fuente única.
- Matriz Python 3.11–3.14.
- `pip-audit` sobre la resolución bloqueada real, no sobre `requirements.txt` obsoleto.
- Tests, lint, mypy, semgrep y build de imagen en PR.
- Workflow de integración opt-in (`pytest -m live`) con secretos, sin imprimirlos.
- Sin `latest` en pushes a `main`: solo tags de desarrollo (`main`, SHA).

### T37 — Contenedor y documentación (`hardening` + `release`)

- `Dockerfile`: sin FastEmbed ni descarga de modelos, sin `.[router]`, usuario no-root si es viable, sin TTY, `ENTRYPOINT` STDIO, señales y cierre ordenado.
- `docker-compose.yml`: solo configuración REST y secreto; `tty: false`; sin credenciales XML.
- `README.md`: REST-only, requisitos Sophos, variables, ejemplos de cliente MCP, nombres de imagen correctos.
- `.env.example`: REST-only, sin usuario/contraseña XML, TLS seguro por defecto.
- `CHANGELOG.md`: cambios de la migración.
- Verifica el namespace canónico de GHCR (`ghcr.io/lordraiden/...`) y corrige enlaces.

### T38 — Preparación de release (`release`, solo con aprobación)

- Versión semántica y notas de release.
- Workflow de publicación: `main` → tags de desarrollo; `v*` → tags estables; `latest` solo en promoción aprobada.
- GitHub Environment con revisores si el propietario lo aprueba.
- **No** publiques tag, imagen estable ni `latest` sin aprobación explícita.
- Adjunta el plan de rollback.

## Revisión (T39)

- `reviewer` independiente revisa el PR completo: seguridad, CI, Docker, docs, evidencia live.
- Veredicto: aprobar / cambios requeridos.
- El Lead corrige o reasigna; los críticos bloquean.

## Cierre

1. Suite completa, linters, build de imagen y smoke test STDIO en verde.
2. `git diff main...HEAD` limitado al alcance.
3. PR de fase con evidencia, riesgos y pendientes.
4. **Puerta B:** pide aprobación explícita al propietario antes de cualquier publicación.
5. Reporta según el maestro §9.

## Criterios de salida

- [ ] e2e MCP y STDIO verificados con el SDK oficial.
- [ ] Matriz live/contract/unsupported/deferred completa.
- [ ] Seguridad revisada sin críticos.
- [ ] CI con lock, matriz 3.11–3.14, `pip-audit` real, semgrep.
- [ ] Docker REST-only, sin TTY, sin FastEmbed, no-root si es viable.
- [ ] README/`.env.example`/CHANGELOG coherentes.
- [ ] GHCR y política de tags corregidas; `latest` solo con aprobación.
- [ ] PR abierto, sin fusionar; release **no** publicada.
- [ ] Evidencia live registrada o diferida con motivo.

## Escalación específica

- Si falta el build de SFOS o una clave de escritura, **no inventes** evidencia: registra el bloqueo.
- Si el propietario no aprueba el release, deja la puerta B preparada y documentada, sin publicar.
- Si un cambio de CI/Docker rompe la suite, revierte y reporta; no lo ocultes.
