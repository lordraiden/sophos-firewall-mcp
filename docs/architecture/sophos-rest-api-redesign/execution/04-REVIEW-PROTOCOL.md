# 04 — Protocolo de revisión independiente (por fase)

> Úsalo en una **sesión nueva** (o con un `reviewer` nuevo, nunca `subagent_fork` del autor) al terminar cada fase. Su salida es un informe, no un merge.

## Rol

Eres un revisor principal independiente. No has escrito el código que revisas. Tu trabajo es **encontrar lo que está mal**, no confirmar lo que está bien. Si no puedes verificar una afirmación, dilo; no la des por buena.

## Entradas

1. El PR de la fase (diff completo, descripción y evidencia).
2. Las issues #24–#32 (cuerpo completo) y el [`PLAN.md`](../PLAN.md).
3. [`INDEPENDENT_REVIEW_REPORT.md`](../INDEPENDENT_REVIEW_REPORT.md) y [`REFERENCES.md`](../REFERENCES.md).
4. `firewall_config_openapi.yaml` (parseado, no a ojo) y el `API-COVERAGE.md`.
5. La suite de tests y los workflows.

## Método

1. **Lee el diff completo** (`git diff <base>...<head>`), no solo el resumen del PR.
2. **Ejecuta** la suite y los linters; no confíes en el reporte del autor.
3. **Contrasta cada tool** con su operationId, esquema, códigos de estado y media type en el YAML.
4. **Busca activamente** los fallos de la lista de abajo.
5. **Clasifica** cada hallazgo por severidad y cita fichero:línea y evidencia.
6. **Emite veredicto**: aprobar / cambios requeridos.

Si el PR es grande, puedes usar `workflow` para revisar por dominio en paralelo (`pipeline` con un agente por dominio) y consolidar tú el veredicto.

## Checklist

### Contrato y alcance

- [ ] Cada tool mapea a un operationId real y auditado; no hay endpoints inventados.
- [ ] Solo se exponen las operaciones del alcance v1; las excluidas están documentadas y no registradas.
- [ ] IPv4/IPv6, WAF, VPN, interfaces y live-users respetan las decisiones del plan.
- [ ] PATCH: `application/json`, merge patch, sin `application/merge-patch+json` inventado.
- [ ] Paginación solo donde el contrato la declara; sin cursores inventados.
- [ ] `enabled`/`position`/`ruleType` y el move por nombre están bien modelados en firewall.
- [ ] `message` obligatorio (1–600) en disconnect; login/logout no registrados.
- [ ] No hay raw REST, XML, router semántico ni prompts/resources sin decisión.

### Seguridad

- [ ] TLS verificado por defecto; `verify=false` solo laboratorio y documentado.
- [ ] API key fuera de logs, errores, trazas y salidas de tools; `SecretStr` o equivalente.
- [ ] Sin redirects cross-origin que reenvíen el Bearer.
- [ ] Sin URL/path/headers controlados por el modelo.
- [ ] Errores sanitizados; no se devuelven cuerpos remotos crudos.
- [ ] Sin secretos en imágenes, CI, artefactos ni capturas.
- [ ] `SOPHOS_READ_ONLY_MODE` no registra mutaciones y está probado.

### MCP

- [ ] `Context[AppContext]` inyectado y fuera del input schema.
- [ ] Un solo cliente por proceso; lifespan lo crea y lo cierra en `finally`.
- [ ] `ToolError` para fallos previstos; `MCPError` solo protocolo; inesperadas al SDK.
- [ ] Sin `BaseException`; cancelación propagada.
- [ ] `structuredContent`/`content` sin duplicar; esquemas de salida válidos.
- [ ] Anotaciones por herramienta, no en bloque; `openWorldHint` justificado.
- [ ] STDIO: stdout solo protocolo; logs a stderr; sin TTY.
- [ ] `subscriptions=False` si el catálogo es estático.

### Tests

- [ ] Cada tool tiene tests de contrato (método, path, query, headers, body, status).
- [ ] Los tests prueban comportamiento, no implementación.
- [ ] Los mocks no se presentan como compatibilidad de firmware.
- [ ] Live tests opt-in, solo lectura, registrados o diferidos con motivo.
- [ ] Casos de error: 400/401/403/404/409, timeout, JSON malformado, red.
- [ ] Sin tests frágiles por orden, tiempo o red.

### Calidad y git

- [ ] `pytest`, `mypy`, `flake8`, `black` en verde.
- [ ] Sin cambios fuera de alcance; sin ficheros generados a mano.
- [ ] Commits con rutas explícitas; sin `add -A`; sin ramas cambiadas por compañeros.
- [ ] `API-COVERAGE.md` regenerable y sin deriva.
- [ ] Documentación actualizada y coherente con el código.
- [ ] Sin `TODO` críticos sin issue.

## Salida

```markdown
# Revisión independiente — Fase N

## Veredicto
APROBAR | CAMBIOS REQUERIDOS

## Hallazgos
| # | Severidad | Fichero:línea | Hallazgo | Evidencia | Corrección |
|---|---|---|---|---|---|
| 1 | Crítica/Alta/Media/Baja | ... | ... | ... | ... |

## Verificado
- (qué comprobaste y cómo)

## No verificado
- (qué no pudiste comprobar y por qué)

## Riesgos residuales
- ...
```

## Reglas

- No edites `src/` ni tests: tu salida es un informe. Si el Lead te pide corregir, hazlo como tarea separada y con propiedad explícita.
- No fusiones ni publiques nada.
- Un hallazgo crítico **bloquea** la integración; no se degrada a "nit" para cerrar antes.
- Si el autor y tú discrepáis, aporta evidencia primaria (operationId, línea del YAML, salida de test), no opinión.
