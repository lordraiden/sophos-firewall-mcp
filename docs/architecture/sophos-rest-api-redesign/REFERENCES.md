# Referencias — Sophos Firewall MCP REST redesign

**Última revisión:** 15 de noviembre de 2026 (auditoría independiente).  
**Principio de autoridad:** primero el YAML exacto versionado en este repositorio; después su contraste con el portal OpenAPI oficial y la versión/build de SFOS del appliance objetivo. Las páginas online pueden actualizarse independientemente del YAML local.

Los identificadores [Rxx] se utilizan en [PLAN.md](./PLAN.md) y en las issues #24–#32. La evidencia completa de la auditoría está en [INDEPENDENT_REVIEW_REPORT.md](./INDEPENDENT_REVIEW_REPORT.md).

## A. Repositorio del proyecto y contrato local

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R00 | Repositorio | https://github.com/lordraiden/sophos-firewall-mcp | Código, documentación, issues, CI y despliegue revisados. |
| R00a | YAML OpenAPI versionado | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/firewall_config_openapi.yaml | Contrato inspeccionado. Blob SHA `40fca0b25d4d85866f86b90aec77e5559ae27214`; SHA-256 `58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5`; 8.934.475 bytes; OpenAPI 3.0.0; info.version 1.0.0; 384 paths/700 operaciones con operationId únicos; 32 esquemas de componente; 76 `$ref` (32 únicos, 0 externos, 0 sin resolver). El propio `info.description` documenta base URL, Bearer, formatos de nombre y PATCH JSON Merge Patch. |
| R00b | Cliente XML actual | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/client.py | Transporte que se elimina. Verificado: `SOPHOS_VERIFY_SSL` tiene default de código `true` (el docstring dice `False`), mientras README/Compose/.env.example usan `false`. |
| R00c | Registro MCP actual | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/server.py | Wiring actual que se reemplaza. |
| R00d | Herramientas existentes | https://github.com/lordraiden/sophos-firewall-mcp/tree/main/src/sophos_firewall_mcp/tools | Comportamiento/alcance funcional de partida. |
| R00e | Dependencias | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/pyproject.toml | Dependencias y restricciones actuales. |
| R00f | Changelog | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/CHANGELOG.md | Historial de incidentes y decisiones técnicas. |

## B. Documentación oficial Sophos — API del appliance

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R01 | Sophos Firewall API Reference — overview | https://docs.sophos.com/nsg/sophos-firewall/rest-api/index.html | Base URL `https://<host>:<port>/api/firewall-config/v1`, Bearer, requisitos de API access/Device access, permisos por perfil, gestión de API keys y aviso de timeouts/reintentos (GET reintentable; escrituras no reintentar a ciegas). |
| R02 | Sophos Firewall Configuration API — catálogo OpenAPI | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/sophos-firewall-configuration-api/index.html | Referencia generada desde OpenAPI 3.0; reproduce el `info.description` del YAML: base URL, Bearer, formatos `sfos-object-name*` y PATCH JSON Merge Patch (RFC 7396) por defecto salvo excepción documentada. |
| R03 | Get started with Sophos Firewall REST API — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/APIRestAPI/index.html | Requisitos previos, consideraciones y API key Bearer. |
| R04 | REST API access and API keys — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/APIRestAPI/APIAccessAndKeys/index.html | API access desactivada por defecto; Allowed IP hosts (máximo 64 entradas); API keys por administrador, máximo 10 por administrador y 1.024 por appliance; caducidad de un año; secreto mostrado una sola vez; permisos heredados del perfil; lista de features no soportadas no exhaustiva e internamente inconsistente. |
| R05 | SFOS 23.0 GA Build 371 release notes | https://docs.sophos.com/releasenotes/output/en-us/nsg/sf_230_rn.html | Publicación 4 Nov 2026; la nota sobre reglas deshabilitadas al crearse se refiere al Firewall AI Assistant en Sophos Fusion, no debe extrapolarse sin probar al POST REST. |
| R06 | Firewall rules — GET all IPv4 / operaciones enlazadas | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-firewall-rules-ipv-4/index.html | Navegación IPv4/IPv6 GET, POST create, GET by ID/name, PATCH, DELETE, bulk delete y move. |
| R06a | Create IPv4 firewall rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/create-firewall-rule-ipv-4/index.html | POST /firewall/rules/ipv4; respuestas documentadas 201, 400, 401, 403, 409 y 500. |
| R06b | Update IPv4 firewall rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/update-firewall-rule-ipv-4/index.html | PATCH /firewall/rules/ipv4/:idOrName; respuestas documentadas 200, 400, 401, 403, 404, 409 y 500. |
| R06c | Move IPv4 firewall rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/move-firewall-rule-ipv-4/index.html | POST /firewall/rules/ipv4/move; el cuerpo exige `name` (no `idOrName`), `position` (`after`/`before`/`bottom`/`top`) y `referenceItem` opcional. |
| R07 | Firewall NAT rules | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-nat-rules-ipv-4/index.html | Navegación CRUD, bulk delete y move para IPv4/IPv6 NAT rules. |
| R07a | Create IPv4 NAT rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/create-nat-rule-ipv-4/index.html | POST /nat/rules/ipv4; respuesta 201 y códigos de error específicos. |
| R07b | Update IPv4 NAT rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/update-nat-rule-ipv-4-by-id-or-name/index.html | PATCH por ID o nombre; respuestas específicas por operación. |
| R07c | Move IPv4 NAT rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/move-nat-rule-ipv-4/index.html | Movimiento de regla NAT como operación dedicada. |
| R08 | Authentication users — list | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-users/index.html | GET /authentication/users; paginado con `page`/`pageSize`/`pageTotal` y filtros `nameContains`/`nameNotEquals`. |
| R09 | Authentication live users — list | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-live-users/index.html | GET /authentication/live-users; devuelve `items` más `pages` (`current`, `size`, `maxSize`), sin parámetros de paginación en la petición. |
| R10 | Disconnect a live user session | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/disconnect-live-user/index.html | POST /authentication/live-users/disconnect; `liveUserId` y `message` obligatorios (`message` 1–600); respuestas 200/400/401/403/500. |
| R11 | IPsec site-to-site connections | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/list-ipsec-connections-ipv-4/index.html | Operaciones de configuración IPsec; complementar con perfiles/failover y live connections. |
| R11a | IPsec site-to-site live connections | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-ipsec-site-to-site-live-connections-ipv-4/index.html | Estado operativo de conexiones IPsec IPv4. |
| R11b | SSL VPN remote access policies | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-remote-access-policies/index.html | Políticas de acceso remoto SSL VPN. |
| R12 | RFC 7396 — JSON Merge Patch | https://www.rfc-editor.org/rfc/rfc7396 | Semántica estándar que Sophos declara como default de PATCH en esta API. |
| R21 | Device access profiles — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Profiles/DeviceAccess/index.html | Los perfiles definen permisos None/Read-only/Read-write por configuración/función; afectan a Web Admin Console y API. |
| R22 | Allow API access to administrators — SFOS 22.0 | https://docs.sophos.com/nsg/sophos-firewall/22.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/API/HowToArticles/APIAllowAccess/ | Flujo completo: perfil, administrador, API access, Device access y acceso desde LAN/WAN. Para WAN, la regla de excepción de Local service ACL es el único mecanismo documentado y exige IPs de origen concretas (no `Any`/`0.0.0.0`). |
| R23 | Web admin console access — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/StartupHelp/ManageSophosFirewall/GettingStartedWebAdminConsole/index.html | Acceso desde otras zonas en Administration > Device access y puerto HTTPS administrativo. |
| R24 | Firewall health check — Web Admin Console | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/FirewallHealthCheck/index.html | Comprobación de cumplimiento de políticas (CIS/recomendadas, compliant/noncompliant, override manual). No demuestra que exista un endpoint equivalente en Configuration REST API. |
| R25 | DNS protection status endpoint | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-dns-protection-status/index.html | Operación GET /network/dns/protection/status (`getDnsProtectionStatus`). |
| R26 | Cellular WAN modem status endpoint | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-cellular-wan-status/index.html | Operación GET /network/cellular-wan/modem-status (`getCellularWanStatus`). |
| R27 | Web admin console HTTPS settings — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/StartupHelp/ManageSophosFirewall/GettingStartedWebAdminConsole/index.html | HTTPS Web Admin Console, puerto predeterminado 4444, interfaz LAN; habilitar acceso desde otras zonas en Device access; Sophos desaconseja exponer la consola en WAN. |
| R28 | Device access profiles — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Profiles/DeviceAccess/index.html | Los perfiles aplican a Web Admin Console y API; permisos None/Read-only/Read-write. |
| R33 | Device access best practices — SFOS 23.0 | https://docs.sophos.com/nsg/sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/DeviceAccess/DeviceAccessBestPractices/index.html | Sophos no recomienda habilitar HTTPS/SSH/portal desde WAN; si es imprescindible, exige una regla de excepción de Local service ACL con IPs de origen concretas. |
| R34 | Interfaces — SFOS 23.0 | https://docs.sophos.com/nsg/sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Network/Interfaces/index.html | Aviso: tras actualizar o eliminar interfaces, las conexiones de red pueden quedar temporalmente inaccesibles; borrar una interfaz borra las reglas que la usan. |

### Notas de interpretación de Sophos

- La API es la Configuration REST API del firewall appliance, no la Sophos Central Firewall Management API.
- El portal de API Reference **no declara versión de SFOS** (solo "Version: 1.0.0", la del contrato); la vinculación con SFOS 23.0 viene de la ayuda 23.0 y de las release notes.
- API access allowlist y Device access son controles distintos y ambos son necesarios. El acceso desde WAN solo se documenta mediante la regla de excepción de Local service ACL, que forma parte de Administration > Device access.
- API keys heredan permisos del administrador y expiran al año. La rotación es manual: no existe endpoint de gestión de claves en el contrato.
- Los códigos HTTP varían por operación. En el contrato, 401/403/500 aparecen en las 700 operaciones, 400 en 636, 404 en 272, 409 en 217, 201 en 92 y 503 en una (`createIpsCustomSignature`). No construir una tabla universal.
- Sophos recomienda dedicar una cuenta de administrador por automatización y asignar únicamente permisos necesarios.
- La consola administrativa HTTPS usa 4444 por defecto en SFOS 23.0 y se puede configurar. No inferir que la interfaz WAN deba habilitar Web Admin Console; Sophos lo desaconseja.
- Sophos documenta para esta API que PATCH usa JSON Merge Patch (RFC 7396) por defecto salvo overrides por operación; el propio YAML lo reproduce. Las 134 PATCH declaran `application/json`; ninguna declara `application/merge-patch+json`.
- GET /authentication/users y /authentication/users/network-users tienen page/pageSize/pageTotal y filtros de nombre; GET /authentication/live-users responde items + pages metadata sin paginación de petición.
- La lista de features no soportadas no es exhaustiva y es internamente inconsistente con el catálogo (wireless/hotspot, DHCP leases); verificar endpoint a endpoint.
- Los `format` `sfos-object-name*` son no asertivos (994 de 1.085 sin `pattern`); el cliente debe implementar la validación documentada.

## C. MCP — protocolo, SDK oficial y prácticas

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R13 | openapi-python-client — repositorio | https://github.com/openapi-generators/openapi-python-client | Generador candidato para la prueba de viabilidad, no una elección predeterminada. |
| R13a | openapi-python-client releases | https://github.com/openapi-generators/openapi-python-client/releases | Versiones y cambios; 0.29.1 (30 Ago 2026) y 0.30.0 (7 Nov 2026). |
| R13b | GHSA-5293-mq8x-g3xj — code generation RCE | https://github.com/openapi-generators/openapi-python-client/security/advisories/GHSA-5293-mq8x-g3xj | Versiones anteriores a 0.29.1 afectadas por generación arbitraria de código desde documentos OpenAPI maliciosos. |
| R13c | GHSA-jg6c-wvfg-fx69 — multipart field injection | https://github.com/openapi-generators/openapi-python-client/security/advisories/GHSA-jg6c-wvfg-fx69 | Afecta a >=0.29.0,<0.30.0; corregido en 0.30.0. Por eso el mínimo es 0.30.0, no 0.29.1. |
| R14 | MCP Python SDK releases | https://github.com/modelcontextprotocol/python-sdk/releases | Historial de SDK; v2.3.0 es la última release estable observada (2 Oct 2026), sin parche posterior a 15 Nov 2026. |
| R15 | MCP Python SDK v2 — What's new | https://py.sdk.modelcontextprotocol.io/v2/whats-new/ | Cambios principales de v2 y protocolo actual; el mismo servidor atiende ambas eras. |
| R15a | MCP 2026-07-28 specification release overview | https://blog.modelcontextprotocol.io/posts/2026-07-28/ | Núcleo stateless, sin initialize/initialized ni sesiones de protocolo, `server/discover` obligatorio, MRTR. |
| R16 | MCP Python SDK — Lifespan | https://py.sdk.modelcontextprotocol.io/v2/handlers/lifespan/ | Un contexto tipado compartido; iniciar recursos antes de yield y cerrarlos en finally. |
| R16a | MCP Python SDK — Tools | https://py.sdk.modelcontextprotocol.io/v2/servers/tools/ | Herramientas async, parámetros Pydantic/Annotated/Field, enums, descripciones, títulos y anotaciones. |
| R17 | MCP Python SDK — Structured Output | https://py.sdk.modelcontextprotocol.io/v2/servers/structured-output/ | Inferencia de output schema desde return types; content y structured_content; validación del valor devuelto. |
| R18 | MCP Tool Annotations — risk vocabulary and limits | https://py.sdk.modelcontextprotocol.io/v2/servers/tools/#names-titles-and-annotations | title/readOnly/destructive/idempotent/openWorld son hints, no enforcement ni autorización. |
| R19 | MCP Python SDK — Handling errors | https://py.sdk.modelcontextprotocol.io/servers/handling-errors/ | ToolError para error de ejecución visible al modelo; MCPError para error de protocolo; excepciones inesperadas registradas por SDK. |
| R20 | MCP Inspector — repo/documentación | https://github.com/modelcontextprotocol/inspector | Herramienta oficial de prueba para descubrir herramientas y revisar esquemas/resultados. |
| R29 | MCP Python SDK v2 — Tools | https://py.sdk.modelcontextprotocol.io/v2/servers/tools/ | Tool schemas, nombres/títulos/descripciones, inputs tipados y anotaciones readOnly/openWorld/destructive/idempotent. |
| R30 | MCP Python SDK v2 — Lifespan | https://py.sdk.modelcontextprotocol.io/v2/handlers/lifespan/ | El lifespan produce un único contexto compartido; el SDK inyecta Context y excluye ese parámetro del input schema. |
| R31 | MCP Python SDK v2 — Structured Output | https://py.sdk.modelcontextprotocol.io/v2/servers/structured-output/ | El tipo de retorno define outputSchema; validación del resultado y canales content/structuredContent. |
| R32 | MCP Tool Annotations as Risk Vocabulary (blog) | https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/ | Interpretación **no normativa** de `openWorldHint` como límite de confianza; la fuente normativa es R37. |
| R35 | MCP Python SDK v2.3.0 release notes | https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.3.0 | Introduce `MCPServer(subscriptions=False)`: deja de servir `subscriptions/listen` y anuncia `listChanged`/`subscribe` como false. |
| R36 | MCP deprecated features registry — 2026-07-28 | https://modelcontextprotocol.io/specification/2026-07-28/deprecated | Roots, Sampling y Logging deprecados por SEP-2577 (retirada elegible desde 2027-07-28); `ping`, `logging/setLevel` y `notifications/roots/list_changed` eliminados. |
| R37 | MCP schema 2026-07-28 (`schema.ts`) | https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts | Fuente normativa de `ToolAnnotations` (defaults), `outputSchema`, `structuredContent`, `server/discover` y versiones de protocolo. |
| R38 | MCP 2026-07-28 changelog | https://modelcontextprotocol.io/specification/2026-07-28/changelog | Lista de cambios: stateless, `server/discover`, SEP-2106 (outputSchema/structuredContent), eliminación de `ping`/`logging/setLevel`/`roots/list_changed`. |
| R39 | MCP Python SDK protocol-version registry | https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp_types/version.py | `HANDSHAKE_PROTOCOL_VERSIONS` (2024-11-05…2025-11-25) y `MODERN_PROTOCOL_VERSIONS` (2026-07-28); confirma la compatibilidad del SDK 2.3.0. |

## D. Referencias de implementación local

- [Cliente XML actual](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/client.py)
- [Registro MCP actual](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/server.py)
- [Guard actual](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/_guard.py)
- [Router semántico actual](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/router.py)
- [Herramientas actuales](https://github.com/lordraiden/sophos-firewall-mcp/tree/main/src/sophos_firewall_mcp/tools)
- [Pruebas actuales](https://github.com/lordraiden/sophos-firewall-mcp/tree/main/tests)
- [pyproject.toml](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/pyproject.toml), [requirements.txt](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/requirements.txt)
- [Dockerfile](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/Dockerfile), [docker-compose.yml](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/docker-compose.yml)
- [GitHub Actions](https://github.com/lordraiden/sophos-firewall-mcp/tree/main/.github/workflows)

## E. Reglas de mantenimiento bibliográfico

1. Registrar en docs/API-COVERAGE.md el SHA-256 exacto del YAML auditado y las versiones openapi/info.version.
2. Guardar evidencia de la versión/build del firmware probado; el portal online no determina la versión del appliance destino.
3. Para cada operación, documentar path, method, request media type, schemas, response codes, error schema, paginación y permisos.
4. No generalizar media types, respuestas, paginación o defaults a partir de otro endpoint.
5. Volver a comprobar las limitaciones publicadas y el API Reference al ampliar dominios.
6. Para SDK MCP, actualizar el pin y revisar migration notes/release notes antes de saltar de minor version.
7. Distinguir fuente normativa (spec/schema) de fuente interpretativa (blog, guía); citar la normativa cuando la afirmación sea de protocolo.
