# Referencias — Sophos Firewall MCP REST redesign

**Última revisión:** 14 de noviembre de 2026.  
**Principio de autoridad:** primero el YAML exacto versionado en este repositorio; después su contraste con el portal OpenAPI oficial y la versión/build de SFOS del appliance objetivo. Las páginas online pueden actualizarse independientemente del YAML local.

Los identificadores [Rxx] se utilizan en [PLAN.md](./PLAN.md).

## A. Repositorio del proyecto y contrato local

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R00 | Repositorio | https://github.com/lordraiden/sophos-firewall-mcp | Código, documentación, issues, CI y despliegue revisados. |
| R00a | YAML OpenAPI versionado | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/firewall_config_openapi.yaml | Contrato que debe auditarse. Blob SHA observado: 40fca0b25d4d85866f86b90aec77e5559ae27214; 8.934.475 bytes. |
| R00b | Cliente XML actual | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/client.py | Transporte que se elimina. |
| R00c | Registro MCP actual | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/server.py | Wiring actual que se reemplaza. |
| R00d | Herramientas existentes | https://github.com/lordraiden/sophos-firewall-mcp/tree/main/src/sophos_firewall_mcp/tools | Comportamiento/alcance funcional de partida. |
| R00e | Dependencias | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/pyproject.toml | Dependencias y restricciones actuales. |
| R00f | Changelog | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/CHANGELOG.md | Historial de incidentes y decisiones técnicas. |

## B. Documentación oficial Sophos — API del appliance

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R01 | Sophos Firewall API Reference — overview | https://docs.sophos.com/nsg/sophos-firewall/rest-api/index.html | Descripción del API del appliance, base URL, autenticación, acceso desde endpoints/zones y referencia. |
| R02 | Sophos Firewall Configuration API — catálogo OpenAPI | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/sophos-firewall-configuration-api/index.html | Referencia generada desde OpenAPI 3.0; portal indica API version 1.0.0, Bearer auth, base URL, formatos comunes de nombres/UUID y JSON Merge Patch como default de PATCH salvo excepciones documentadas. No asumir que el YAML local tiene igual info.version hasta leerlo. |
| R03 | Get started with Sophos Firewall REST API — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/APIRestAPI/index.html | Requisitos previos, consideraciones y API key Bearer. |
| R04 | REST API access and API keys — SFOS 23.0 | https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/APIRestAPI/APIAccessAndKeys/index.html | Habilitar API access, Allowed IP hosts, API keys, permisos heredados, duración un año y funcionalidades no soportadas. La lista no es exhaustiva. |
| R05 | SFOS 23.0 GA Build 371 release notes | https://docs.sophos.com/releasenotes/output/en-us/nsg/sf_230_rn.html | Publicación 4 Nov 2026; la nota sobre reglas deshabilitadas al crearse se refiere al Firewall AI Assistant en Sophos Fusion, no debe extrapolarse sin probar al POST REST. |
| R06 | Firewall rules — GET all IPv4 / operaciones enlazadas | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-firewall-rules-ipv-4/index.html | La navegación lista IPv4/IPv6 GET, POST create, GET by ID/name, PATCH, DELETE, bulk delete y move. Ejemplos de códigos distintos por operación. |
| R06a | Create IPv4 firewall rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/create-firewall-rule-ipv-4/index.html | POST /firewall/rules/ipv4; respuestas documentadas 201, 400, 401, 403, 409 y 500. |
| R06b | Update IPv4 firewall rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/update-firewall-rule-ipv-4/index.html | PATCH /firewall/rules/ipv4/:idOrName; respuestas documentadas 200, 400, 401, 403, 404, 409 y 500. |
| R06c | Move IPv4 firewall rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/move-firewall-rule-ipv-4/index.html | POST /firewall/rules/ipv4/move; move como operación específica. |
| R07 | Firewall NAT rules | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-nat-rules-ipv-4/index.html | Navegación CRUD, bulk delete y move para IPv4/IPv6 NAT rules. |
| R07a | Create IPv4 NAT rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/create-nat-rule-ipv-4/index.html | POST /nat/rules/ipv4; respuesta 201 y códigos de error específicos. |
| R07b | Update IPv4 NAT rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/update-nat-rule-ipv-4-by-id-or-name/index.html | PATCH por ID o nombre; respuestas específicas por operación. |
| R07c | Move IPv4 NAT rule | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/move-nat-rule-ipv-4/index.html | Movimiento de regla NAT como operación dedicada. |
| R08 | Authentication users — list | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-users/index.html | GET /authentication/users; el endpoint se describe como paginado; la navegación diferencia usuarios de red y administradores. |
| R09 | Authentication live users — list | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-live-users/index.html | GET /authentication/live-users; describe array plano de sesiones conectadas. |
| R10 | Disconnect a live user session | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/disconnect-live-user/index.html | POST /authentication/live-users/disconnect; desconecta una sesión mediante liveUserId y message. |
| R11 | IPsec site-to-site connections | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/list-ipsec-connections-ipv-4/index.html | Operaciones de configuración IPsec; complementar con perfiles/failover y live connections desde R02. |
| R11a | IPsec site-to-site live connections | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-ipsec-site-to-site-live-connections-ipv-4/index.html | Estado operativo de conexiones IPsec. |
| R11b | SSL VPN remote access policies | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-remote-access-policies/index.html | Políticas de acceso remoto SSL VPN. |
| R12 | RFC 7396 — JSON Merge Patch | https://www.rfc-editor.org/rfc/rfc7396 | Semántica estándar solo si el endpoint Sophos declara ese formato/media type. PATCH por sí mismo no equivale a Merge Patch. |

### Notas de interpretación de Sophos

- La API es la Configuration REST API del firewall appliance, no la Sophos Central Firewall Management API.
- API access allowlist y Device access/zones son controles distintos; revisar ambos.
- API keys heredan permisos de administrador y expiran al año. La rotación de claves es manual según el flujo documentado.
- Los códigos HTTP varían por operación. R06a/R06b/R07a/R09/R10 ofrecen ejemplos verificables; no construir una tabla universal.
- A diferencia de la regla genérica de HTTP, Sophos documenta para esta Configuration REST API que PATCH usa JSON Merge Patch (RFC 7396) por defecto salvo overrides por operación. Las excepciones y el tratamiento de arrays/oneOf prevalecen; no cambiar el Content-Type sin contrato explícito.
- El listado de usuarios está paginado, mientras que live users se documenta como array plano.
- La lista de features no soportadas en R04 no es exhaustiva; consultar cada endpoint del API Reference.

| R21 | Device access profiles — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Profiles/DeviceAccess/index.html | Los perfiles de administrador definen permisos para gestionar el firewall desde Web Admin Console o API; los permisos None/Read-only/Read-write afectan a la visibilidad y operaciones. |
| R22 | Allow API access to administrators — SFOS 23.0 | https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/APIXmlAPI/HowToArticles/APIAllowAccess/index.html | Describe por separado API access/Allowed IP hosts, perfiles de administrador y Device Access/HTTPS local service ACL; usarlo para comprobar requisitos de red y permisos. |
| R23 | Web admin console access — SFOS 23.0 | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/StartupHelp/ManageSophosFirewall/GettingStartedWebAdminConsole/index.html | Explica que el acceso a Web Admin Console desde otras zonas debe habilitarse en Administration > Device access y el uso del puerto HTTPS administrativo. |
| R24 | Firewall health check — Web Admin Console | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/FirewallHealthCheck/index.html | Describe la función de health/compliance de la interfaz de administración. No demuestra que exista un endpoint equivalente en Configuration REST API; solo el OpenAPI puede justificar una herramienta MCP.

## C. MCP — SDK oficial, protocolo y prácticas

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R13 | openapi-python-client — repositorio | https://github.com/openapi-generators/openapi-python-client | Generador candidato para la prueba de viabilidad, no una elección predeterminada. |
| R13a | openapi-python-client releases | https://github.com/openapi-generators/openapi-python-client/releases | Versiones y cambios; la versión 0.29.1 se publicó el 30 Ago 2026. |
| R13b | GHSA-5293-mq8x-g3xj — code generation RCE | https://github.com/openapi-generators/openapi-python-client/security/advisories/GHSA-5293-mq8x-g3xj | Versiones anteriores a 0.29.1 afectadas por generación arbitraria de código desde documentos OpenAPI maliciosos. |
| R14 | MCP Python SDK releases | https://github.com/modelcontextprotocol/python-sdk/releases | Historial de SDK; v2.3.0 es la última release observada en esta revisión (2 Oct 2026). |
| R15 | MCP Python SDK v2 — What's new | https://py.sdk.modelcontextprotocol.io/v2/whats-new/ | Cambios principales de v2 y protocolo actual. |
| R15a | MCP 2026-07-28 specification release overview | https://blog.modelcontextprotocol.io/posts/2026-07-28/ | Cambio a núcleo stateless, sin initialize/initialized ni sesiones de transporte, server/discover opcional, MRTR y otras modificaciones. |
| R16 | MCP Python SDK — Lifespan | https://py.sdk.modelcontextprotocol.io/v2/handlers/lifespan/ | Un contexto tipado compartido para toda la vida del server; iniciar recursos antes de yield y cerrarlos en finally. |
| R16a | MCP Python SDK — Tools | https://py.sdk.modelcontextprotocol.io/v2/servers/tools/ | Herramientas async, parámetros Pydantic/Annotated/Field, enums, descripciones, títulos y anotaciones. |
| R17 | MCP Python SDK — Structured Output | https://py.sdk.modelcontextprotocol.io/v2/servers/structured-output/ | Inferencia de output schema desde return types; content y structured_content; validación del valor devuelto. |
| R18 | MCP Tool Annotations — risk vocabulary and limits | https://py.sdk.modelcontextprotocol.io/v2/servers/tools/#names-titles-and-annotations | title/readOnly/destructive/idempotent/openWorld son hints, no enforcement ni autorización. |
| R19 | MCP Python SDK — Handling errors | https://py.sdk.modelcontextprotocol.io/servers/handling-errors/ | ToolError para error de ejecución visible al modelo; MCPError para error de protocolo; excepciones inesperadas registradas por SDK. |
| R20 | MCP Inspector — repo/documentación | https://github.com/modelcontextprotocol/inspector | Herramienta oficial de prueba para descubrir herramientas y revisar esquemas/resultados. |

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

1. Registrar en docs/API-COVERAGE.md el SHA exacto del YAML auditado y las versiones openapi/info.version.
2. Guardar evidencia de la versión/build del firmware probado; el portal online no determina la versión del appliance destino.
3. Para cada operación, documentar path, method, request media type, schemas, response codes, error schema, paginación y permisos.
4. No generalizar media types, respuestas, paginación o defaults a partir de otro endpoint.
5. Volver a comprobar las limitaciones publicadas y el API Reference al ampliar dominios.
6. Para SDK MCP, actualizar el pin y revisar migration notes/release notes antes de saltar de minor version.
