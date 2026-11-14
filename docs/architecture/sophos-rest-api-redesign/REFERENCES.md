# Referencias — Sophos Firewall MCP REST API redesign

**Fecha de consulta:** 14 de noviembre de 2026.  
**Criterio:** se priorizan especificaciones oficiales, documentación del fabricante, documentación del SDK MCP, estándares y repositorios originales de las herramientas evaluadas.

Las referencias se identifican como `Rxx` en [PLAN.md](./PLAN.md). Los enlaces de Sophos pueden evolucionar con cada versión de SFOS; antes de implementar debe comprobarse la versión que corresponde al firewall de destino.

## A. Repositorio y especificación objeto del rediseño

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R00 | Repositorio del proyecto | https://github.com/lordraiden/sophos-firewall-mcp | Código, documentación y automatizaciones revisadas. |
| R00a | Especificación OpenAPI añadida al repositorio | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/firewall_config_openapi.yaml | Contrato local que debe auditarse exhaustivamente en la Fase 0. Blob SHA observado: `40fca0b25d4d85866f86b90aec77e5559ae27214`. |
| R00b | Cliente XML actual | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/client.py | Cliente que se propone reemplazar. |
| R00c | Registro MCP actual | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/server.py | Registro de herramientas que se propone rediseñar. |
| R00d | Herramientas de firewall actuales | https://github.com/lordraiden/sophos-firewall-mcp/tree/main/src/sophos_firewall_mcp/tools | Implementación funcional de partida y contratos heredados que deben revisarse. |
| R00e | Dependencias actuales | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/pyproject.toml | Dependencias del proyecto y extras. |
| R00f | Changelog actual | https://github.com/lordraiden/sophos-firewall-mcp/blob/main/CHANGELOG.md | Incidencias y decisiones técnicas históricas citadas en el plan. |

## B. Documentación oficial de Sophos

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R01 | Sophos Firewall API Reference — overview | https://docs.sophos.com/nsg/sophos-firewall/rest-api/index.html | Introducción oficial, API REST, acceso desde endpoints confiables, autorización y autenticación. |
| R02 | Sophos Firewall Configuration API — OpenAPI reference | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/sophos-firewall-configuration-api/index.html | Referencia generada desde OpenAPI 3.0; versión documentada 1.0.0; base URL, autenticación y catálogo de operaciones. |
| R03 | Get started with Sophos Firewall REST API (SFOS 23.0) | https://docs.sophos.com/nsg/Sophos-firewall/23.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/APIRestAPI/index.html | Requisitos previos, activación de REST, uso de API keys y consideraciones de implementación. |
| R04 | REST API access and API keys (SFOS 23.0) | https://docs.sophos.com/nsg/sophos-firewall/23.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/APIRestAPI/APIAccessAndKeys/index.html | API access desactivado por defecto, hosts/IP de confianza, API keys, herencia de permisos, validez de un año y lista de funcionalidades no soportadas. |
| R05 | Firewall rules — IPv4 endpoint reference | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-firewall-rules-ipv-4/index.html | Lectura de reglas y catálogo de operaciones CRUD/movimiento para IPv4 e IPv6. |
| R06 | Firewall NAT rules — IPv4 endpoint reference | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-nat-rules-ipv-4/index.html | Lectura de NAT y catálogo de operaciones CRUD/movimiento IPv4 e IPv6. |
| R07 | Network addresses — IPv4 | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-ip-addresses/index.html | Operaciones de objetos IPv4. |
| R08 | Network addresses — IPv6 | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-ipv-6-addresses/index.html | Operaciones de objetos IPv6. |
| R09 | Network address groups — IPv4 | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-ipv-4-address-groups/index.html | Grupos de direcciones IPv4. |
| R10 | Network addresses — FQDN | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-fqdns/index.html | Objetos FQDN. |
| R11 | Network services | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-services/index.html | Servicios de red. |
| R12 | Network service groups | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-all-service-groups/index.html | Grupos de servicios. |
| R13 | Network interfaces | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/list-network-interfaces/index.html | Interfaces de red. |
| R14 | Authentication live users | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-live-users/index.html | Sesiones de usuarios activas. |
| R15 | IPsec site-to-site connections | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/list-ipsec-connections-ipv-4/index.html | Configuración de conexiones IPsec. |
| R16 | IPsec site-to-site live connections | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-ipsec-site-to-site-live-connections-ipv-4/index.html | Estado de conexiones IPsec activas. |
| R17 | SSL VPN remote access policies | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/get-remote-access-policies/index.html | Políticas SSL VPN de acceso remoto. |

**Nota de cobertura:** la referencia general [R02] contiene además los endpoints de autenticación/usuarios, grupos, otras modalidades VPN y distintas áreas de administración. Las páginas individuales de [R05]–[R17] son ejemplos verificables de familias relevantes, no una lista exhaustiva del alcance REST.

## C. Estándares y documentación MCP

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R18 | RFC 7396 — JSON Merge Patch | https://www.rfc-editor.org/rfc/rfc7396 | Semántica normativa de JSON Merge Patch: propiedades omitidas, null para eliminación y sustitución de arrays. La especificación OpenAPI de Sophos debe confirmar el media type y las excepciones de cada operación PATCH. |
| R20 | MCP Python SDK — Tools | https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/servers/tools.md | Registro de herramientas, inferencia de esquemas, tipos Pydantic, anotaciones de comportamiento y descripciones. |
| R21 | MCP Python SDK — Lifespan | https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/handlers/lifespan.md | Gestión del ciclo de vida y compartición segura de recursos entre handlers. |
| R22 | MCP Python SDK — Structured Output | https://py.sdk.modelcontextprotocol.io/v2/servers/structured-output/ | Output schema, validación de resultados y structured content. |
| R23 | MCP Inspector — documentación | https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tools/inspector.mdx | Herramienta oficial de prueba e inspección de servidores MCP: conexión, herramientas, esquemas, recursos, prompts y resultados. |
| R24 | MCP Python SDK — Handling errors | https://py.sdk.modelcontextprotocol.io/servers/handling-errors/ | Diferencia entre ToolError (error de ejecución visible para el modelo), MCPError (error de protocolo) y excepciones inesperadas. |

## D. Herramientas de generación y contratos OpenAPI

| ID | Recurso | URL | Uso |
|---|---|---|---|
| R19 | openapi-python-client — repositorio | https://github.com/openapi-generators/openapi-python-client | Generador de cliente Python a partir de OpenAPI; candidato para una prueba de viabilidad, no una decisión de adopción. |
| R19a | openapi-python-client — releases | https://github.com/openapi-generators/openapi-python-client/releases | Registro de versiones y cambios; la versión 0.29.1 figura publicada el 30 de agosto de 2026 y documenta una corrección de seguridad en la generación de código. |

## E. Referencias de implementación local

Estas rutas permiten revisar el código concreto que motivó la recomendación de reescritura. No son especificaciones externas:

- Cliente XML: [src/sophos_firewall_mcp/client.py](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/client.py)
- Registro MCP: [src/sophos_firewall_mcp/server.py](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/server.py)
- Guard de excepciones: [src/sophos_firewall_mcp/_guard.py](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/_guard.py)
- Router semántico: [src/sophos_firewall_mcp/router.py](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/src/sophos_firewall_mcp/router.py)
- Herramientas: [src/sophos_firewall_mcp/tools/](https://github.com/lordraiden/sophos-firewall-mcp/tree/main/src/sophos_firewall_mcp/tools)
- Pruebas actuales: [tests/](https://github.com/lordraiden/sophos-firewall-mcp/tree/main/tests)
- Dependencias: [pyproject.toml](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/pyproject.toml), [requirements.txt](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/requirements.txt)
- Contenedor: [Dockerfile](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/Dockerfile), [docker-compose.yml](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/docker-compose.yml)
- Flujos de CI: [GitHub Actions](https://github.com/lordraiden/sophos-firewall-mcp/tree/main/.github/workflows)

## F. Reglas para mantener las referencias

1. La especificación OpenAPI versionada en el repositorio y su SHA son el contrato que debe analizarse en la Fase 0. La documentación web oficial es una referencia de apoyo y puede actualizarse independientemente.
2. No se debe asumir que una operación existe en todos los firmwares: comprobar versión de SFOS, endpoint, perfil del administrador y permisos efectivos.
3. Antes de implementar una operación PATCH, comprobar en el OpenAPI su content type, esquema y comportamiento específico. RFC 7396 solo describe la semántica del formato; no demuestra por sí solo que todos los endpoints Sophos utilicen ese formato.
4. Registrar en `docs/API-COVERAGE.md` la versión y SHA del YAML analizado, las operaciones soportadas, limitaciones y cualquier diferencia entre la especificación del repositorio y la documentación en línea.
5. Verificar los enlaces y las versiones de documentación antes de cerrar la Fase 0.
