# Plan de rediseño: Sophos Firewall MCP — REST API

**Revisión técnica:** 15 de noviembre de 2026  
**Estado:** diseño revisado y auditado de forma independiente; la implementación todavía no está realizada.  
**Repositorio:** [lordraiden/sophos-firewall-mcp](https://github.com/lordraiden/sophos-firewall-mcp)  
**Especificación versionada:** [firewall_config_openapi.yaml](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/firewall_config_openapi.yaml)  
**Blob SHA observado:** `40fca0b25d4d85866f86b90aec77e5559ae27214`  
**SHA-256 del fichero:** `58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5`  
**Tamaño registrado por GitHub:** 8.934.475 bytes.  
**Baseline re-parseado y verificado el 15 de noviembre de 2026:** `openapi: 3.0.0`; `info.title: Sophos Firewall Configuration API`; `info.version: 1.0.0`; 384 paths; 700 operaciones HTTP (GET 263, POST 210, PATCH 134, DELETE 93; sin PUT/HEAD/OPTIONS); 700 `operationId` presentes y sin duplicados; 76 ocurrencias de `$ref`, 32 referencias únicas, todas locales bajo `#/components/schemas`, sin referencias externas ni sin resolver; 32 esquemas de componente y 0 sin usar; 0 ciclos de esquemas. El documento es mayoritariamente de esquemas inline (4.265 esquemas inline, 162.760 nodos; el mayor, el body de `updateFirewallRuleIpv4`, con 1.148 nodos).  
**Servidor declarado en el YAML:** `https://{firewallHost}/api/firewall-config/v1`, con variable `firewallHost` y default `172.16.16.16:4444`.  
**Seguridad global del OpenAPI:** HTTP Bearer (`scheme: bearer`, `bearerFormat: API key`); las 700 operaciones heredan la seguridad global y ninguna la sobrescribe.  
**PATCH en el contrato:** 134 operaciones PATCH; las 134 declaran `application/json` y **ninguna** declara `application/merge-patch+json` (0 ocurrencias en todo el fichero). `info.description` documenta el default JSON Merge Patch (RFC 7396) y cuatro operaciones documentan desviaciones (ver §5).  
**Paginación en el contrato:** 83 operaciones GET aceptan `page`/`pageSize`/`pageTotal` (defaults 1/50/false; `pageSize` máximo 100 solo en `getUsers`, `getAdministrators` y `getNetworkUsers`); no existe `limit`, `offset` ni cursor en el documento.  
**Auditoría independiente:** ver [INDEPENDENT_REVIEW_REPORT.md](./INDEPENDENT_REVIEW_REPORT.md) (15 de noviembre de 2026). Este plan incorpora las correcciones respaldadas por evidencia de esa revisión; las afirmaciones que dependen del firmware o del appliance siguen marcadas como pendientes de verificación.
**Validación en vivo:** smoke test de solo lectura contra el appliance real el 15 de noviembre de 2026; evidencia en [docs/live-evidence/api-smoke-2026-11-15.md](../live-evidence/api-smoke-2026-11-15.md).
**Acceso al laboratorio:** endpoint, API key de solo lectura y variables de entorno en [LAB-ACCESS.md](./LAB-ACCESS.md).
**Ejecución (fase 1):** decisión de cliente REST en [ADR-001-rest-client-strategy.md](../ADR-001-rest-client-strategy.md) e inventario por operación en [API-COVERAGE.md](../../API-COVERAGE.md).

> La documentación oficial online también muestra OpenAPI 3.0 y versión 1.0.0, y reproduce literalmente en su Introduction el texto de `info.description` de este YAML (base URL, Bearer, formatos de nombre y semántica PATCH). Aun así, el contrato que se implementa es el fichero versionado y la versión de SFOS objetivo; la página online puede actualizarse por separado.

> Este documento sustituye las decisiones anteriores que dependían de supuestos no verificados. La fuente contractual para implementar es el YAML versionado y la versión de SFOS objetivo; la documentación online oficial sirve para contrastar alcance y comportamiento. Consultar [REFERENCES.md](./REFERENCES.md) para las fuentes, versiones y advertencias.

# 1. Decisión técnica

**Reconstruir la implementación funcional sobre la API REST de Sophos, sin compatibilidad XML.** Conservar el repositorio y los elementos operativos que sigan siendo válidos, pero no adaptar el cliente XML para que soporte dos protocolos.

No se debe empezar un repositorio nuevo. Se conserva lordraiden/sophos-firewall-mcp, su identidad, historial, licencia, issues, automatizaciones y estructura de distribución.

## Reutilizar, después de revisar

- Repositorio, licencia, metadatos y procesos de release.
- Docker, GHCR y GitHub Actions, después de alinearlos con el nuevo runtime.
- Experiencia y casos de prueba derivados de fallos reales.
- Las necesidades funcionales que siguen teniendo sentido.
- La organización modular por dominios cuando resulte adecuada.

## Reescribir

- Transporte y cliente Sophos.
- Configuración, autenticación y manejo de secretos.
- Modelos de API y modelos de entrada/salida MCP.
- Herramientas de todos los dominios.
- Registro del servidor y ciclo de vida.
- Errores, paginación y tratamiento de operaciones ambiguas.
- Recursos y prompts, únicamente si aportan valor real sobre REST.

## Eliminar

- Cliente XML, construcción/parsing XML y xmltodict.
- Usuario, contraseña XML y variable SOPHOS_API_VERSION.
- Lógica de estado XML y sanitización específica del árbol XML.
- sophos_raw_api_request y cualquier sustituto que permita ejecutar URLs/rutas arbitrarias.
- Fixtures y pruebas exclusivamente XML.
- Router semántico FastEmbed en la primera versión REST.
- Cualquier mecanismo de compatibilidad con la API XML.

No mantener capas, abstracciones o dependencias solo por continuidad histórica.

## Estado real del repositorio en la revisión (15 de noviembre de 2026)

La migración parte de una implementación todavía XML y de una infraestructura que tiene inconsistencias que deben tratarse como trabajo explícito, no como detalles de empaquetado:

- `pyproject.toml` declara actualmente `mcp[cli]>=2.0.0,<3.0.0`, mientras que el baseline MCP de este plan es `mcp>=2.3.0,<3` sin el extra CLI en runtime. También incluye `xmltodict` y el extra opcional `router` (FastEmbed/numpy), que deben desaparecer de la distribución REST.
- `requirements.txt` declara `mcp[cli]>=1.2.0,<2.0.0`, incompatible con el runtime actual `MCPServer` y desalineado con `pyproject.toml`. Existe `uv.lock`; debe convertirse en el lock canónico, regenerarse con el nuevo contrato y usarse con resolución bloqueada en CI/build. Eliminar los requirements duplicados o generarlos de forma verificable desde esa resolución; retirar también tipos/fixtures de XML en `requirements-dev.txt`.
- `src/sophos_firewall_mcp/client.py` sigue siendo cliente XML (`/webconsole/APIController`, usuario/contraseña, APIVersion, `xmltodict`). `server.py` ya usa `MCPServer` de SDK v2, pero registra herramientas globalmente, importa el raw API tool, prompts/resources y el router FastEmbed; no tiene lifespan que comparta un REST client.
- `_guard.py` captura `BaseException` y convierte errores inesperados en `SophosAPIError` tras una lista de excepciones passthrough. No trasladar este wrapper al diseño nuevo: usar errores de dominio tipados y `ToolError` para fallos previstos; dejar excepciones inesperadas bajo el manejo/logging del SDK y propagar cancelación/shutdown sin envolverlas.
- `Dockerfile` instala `.[router]` y descarga el modelo FastEmbed durante el build. `docker-compose.yml` todavía entrega credenciales XML, desactiva TLS por defecto y activa `tty: true`; `.env.example` y README también documentan XML, FastEmbed y el flujo de autenticación antiguo. Deben migrarse como una misma unidad y mantener STDIO sin TTY.
- CI ejecuta tests para Python 3.11/3.12/3.13 y lint/type-check con Python 3.12. `.github/workflows/security.yml` ejecuta `pip-audit -r requirements.txt`, que hoy audita la línea MCP 1.x y no el conjunto de dependencias que instala el paquete desde `pyproject.toml`/lock. Corregirlo para auditar el lock de runtime usado por el build.
- `.github/workflows/docker-publish.yml` publica actualmente tanto en pushes a `main` como en tags `v*`, y asigna `latest` a pushes de `main`. Esto contradice la política de no promover una release de producción sin aprobación: los pushes a main deben producir, como mucho, tags de desarrollo (por ejemplo `main`/SHA); `latest` y tags estables deben reservarse a una promoción de release explícita y revisada.

El alcance de esta revisión es corregir el plan y las issues; estos archivos de implementación no se han modificado como parte de la actualización documental.

# 2. Qué API estamos implementando y qué exige Sophos

El objetivo es la **Sophos Firewall Configuration REST API del propio appliance**, no la Sophos Central Firewall Management API ni un API de inventario/gestión centralizada.

La API de configuración del appliance utiliza:

- Base URL: `https://<firewall-hostname>:<admin-https-port>/api/firewall-config/v1`. El YAML versionado declara como valor de ejemplo/default de la variable de servidor `172.16.16.16:4444`; 4444 coincide con el puerto HTTPS predeterminado del Web Admin Console en SFOS 23, pero el puerto real se debe poder configurar.
- Autenticación por API Key en Authorization: Bearer <api-key>.
- JSON y operaciones HTTP descritas por OpenAPI 3.0.
- Acceso desde dispositivos/IP hosts permitidos por el propio firewall.

No añadir un API_VERSION configurable: v1 forma parte de la ruta base. Tampoco asumir un puerto universal; debe configurarse el puerto HTTPS del Web Admin Console del appliance. [R01] [R02]

## Prerrequisitos de seguridad del appliance

Para habilitar la API no basta con disponer de una API Key:

1. Activar REST API access en Administration → API access.
2. Añadir la IP, rango o red de origen a Allowed IP hosts.
3. Comprobar Administration → Device access: habilitar el servicio HTTPS (Web Admin Console) para la zona de origen del administrador. Sophos no recomienda habilitar la consola administrativa en interfaces WAN. Si un administrador debe acceder desde WAN, el único mecanismo documentado es una **regla de excepción de Local service ACL** que autorice IPs de origen concretas; no se admite `Any` ni `0.0.0.0` como origen. Esa regla forma parte de la propia página Administration → Device access y actúa como excepción por host sobre el ACL por zona: no es un control independiente ni un sustituto de Device access, sino el mecanismo previsto para restringir el acceso desde zonas donde el servicio no se habilita para todos. Allowed IP hosts (API access) sigue siendo un control separado y ambos son necesarios. [R04] [R22] [R33]
4. Crear un administrador dedicado con un perfil de permisos mínimos por funcionalidad.
5. Generar una API Key exclusiva para esa automatización/servidor.

Las API Keys heredan los permisos del perfil de administrador que las genera. Los perfiles permiten `None`, `Read-only` y `Read-write` por configuración/función, de modo que el mínimo privilegio debe definirse en el perfil, no solo creando una cuenta separada. Sophos documenta un máximo de 10 claves por administrador y 1.024 por appliance; la allowlist admite hasta 64 entradas. Las claves caducan al año y el secreto solo se muestra al generarlo. Todos los administradores pueden ver la lista de claves; cada administrador puede crear/eliminar las propias y el administrador predeterminado puede eliminar las claves de cualquier administrador. No compartir claves entre administradores/automatizaciones. La rotación/revocación es una tarea administrativa manual; no asumir un endpoint de renovación. [R03] [R04] [R21] [R22] [R27]

## Firmware y limitaciones

La referencia de API online no declara una versión de SFOS: muestra "Version: 1.0.0" (versión del contrato OpenAPI) y se describe como "every endpoint on the current firmware". La vinculación con SFOS 23.0 proviene de la ayuda 23.0 y de las release notes, que sitúan la REST API en SFOS 23.0 GA Build 371 (4 de noviembre de 2026). Esto **no demuestra** que el firewall destino del proyecto esté ejecutando esa versión ni que todas las operaciones se comporten igual en cualquier build. Sophos tampoco afirma que el `OpenAPI.yaml` descargable del appliance sea idéntico al portal online; la cautela de contrastarlo es una inferencia razonable, no una advertencia documentada. [R05]

Sophos publica una lista de funcionalidades no soportadas (entre ellas firewall rule groups, varias modalidades VPN, RED, wireless y determinadas funciones de estado), pero advierte que la lista no es exhaustiva. Además es internamente inconsistente con el catálogo: declara "Wireless: All wireless features" pese a que existen endpoints de hotspot, y "Status information: DHCP lease information" pese a que existen endpoints de leases DHCP. Sophos tampoco define el alcance exacto de "IPsec routes" en esa tabla; el término parece referirse a rutas/VPN routes y al comando `ipsec_route`, no a las conexiones route-based (XFRM/VTI), que sí tienen CRUD IPv4. Para cada capacidad hay que consultar el endpoint en el API Reference y verificarlo en el firmware objetivo; la lista sirve como señal de riesgo, no como sustituto del contrato. [R04]

# 3. Arquitectura recomendada

El MCP es una capa especializada de administración de Sophos. No debe ser un proxy HTTP genérico ni una traducción mecánica de cada path de OpenAPI.

~~~text
MCP Server (MCP Python SDK v2)
  |
  +-- Tool contracts
  |     +-- Input schemas
  |     +-- Output schemas
  |     +-- Annotations and descriptions
  |
  +-- Domain operations
  |     +-- Firewall rules
  |     +-- NAT rules
  |     +-- Network addresses and services
  |     +-- Network users and live sessions
  |     +-- VPN, interfaces and selected health data
  |
  +-- Sophos REST client
        +-- Fixed appliance API base URL
        +-- Bearer API key
        +-- TLS and timeout policy
        +-- JSON serialization
        +-- Operation-specific status/error mapping
        +-- Bounded read retry policy
        +-- No blind retry of ambiguous writes
        |
        +-- Sophos Firewall Configuration REST API v1
~~~

Mantener separadas tres responsabilidades sin crear capas vacías:

- **MCP handlers:** convierten la intención del modelo en una operación de dominio segura.
- **Domain/API adapter:** conoce los recursos, referencias y operaciones tipadas de Sophos.
- **REST transport:** HTTP, autenticación, serialización, timeouts y errores de transporte.

Los handlers no deben construir URLs, headers ni payloads HTTP directamente. El cliente de transporte no debe conocer nombres de herramientas MCP.

# 4. Alcance funcional: mapear primero, implementar solo lo justificado

> **Nota (15 de noviembre de 2026):** el alcance v1 de la tabla siguiente fue ampliado por decisión del propietario (MAC con CRUD completo, country groups en lectura, escrituras de interfaz solo para VLAN, dominio de arquitectura de red, herramientas de auditoría #35 y enable/disable + clone en reglas de firewall). El alcance vigente está en [ADR-001 §10](../ADR-001-rest-client-strategy.md) y en [API-COVERAGE.md](../../API-COVERAGE.md) §4; esta tabla se conserva como decisión inicial y queda superada por las issues #24, #27, #29, #31 y #35.

La referencia OpenAPI incluye muchos más módulos que las herramientas XML originales. La primera versión no tiene que exponer todo el catálogo. La Fase 0 debe inventariarlo por completo y seleccionar un alcance inicial coherente con las funciones actuales y las necesidades reales de administración.

| Dominio | Cobertura a investigar | Decisión inicial |
|---|---|---|
| Firewall rules | IPv4/IPv6, list/get/create/update/delete/move y bulk delete | Implementar operaciones individuales; no exponer bulk delete inicialmente |
| NAT rules | IPv4/IPv6, list/get/create/update/delete/move y bulk delete | Operaciones individuales; bulk delete fuera del alcance inicial |
| Network addresses | IPv4, IPv6, FQDN y otros tipos que aparezcan en el spec (por ejemplo MAC) | Priorizar IPv4/IPv6/FQDN; los demás se clasifican en cobertura |
| Address groups | Grupos por familia/tipo, incluyendo FQDN, IPv4, IPv6 y country según endpoints | No asumir grupos mixtos; seguir cada esquema |
| Network services | Servicios y grupos | Implementar esquemas/endpoints reales, no reutilizar modelos XML |
| Authentication users | Lista general paginada y recursos de usuarios de red | Separar listado general de CRUD de usuarios de red |
| Administrators | GET/POST/PATCH/DELETE y bulk delete presentes en el catálogo | Documentar; excluir CRUD y cambios de privilegios en la primera versión por su impacto |
| Authentication user groups | GET/POST/PATCH/DELETE, bulk delete y set-fallback-group | Clasificar y documentar; no incluir gestión de grupos ni fallback en la primera versión salvo requisito explícito |
| Live sessions | Listado de sesiones activas y desconexión de una sesión | Implementar lectura y desconexión individual; la respuesta contiene `items` y `pages` (`current`, `size`, `maxSize`), pero el GET no define parámetros page/pageSize, por lo que no se debe inventar paginación de petición |
| VPN | IPsec profiles, failover groups, site-to-site y live state; SSL VPN remote access y otros recursos documentados | Seleccionar operaciones compatibles; documentar explícitamente exclusiones |
| Network interfaces | `/network/interfaces/network-interfaces`: GET/POST/GET-by-ID/PATCH/DELETE | OpenAPI define CRUD, pero el primer release MCP empieza en lectura; posponer create/update/delete por riesgo de perder conectividad |
| Read-only network status | `GET /network/dns/protection/status` y `GET /network/cellular-wan/modem-status` | Candidatos read-only concretos; no inferir un endpoint REST para la pantalla Firewall Health Check del Web Admin UI |

## Firewall rules

La API expone operaciones IPv4 e IPv6 diferenciadas. La documentación de referencia incluye GET, POST, PATCH, DELETE, movimiento y endpoints de bulk delete. Los grupos de reglas de firewall figuran como no soportados en la documentación de SFOS 23.0. [R06] [R04]

Para la primera versión:

- Implementar las operaciones individuales que estén presentes en el YAML y verificadas.
- Tratar el movimiento/orden como una operación independiente si así lo define OpenAPI.
- Clasificar bulk delete en la matriz, pero no exponerlo inicialmente: su radio de impacto es elevado y no es necesario para recuperar CRUD individual.
- No implementar firewall rule groups por la mera existencia de grupos de otros objetos.
- No activar automáticamente una regla recién creada. La nota de release de SFOS 23.0 sobre reglas deshabilitadas y colocadas al final se refiere expresamente al Firewall AI Assistant en Sophos Fusion; no debe extrapolarse como comportamiento de POST REST sin comprobar su esquema y el firewall. La herramienta debe requerir/representar el estado de forma explícita y devolver el estado realmente aplicado. [R05]

## NAT rules

La API documenta recursos IPv4 e IPv6, operaciones individuales y movimiento. No convertir una regla NAT en una variante de firewall rule ni asumir que ambos dominios comparten todos los campos. Excluir bulk delete inicialmente y documentar la cobertura exacta. [R07]

## Network Objects y Services

La API separa recursos de direcciones y grupos por familias/tipos. No mantener un objeto genérico IPHost que acepte una mezcla de esquemas no equivalentes.

- Modelar cada tipo soportado mediante esquemas Pydantic separados o modelos discriminados cuando las propiedades difieran.
- No asumir que IPv4, IPv6, FQDN, MAC y country groups comparten pertenencia o referencias.
- Distinguir IDs/UUIDs, nombres visibles y campos de referencia. Usar exactamente el formato que cada operación espera.
- Identificar objetos built-in/read-only y conflictos por dependencias antes de ofrecer delete.
- Mantener Network Services y Service Groups como dominios tipados; no asumir que un servicio individual y un grupo comparten payload.

## Users y Live Sessions

El YAML distingue:

- `GET /authentication/users` (`getUsers`): listado resumido paginado, con `page` (default 1), `pageSize` (default 50, máximo 100), `pageTotal` (default false) y los filtros mutuamente excluyentes `nameContains` / `nameNotEquals` (1–255 caracteres).
- `GET /authentication/users/network-users` (`getNetworkUsers`): listado de usuarios de red paginado con los mismos parámetros, límites y filtros.
- CRUD individual de network users; login/logout son operaciones independientes y con efectos operativos.
- CRUD de administradores y de user groups también aparecen en OpenAPI, pero quedan excluidos del primer release por privilegio/alcance.
- `GET /authentication/live-users` (`getLiveUsers`): el YAML no declara query parameters de página. Su respuesta es un objeto con `items` (array de sesiones) y `pages` (`current`, `size`, `maxSize`); no contiene `total` ni `items` dentro de `pages` en el contrato. **Evidencia en vivo (15 nov 2026):** el appliance sí acepta `page`, `pageSize` y `pageTotal` en este endpoint (`page=2` → `current:2`; `pageSize=10` → `size:10`; `pageTotal=true` añade `items`/`total`; `pageSize=101` → 400), y `maxSize` real es **100** (no 1000). Decisión: el MCP no expone esos parámetros en v1 porque no están en el contrato; se documenta la observación y #24/#30 deciden con ella. No describirlo como una lista desnuda.
- `POST /authentication/live-users/disconnect` desconecta una sesión mediante `liveUserId` y `message`; ambos campos son obligatorios en el contrato (`liveUserId` entero ≥ 1; `message` 1–600 caracteres). Respuestas documentadas: 200, 400, 401, 403 y 500.

El MCP debe preservar exactamente la metadata `pages` del live-users endpoint. Como no se define una petición de continuación, no debe inventar un cursor/page loop. La Fase 0 debe comprobar en firmware cómo se comporta cerca de `maxSize` y documentar cualquier límite de completitud. [R08] [R09] [R10]

La primera versión debe:

- Separar network users, administrator accounts y live sessions en modelos y nombres de herramientas.
- Implementar paginación solo en los endpoints que la documentan.
- Implementar desconexión individual solo con el endpoint oficial, identificador correcto y anotación destructiva.
- Excluir create/update/delete de administradores y cambios de privilegios.
- Tratar password y credenciales como write-only/sensitive; nunca devolverlas ni incluirlas en logs.

## VPN, interfaces y salud

No ofrecer “VPN management” genérico. El YAML incluye perfiles IPsec y failover groups; conexiones IPsec site-to-site policy-based y route-based para IPv4; estado live de conexiones IPv4; ajustes de remote-access IPsec; políticas SSL VPN de acceso remoto; políticas clientless, bookmark groups/bookmarks y SSL VPN global settings. No asumir que todas las modalidades tienen CRUD completo ni que IPsec site-to-site IPv6 está disponible: el inventario actual contiene operaciones de conexión IPv4. La lista oficial de funciones no soportadas (por ejemplo IPsec routes, GRE, L2TP, PPTP y SSL VPN site-to-site client/server) se debe interpretar según la feature exacta, sin confundir el término 'IPsec routes' con los endpoints 'route-based connection'. [R04] [R11]

El YAML contiene CRUD para `/network/interfaces/network-interfaces` (list, create, get, patch, delete), pero el primer release MCP empieza con list/get por el impacto que una mutación puede tener sobre la conectividad de administración. La advertencia de conectividad no está en el API Reference: procede de la ayuda de administración, que indica que, tras actualizar o eliminar interfaces, las conexiones de red pueden quedar temporalmente inaccesibles. Las operaciones de escritura deben permanecer documentadas como diferidas hasta que exista una prueba segura en el firewall de laboratorio. [R34] **Actualizado (15 nov 2026):** el alcance v1 vigente permite create/update/delete **solo para interfaces `type: vlan`**, con lectura previa del tipo mediante `getNetworkInterface`; physical, bridge, LAG y XFRM siguen en solo lectura (ADR-001 §10).

Para estado read-only de red hay dos endpoints concretos en el YAML: `GET /network/dns/protection/status` (`getDnsProtectionStatus`) y `GET /network/cellular-wan/modem-status` (`getCellularWanStatus`). Son estados específicos de DNS Protection y del módem WAN celular, no un health score general del firewall. La función Firewall Health Check del Web Admin UI es una comprobación de cumplimiento de políticas (CIS y configuraciones recomendadas, con estados compliant/noncompliant y override manual), no un estado de salud general ni un endpoint REST del OpenAPI actual. No crear una herramienta Firewall Health Check. Tampoco prometer modelo, número de serie, firmware o uptime si no existe una operación que devuelva esos datos: `GET /administration/system-settings` solo devuelve `hostname`, `loginDisclaimer` y `updatedAt`. [R24]

# 5. OpenAPI como contrato de implementación

El YAML versionado en el repositorio es el contrato que hay que auditar. La página del API Reference de Sophos es una proyección oficial de OpenAPI 3.0, pero no sustituye la inspección del fichero exacto ni confirma la versión de SFOS del usuario. [R01] [R02]

## Nombres e identificadores de objetos Sophos

La referencia oficial describe formatos comunes que deben respetarse cuando el endpoint los use: [R02]

- `sfos-object-name`: nombre UTF-8 válido, sin comas, punto y coma, caracteres no imprimibles, espacios iniciales/finales y que no sea un UUID.
- `sfos-object-name-or-id`: nombre anterior o UUID.
- `sfos-object-name-lenient`: variante que permite comas y punto y coma para ciertos objetos preexistentes/built-in/localizados.
- `sfos-object-name-lenient-or-id`: variante lenient o UUID.

La regla general de Sophos indica que POST suele identificar objetos mediante nombre único, mientras que GET/PATCH/DELETE pueden usar nombre único o UUID. No convertir esa regla general en una suposición para cada endpoint: el path parameter y su schema concretos siguen siendo la autoridad. Las herramientas MCP deben reflejar el formato correcto por operación y evitar tratar display name, ID y referencia de objeto como intercambiables.

En el contrato versionado, ningún path parameter es solo-nombre: 260 operaciones usan `sfos-object-name-or-id` (248) o `sfos-object-name-lenient-or-id` (12), 6 usan UUID exclusivamente (los DHCP relays) y 17 tienen el parámetro sin tipar (`{name}`/`{idOrName}`/`{floodAttackType}`). El nombre único aparece en los cuerpos (806 esquemas `sfos-object-name`), no en las rutas.

Los formatos `sfos-object-name*` son anotaciones `format` no asertivas y con patrones desiguales: de los 806 esquemas `sfos-object-name`, 718 no llevan `pattern`, 22 usan `^[^,]*$` (solo excluyen comas) y solo 5 llevan la regex completa; en total, 994 de 1.085 esquemas con formato `sfos-object-name*` no llevan `pattern`. La validación documentada (UTF-8, sin comas/punto y coma, sin caracteres no imprimibles, sin espacios extremos, nunca UUID) debe implementarla el cliente MCP; no se puede delegar en el `pattern` del YAML.

La Fase 0 debe registrar:

- Blob SHA, tamaño, openapi, info.title, info.version, servers/base URL, tags y security schemes.
- Diferencias entre el YAML local, la versión mostrada por Sophos online y la especificación descargable desde el appliance/Administration → API access.
- Cada path y método con operationId, parámetros, media type, request schema, response schema, códigos de respuesta y referencias.
- $ref, allOf, oneOf, anyOf, enums, defaults, required/readOnly/writeOnly, nullable, arrays, límites y formatos.
- Operaciones paginadas, filtros, ordenación/move, bulk operations y efectos colaterales.
- Operaciones presentes en OpenAPI pero no disponibles por permisos o firmware.
- Correspondencia de cada operación REST con una herramienta MCP, o razón explícita para excluirla.

## PATCH: default oficial de Sophos y excepciones por operación

HTTP PATCH no implica JSON Merge Patch por definición general de HTTP. Sin embargo, la referencia oficial Sophos para su **Firewall Configuration REST API** establece una regla propia: las peticiones PATCH siguen por defecto la semántica JSON Merge Patch de RFC 7396, salvo que la documentación de una operación indique expresamente otro comportamiento. [R02] [R12]

Esa regla no depende del portal online: el propio `info.description` del YAML versionado la reproduce literalmente, junto con la base URL, el esquema Bearer y los formatos de nombre. #24 debe citar el SHA del fichero como evidencia, no solo la página web.

En el contrato versionado, las 134 operaciones PATCH declaran `application/json` y ninguna declara `application/merge-patch+json`; no existe ningún PUT. Cuatro operaciones documentan desviaciones de la semántica de arrays: `patchMessages` (`/administration/messages`, actualización por catálogo claveada por `name`, no reemplazo completo del array), `updateCentralFirewallReportingLogComponents` y `updateSyslogServerLogs` (merge por `name`) y `updateAlertNotificationSettings` (`/notification/notifications`: los booleanos raíz siguen RFC 7396, pero `notifications[]` se actualiza por `name`). Son ejemplos concretos que la matriz de #24 debe registrar; ninguna está en el primer release MCP, pero demuestran que la excepción existe y que el contrato la documenta.

Por tanto:

- Implementar JSON Merge Patch como default para PATCH de esta API, siempre que no exista una excepción documentada.
- Inspeccionar el OpenAPI local y la página de cada operación para localizar overrides y el request schema/media type. No cambiar el Content-Type a `application/merge-patch+json` salvo que el contrato de esa operación lo indique; la semántica de merge y el media type HTTP no deben confundirse.
- Las propiedades omitidas conservan el valor persistido y `null` elimina una propiedad según la regla general.
- No asumir que todos los arrays se tratan igual: la referencia advierte que algunas operaciones los sustituyen como conjunto o usan listas explícitas de `add`/`remove`.
- Si un campo pertenece a una rama `oneOf`/mutuamente excluyente, Sophos indica que enviar la nueva rama puede ser suficiente para cambiarla; no enviar `null` para la anterior salvo que la operación lo requiera.
- Registrar cada excepción en `docs/API-COVERAGE.md` y probar el comportamiento correspondiente.

Nunca inferir Merge Patch desde el verbo en otra API ni sustituir la regla específica de Sophos por una interpretación HTTP genérica. [R02] [R12]

## Respuestas y errores por operación

No crear un mapa universal de códigos HTTP que se aplique a todos los endpoints. Sophos documenta códigos distintos según operación. Ejemplos de la referencia actual:

- GET de reglas IPv4: 200, 400, 401, 403, 500.
- POST de creación de regla IPv4: 201, 400, 401, 403, 409, 500.
- PATCH de actualización: 200, 400, 401, 403, 404, 409, 500.
- POST para desconectar una live session: 200, 400, 401, 403, 500.

Los ejemplos no son una lista global: el cliente y las pruebas deben seguir las respuestas de cada operación del YAML. Los estados no documentados deben tratarse de forma segura como inesperados, no inventar envelopes o significados. [R06a] [R06b] [R07a] [R10]

## Paginación: tampoco inferir por el nombre

La matriz debe documentar parámetros de petición y metadata de respuesta por operación. En el YAML local, 83 operaciones GET (todas las colecciones del primer release) aceptan `page` (1-indexed, default 1), `pageSize` (default 50; máximo 100 solo en `getUsers`, `getAdministrators` y `getNetworkUsers`, sin máximo declarado en el resto) y `pageTotal` (default false); no existe `limit`, `offset` ni cursor en el documento. `/authentication/users` y `/authentication/users/network-users` añaden los filtros mutuamente excluyentes `nameContains` / `nameNotEquals`. `/authentication/live-users` no define query params de página: responde con `items` más `pages.current`, `pages.size` y `pages.maxSize`, sin `total` ni `items` dentro de `pages`, ni mecanismo de continuación en la petición. No aplicar un helper de paginación genérico a este endpoint; preservar la metadata y validar en el appliance si el límite máximo puede truncar la lista. [R08] [R09]

Las páginas de operación del portal no renderizan estáticamente los parámetros de petición; los defaults y límites anteriores se verificaron en el contrato OpenAPI del vendor, que es la fuente de verdad para el cliente. [R02]

**Evidencia en vivo (15 nov 2026):** `pageTotal=true` añade `pages.total` y `pages.items`; `pageSize > 100` devuelve 400 `invalidPageSizeParam` en todos los listados probados, incluso donde el contrato no declara máximo; `page=0` se acepta con 200 y `current:0` aunque el contrato exige `minimum: 1`, así que el cliente debe validar `page >= 1` antes de enviar.

# 6. Cliente REST y configuración

Una única abstracción de cliente asíncrono, reutilizable y testeable, debe encapsular HTTP. No exponerla como herramienta MCP.

Configuración recomendada:

| Variable | Propósito |
|---|---|
| SOPHOS_HOST | IP/DNS del appliance |
| SOPHOS_PORT | Puerto HTTPS actual del Web Admin Console |
| SOPHOS_API_KEY / SOPHOS_API_KEY_FILE | API Key del administrador dedicado; usar una única fuente, variable o fichero secreto montado |
| SOPHOS_VERIFY_SSL | Verificación TLS; segura por defecto |
| SOPHOS_CA_BUNDLE | CA privada opcional |
| SOPHOS_TIMEOUT | Timeout configurable |
| SOPHOS_READ_ONLY_MODE | Opcional; cuando true, no registrar herramientas de mutación |

No definir SOPHOS_USERNAME, SOPHOS_PASSWORD ni SOPHOS_API_VERSION. Usar 4444 como default inicial porque aparece en la variable `servers.firewallHost` del YAML (172.16.16.16:4444) y coincide con el puerto admin HTTPS predeterminado de SFOS 23; permitir override obligatorio para instalaciones que hayan cambiado el puerto. No sustituir el puerto por un default codificado cuando el usuario ya lo configura.

Requisitos:

- Construir internamente el base URL fijo https://host:port/api/firewall-config/v1.
- Enviar la API Key como Bearer token únicamente por HTTPS.
- TLS verification habilitada por defecto; CA bundle opcional para certificados privados. Desactivar TLS solo como override explícito para laboratorio, nunca como ejemplo recomendado.
- No seguir redirects a otros hosts ni permitir que parámetros del modelo modifiquen host/base URL/path.
- Definir explícitamente si se respetan proxies de entorno; nunca enviar la credencial a un proxy inesperado.
- No registrar headers, API Key, payloads completos ni valores sensibles. Redactar antes de registrar errores del cliente HTTP.
- Un solo pool HTTP compartido por el servidor y cerrado limpiamente en shutdown.
- Paginación y retries por operación, nunca como supuesto global.
- No reintentar automáticamente una escritura cuyo resultado sea ambiguo por timeout/desconexión. Consultar estado antes de decidir repetir.

## Generación de modelos/cliente

Issue #24 compara cliente generado y cliente HTTPX manual con modelos tipados. Mantener una decisión ADR explícita.

Si se usa openapi-python-client, usar al menos 0.30.0. La 0.29.1 corrigió GHSA-5293-mq8x-g3xj (generación arbitraria de código al procesar OpenAPI malicioso), pero la 0.29.0–0.29.x está afectada por GHSA-jg6c-wvfg-fx69 (inyección de campos multipart en clientes generados que aceptan entrada no confiable, publicado el 7 de noviembre de 2026 y corregido en 0.30.0). Ejecutar generación en entorno aislado, tratar el YAML como entrada de confianza limitada y revisar el código generado. No introducir un SDK generado enorme en producción sin justificarlo. [R13] [R13a] [R13b] [R13c]

No duplicar dos catálogos de schemas sin una prueba de drift. El diseño final puede ser cliente generado detrás de un adapter fino, modelos generados/derivados con transporte propio o HTTPX+Pydantic; debe decidirse por evidencia del POC, no por preferencia previa.

# 7. Arquitectura MCP y prácticas recomendadas

El proyecto actual usa mcp>=2. La línea estable del SDK Python es v2; a 15 de noviembre de 2026 la última release estable publicada es v2.3.0 (2 de octubre de 2026; PyPI y GitHub coinciden, sin parche posterior). Esta release implementa la revisión de protocolo MCP 2026-07-28 y el SDK sirve también las revisiones anteriores mediante handshake (2024-11-05, 2025-03-26, 2025-06-18 y 2025-11-25). La dependencia runtime debe ser `mcp>=2.3.0,<3`; instalar el extra `[cli]` solo en un entorno de desarrollo si se utilizan sus comandos, no en la imagen de producción por defecto. Fijar la resolución exacta en el lockfile. El SDK 2.3.0 declara `Requires-Python >=3.10` en PyPI y en su `pyproject.toml` (classifiers 3.10–3.14), aunque su página de instalación aún dice "Python 3.11+"; la matriz de CI del proyecto debe fijarse a 3.11–3.14 y dejar constancia de la discrepancia. [R14] [R15]

## Transporte inicial

- Mantener stdio como transporte soportado para la integración local/CLI del proyecto.
- En stdio local, la frontera de confianza es el proceso/usuario del sistema operativo que lanza el servidor. No añadir OAuth ni un sistema de identidad MCP que no resuelve un requisito de este despliegue; la API Key de Sophos autentica al servidor frente al appliance, no al host MCP.
- No añadir Streamable HTTP ni un listener de red sin un requisito real de despliegue remoto. Si se aprueba posteriormente, esa será una superficie de seguridad distinta: exigir autenticación/autorización del transporte MCP y revisar el modelo OAuth vigente; no reutilizar la API Key de Sophos como credencial de cliente MCP.
- En Docker, mantener el canal stdio limpio; no activar TTY.
- No implementar manualmente un handshake MCP. En la revisión 2026-07-28 se retiraron el handshake `initialize`/`notifications/initialized` y las sesiones de protocolo (incluida la cabecera `Mcp-Session-Id` en Streamable HTTP); cada petición lleva versión, capacidades e identidad en `_meta`, y los servidores **MUST** implementar `server/discover`. Los clientes anteriores a 2026-07-28 siguen usando `initialize` y sesiones: el SDK v2 atiende ambas eras con el mismo servidor y su `Client` negocia automáticamente (`mode="auto"` por defecto). Las pruebas deben usar el `Client` del SDK y verificar por defecto 2026-07-28; una prueba con `mode="legacy"` es válida si el proyecto declara soporte para clientes heredados. [R15] [R15a]
- Crear el servidor con `subscriptions=False` mientras la lista de herramientas y recursos sea estática durante la vida del proceso (incluido `SOPHOS_READ_ONLY_MODE`, aplicado al inicio). El valor por defecto del SDK 2.3.0 es una `InMemorySubscriptionBus` que anuncia `subscriptions/listen`; `False` no registra el handler y deja de anunciar `listChanged`/`subscribe`. El efecto es visible para clientes 2026-07-28; los clientes anteriores no ven diferencia. Habilitarlo únicamente si se implementan notificaciones/catálogos dinámicos reales y se añaden pruebas de ese comportamiento. [R14] [R35]

## Lifespan y Context

Utilizar el lifespan oficial del SDK:

1. Validar configuración al iniciar.
2. Crear una instancia compartida del cliente REST.
3. Exponer un objeto AppContext tipado a los handlers.
4. Cerrar el cliente HTTP en el bloque de salida/finally.

Los handlers reciben `Context[AppContext]` y acceden al objeto de lifespan mediante `ctx.request_context.lifespan_context`, tal como documenta el SDK. `Context` lo inyecta el runtime y no forma parte del input schema. Con la versión v2.3.0 revisada, el Context tipado también funciona en prompts y resource templates si se conservan; no rebajar el tipo a `Any` ni asumir que una función auxiliar recibe Context ambientalmente. No usar `client: Any = None` como parámetro visible ni crear un pool HTTP por llamada. [R16] [R14]

## Herramientas e input schemas

- Usar async def para handlers que realizan I/O.
- Usar tipos Python, Pydantic, Annotated, Field, Literal/Enum y modelos de entrada cuando aporten claridad.
- Exponer operaciones de negocio delimitadas, no una herramienta genérica de REST.
- Nombres/títulos/descripciones claros. Cada descripción debe explicar cuándo usar la herramienta, efecto/side effect, identificadores requeridos y limitaciones relevantes.
- No publicar como parámetros argumentos internos como client, headers, contexto, host, URL, path o API Key.
- No crear una herramienta separada solo por una diferencia invisible de implementación; separar IPv4/IPv6 cuando los contratos o el significado lo justifiquen.
- No añadir opciones MCP, prompts, recursos o completions por inercia. Mantener únicamente recursos/prompts que aporten valor claro y estén actualizados. No introducir Roots, Sampling ni MCP protocol Logging en el nuevo diseño: están **deprecados** (no eliminados) en 2026-07-28 por SEP-2577, con retirada elegible a partir de la primera revisión publicada el 2027-07-28 o después, y las implementaciones nuevas **SHOULD NOT** adoptarlos. El SDK v2 los sigue soportando para clientes heredados con `MCPDeprecationWarning`. Además, `ping`, `logging/setLevel` y `notifications/roots/list_changed` sí se **eliminaron** en esta revisión. Usar configuración explícita, herramientas/recursos y logging estándar de Python hacia stderr/observabilidad del proceso. [R15] [R36]

## Output schemas y resultados

El SDK v2 infiere `outputSchema` del tipo de retorno y valida el resultado. El cliente recibe `content` orientado al modelo y `structuredContent` orientado a la aplicación. Usar DTOs Pydantic tipados para objetos de salida estables y comprobar el esquema publicado a través de un cliente MCP real. No devolver JSON Sophos crudo ni campos sensibles. [R17]

**Forma de salida:** preferir un objeto raíz tipado (`items`, `item`, `page`, `pages`, `total`, `truncated` solo cuando el contrato permita afirmarlo, etc.). En 2026-07-28 el protocolo ya **no** impone objeto raíz: `outputSchema` admite cualquier JSON Schema 2020-12 y `structuredContent` cualquier valor JSON (SEP-2106). La restricción a objeto raíz existía hasta 2025-11-25 (`outputSchema` con `type: "object"` obligatorio y `structuredContent` objeto). El SDK v2 ya envuelve automáticamente escalares, listas, tuplas, uniones y `None` en `{"result": ...}` y publica ese `outputSchema` con raíz de objeto, así que la regla se cumple por construcción; mantenerla es una decisión de interoperabilidad con clientes anteriores, no un requisito de la revisión actual. No duplicar manualmente datos en `content` y `structuredContent`: seguir el comportamiento del SDK fijado y probar ambos canales. [R15] [R17]

**Tamaño y paginación:** no hacer auto-pagination ilimitada ni recuperar todas las páginas en una sola llamada MCP. Exponer `page`/`pageSize` solo cuando el endpoint Sophos los defina, aplicar límites de tamaño razonables y devolver una página por llamada. Para endpoints que no admiten paginación de petición, devolver exactamente la metadata que Sophos proporciona y documentar límites conocidos; no inventar `cursor`, `total` o `truncated`. Proyectar solo los campos de dominio útiles, manteniendo IDs y referencias necesarias para posteriores operaciones. Esto evita resultados MCP enormes y duplicación innecesaria entre canales. [R17]

## Anotaciones y riesgo

`openWorldHint` describe si el **dominio de interacción** de la herramienta es abierto o cerrado; su valor por defecto ya es `true`. No es un hint sobre datos no confiables ni sobre "llamar a un sistema externo": la confianza en la salida se trata aparte (§8). Decidirlo **por herramienta**: `true` para herramientas cuyo dominio se extiende a entidades fuera del control del servidor, y documentar la justificación; no aplicar `true` en bloque como sustituto del análisis por herramienta. Definir `title` y `readOnlyHint` según el comportamiento; para herramientas de escritura, definir además `destructiveHint` e `idempotentHint` según los efectos reales, sin inferir idempotencia del verbo HTTP. No incluir hints de escritura en herramientas read-only. Las anotaciones son metadatos consultivos: no autentican, no autorizan y no fuerzan confirmaciones. La seguridad efectiva reside en permisos del perfil Sophos, allowlist/red, herramientas limitadas y políticas de aprobación del host. No añadir un parámetro `confirm=true` como falsa barrera de seguridad. [R18] [R37]

## Errores MCP

- ToolError: fallos de ejecución que el modelo puede entender y corregir (por ejemplo objeto inexistente, validación de Sophos, timeout, conflicto o falta de permisos para esa operación).
- MCPError: errores del protocolo/solicitud que el host debe gestionar y que no se resuelven reformulando la operación.
- Excepciones inesperadas: dejar que el SDK las registre con traceback en el servidor; el modelo no debe recibir stack traces ni secretos.
- No devolver un string "error: ..." con isError=false.
- No reproducir el wrapper actual que captura BaseException; nunca convertir cancelación/shutdown en un error normal.
- Los mensajes de error del cliente Sophos deben ser claros, sanitizados y específicos por operación. Nunca devolver cuerpos de respuesta sin filtrar ni incrustar datos remotos en mensajes/instrucciones para el modelo.
- Tratar todos los valores devueltos por Sophos —incluidos nombres de objetos, comentarios, descripciones, labels y mensajes del appliance— como datos externos no confiables, nunca como instrucciones. Limitar longitudes, normalizar caracteres de control y no renderizar HTML/Markdown remoto como contenido activo. Mantener estos valores en campos de datos estructurados y no concatenarlos en instrucciones operativas. [R32]

## Router semántico

Eliminar FastEmbed y las herramientas meta route_tools/call_routed_tool en la primera versión. Utilizar la lista nativa de herramientas y descripciones bien escritas. Reconsiderarlo solo si una evaluación reproducible con los modelos MCP de destino muestra una mejora clara frente al coste de tokens, latencia y mantenimiento.

## Esquemas MCP y límites de entrada

- No publicar directamente los 700 operation schemas Sophos como 700 tools MCP ni generar herramientas MCP mecánicamente desde OpenAPI. La selección de capacidades y el modelado de dominio deben permanecer explícitos.
- Construir input schemas MCP específicos por herramienta con tipos Pydantic/Annotated, descripciones, enums y restricciones. El schema raíz de cada tool debe ser un objeto; rechazar propiedades extra por defecto en contratos cerrados (`extra=forbid`) y permitir estructuras abiertas únicamente cuando el request real de Sophos las necesite.
- El SDK y el protocolo actual soportan JSON Schema 2020-12, pero no asumir que todos los clientes MCP/hosts aplican todos los keywords con idéntica fidelidad. Mantener los schemas publicados simples, interoperables y comprobados desde `tools/list`.
- Modelar únicamente los campos que la operación requiera; separar DTOs MCP de los schemas de transporte Sophos cuando sus propósitos difieran. No exponer headers, URL, host, path, API Key o `Context`.
- Cada herramienta debe tener nombre estable, título legible, descripción accionable, campos requeridos explícitos, unidades/formato de valores y efectos laterales explicados. No confiar en los defaults de Python para ocultar decisiones importantes de firewall.

# 8. Seguridad operativa y semántica de escritura

- API Key en secreto de despliegue, nunca en repo, imagen, salida, trazas o logs.
- Tratar todas las respuestas del firewall como datos externos no confiables. Los nombres, comentarios y descripciones pueden ser controlados por usuarios/admins o proceder de sistemas conectados; nunca interpretarlos como instrucciones para el agente ni concatenarlos en instrucciones de herramientas.
- Un administrador dedicado por automatización/servidor y permisos mínimos; no usar admin por conveniencia.
- Documentar expiración de un año y rotación/revocación manual de la clave.
- Respetar API Access allowlist y Device Access del firewall.
- Usar permisos `None`/`Read-only`/`Read-write` por módulo en el perfil de administrador de Sophos cuando estén disponibles; no asumir que la granularidad de permisos del servidor MCP reemplaza las ACL del appliance. Todos los administradores pueden ver el inventario de API Keys; el administrador predeterminado puede eliminar claves de otros administradores, por lo que la operación debe documentar el impacto de revocación y la rotación de claves usadas por integraciones.
- Implementar un modo de servidor opcional `SOPHOS_READ_ONLY_MODE=true` que no registre herramientas de mutación como defensa adicional para despliegues de consulta (default `false`). Este modo no sustituye el perfil `Read-only` de Sophos ni debe usarse como única barrera.
- No ofrecer raw REST, arbitrary path ni operaciones que permitan saltarse schemas de herramientas.
- En operaciones de escritura, validar referencias antes de mutar y devolver los IDs reales.
- No hacer read-modify-write si PATCH permite modificar de forma segura los campos solicitados. Si es necesario, preservar las propiedades no modificadas y probarlo.
- No interpretar timeout/cancelación como rollback. Tras escritura ambigua, realizar lectura de reconciliación antes de cualquier repetición.
- Solo declarar idempotencia cuando el contrato y la operación real lo garanticen; el verbo HTTP por sí solo no basta.
- Las anotaciones no sustituyen las aprobaciones/confirmaciones que tenga configuradas el host agente.

# 9. Organización de los trabajos: diez issues

La ejecución se divide en 3 grupos, con un entregable verificable por issue. La décima issue es [#35 — rule audit, connectivity explanation and object usage](https://github.com/lordraiden/sophos-firewall-mcp/issues/35), añadida al ampliar el alcance v1 el 15 de noviembre de 2026.

## M1 — REST Foundation

**#24 — [M1] Audit Sophos Firewall REST OpenAPI and define API coverage**

- Auditar todo el YAML local, compararlo con Sophos online y con la versión SFOS objetivo.
- Crear docs/API-COVERAGE.md por operación.
- Clasificar límites, paginación, media types, respuestas, IDs y permisos.
- POC de generación de cliente y ADR.

**#25 — [M1] Replace XML transport with a typed Sophos REST client**

- Eliminar XML y credenciales antiguas.
- Configuración, Bearer token, TLS, HTTPX, errores, timeout, paginación y retries.
- Cliente reutilizable, sin endpoints arbitrarios.

**#26 — [M1] Rebuild MCP server foundation for REST-backed tools**

- SDK v2, lifespan, AppContext, registro modular.
- Input/output schemas, anotaciones, error mapping.
- stdio y eliminación de router/raw API.

## M2 — Sophos REST capabilities

**#27 — [M2] Implement Sophos Firewall Rule management tools (IPv4 and IPv6)**

- CRUD individual y move según OpenAPI; bulk delete excluido inicialmente.
- Estado explícito y no autoactivar reglas.

**#28 — [M2] Implement Sophos NAT Rule management tools (IPv4 and IPv6)**

- CRUD individual y move según OpenAPI; bulk delete excluido inicialmente.

**#29 — [M2] Implement Sophos Network Address and Service object tools**

- Direcciones, grupos, servicios y referencias, tipados por esquema y familia.

**#30 — [M2] Implement Sophos Network User and Live Session tools**

- Usuarios de red, lista paginada general, sesiones activas y desconexión individual.
- Administración de administradores excluida inicialmente.

**#31 — [M2] Implement Sophos VPN, Network Interface and Read-only Status tools**

- VPN configurada vs live state, interfaces y endpoints de salud/monitorización seleccionados.
- Limitarse a capacidades verificadas.

## M3 — Quality and Release

**#32 — [M3] Harden, validate, package, and release the REST-only MCP server**

- Seguridad y pruebas globales.
- Integración no destructiva contra SFOS de prueba.
- Docker, CI, dependencias, documentación y preparación de release.

## Dependencias

- #24 precede a #25; #24 y #25 son prerrequisitos de #26.
- #27–#31 dependen de #24, #25 y #26; pueden avanzar en PR separados tras aceptar la base.
- #32 depende de #24–#31.
- Cada issue funcional incluye sus propias pruebas unitarias/contractuales; #32 hace la validación integral.
- Los prefijos de título agrupan el trabajo. No es necesario crear un milestone de GitHub separado para cada bloque.

# 10. Pruebas y criterios de aceptación

| Prueba | Qué debe demostrar |
|---|---|
| OpenAPI validation | Fichero íntegro parseable, refs resueltas y contrato trazable por SHA |
| Contract tests | Método, path, headers, media type, parámetros, body y respuestas por operación |
| Model tests | Required/optional/null, enums, formatos, referencias y salida estructurada |
| Domain tests | Operaciones de negocio, PATCH y preservación de propiedades |
| Pagination tests | Solo en endpoints paginados; sin truncamiento silencioso |
| Error tests | Status/error schema definido por cada operación más fallos de red |
| Security tests | TLS, redacción, secretos, redirects, permisos y tool annotations |
| MCP tests | Tool discovery, argumentos, resultados, isError, transporte y cancellation |
| Appliance tests | Firmware, permisos y comportamiento real no demostrable con mocks |
| Docker/CI | Imagen, stdio, lockfile y workflows reproducibles |

Escenarios prioritarios:

1. Crear una regla con estado expresamente solicitado, recuperarla y modificar un campo sin alterar propiedades ajenas.
2. Verificar el resultado de un POST/PATCH/DELETE tras un timeout sin repetir la escritura a ciegas.
3. Confirmar que la paginación de usuarios no se confunde con el array plano de live users.
4. Probar desconexión individual mediante el liveUserId correcto y el mensaje requerido.
5. Confirmar que ninguna respuesta/log/schema expone API Keys o credenciales.
6. Confirmar que las herramientas anunciadas corresponden a operaciones verificadas en el OpenAPI y el firmware.

Las pruebas destructivas deben usar un appliance/lab de pruebas y objetos creados para ese fin. No ejecutar bulk delete ni cambios de interfaz/producción como parte del test suite.

# 11. CI, empaquetado y publicación

- Usar `pyproject.toml` + `uv.lock` como fuentes canónicas. Ejecutar installs bloqueados (`uv sync --locked` o equivalente) en CI/build. Eliminar `requirements.txt`/`requirements-dev.txt` si no tienen consumidor, o generarlos y verificarlos desde `uv.lock`; no mantener pines independientes. Eliminar tipos de xmltodict y FastEmbed del set de desarrollo/runtime que ya no se use.
- Actualizar Dockerfile para no instalar FastEmbed ni descargar modelos.
- Docker Compose debe pasar únicamente configuración REST y secreto, mantener stdio y no asignar TTY.
- Revisar ejecución no-root, paquetes mínimos, señales y cierre ordenado.
- Pipelines deben instalar desde el mismo lockfile que construye la imagen y escanear ese conjunto real de dependencias. En particular, sustituir el `pip-audit -r requirements.txt` actual, que analiza MCP 1.x mientras `pyproject.toml` instala MCP 2.x, por un export auditado de la resolución bloqueada real.
- Matrix de Python según versiones que se declaren oficialmente soportadas: 3.11–3.14. El SDK 2.3.0 declara `>=3.10` en metadatos y "3.11+" en su documentación de instalación; el proyecto ya exige `>=3.11`, así que 3.11–3.14 es la matriz coherente y añade 3.14, hoy ausente del CI.
- Añadir validación OpenAPI/drift reproducible.
- Actualizar README, .env.example, CHANGELOG, API-COVERAGE y release metadata.
- Cambiar `docker-publish.yml`: no promover `latest` en cada push a `main`; los commits de main pueden publicar solo tags de desarrollo (main/SHA). Reservar `latest` y tags semver estables a una promoción de release explícita, revisada y protegida por el mecanismo de aprobación del repositorio.
- Verificar el nombre canónico de la imagen GHCR y actualizar README/Compose; el README actual referencia `ghcr.io/jelmervdm/...` mientras el workflow etiqueta con `${{ github.repository }}` (`ghcr.io/lordraiden/...`).
- No publicar tag/imagen de release sin la aprobación de release habitual del propietario.

# 12. Riesgos y decisiones que no deben darse por resueltas

1. **Versión del spec local:** el SHA-256, blob SHA y tamaño están registrados, pero info.version y todos sus esquemas deben leerse del propio fichero en #24. No asumir que es idéntico al portal online.
2. **Firmware destino:** el target de prueba no está confirmado en este documento. Registrar build exacto; no declarar compatibilidad general a partir de SFOS 23 docs.
3. **Code generation:** no se decidió todavía. La ADR de #24 debe elegir con pruebas. El documento es mayoritariamente inline (32 esquemas de componente para 700 operaciones; 4.265 esquemas inline), lo que penaliza un cliente generado completo.
4. **PATCH semantics:** el verbo no define RFC 7396; verificar request content type por operación. En este contrato las 134 PATCH son `application/json` y cuatro documentan merge por `name` en arrays. El comportamiento real de PATCH sobre arrays sigue sin probarse en el appliance.
5. **Pagination:** endpoint-specific. No implementar cursor genérico si el API no lo usa; 83 GET comparten `page`/`pageSize`/`pageTotal`. `live-users` no los declara, pero el appliance los acepta (verificado el 15 nov 2026); el MCP no los expone en v1.
6. **Status codes/errors:** endpoint-specific. No codificar 429 u otros status como contrato sin documentación o evidencia. Verificado en vivo: 401/400 y 404 de recurso son JSON (`{"error":…,"message":…}`), pero un path inexistente devuelve 404 HTML, 405 devuelve texto plano y PUT devuelve 403 HTML; el cliente debe mapear y sanitizar por operación.
7. **Rule defaults:** comportamiento del Firewall AI Assistant no se debe extrapolar al REST POST.
8. **Administrators:** la API puede exponer operaciones de administradores; el primer release las excluye por seguridad, no porque el API carezca de ellas.
9. **System information:** no reconstruir información no expuesta; seleccionar health/status endpoints realmente documentados. `getSystemSettings` solo devuelve `hostname`, `loginDisclaimer` y `updatedAt`.
10. **Tamaño de resultados MCP:** no exponer dumps completos ni auto-pagination ilimitada; los outputs estructurados y las listas deben tener límites y ser útiles para el siguiente paso del agente.
11. **Compatibilidad MCP:** la revisión `2026-07-28` es la versión moderna, pero el SDK v2 atiende también 2024-11-05, 2025-03-26, 2025-06-18 y 2025-11-25 mediante handshake. No codificar un servidor que funcione solo con un handshake heredado ni un payload que dependa de listas JSON raíz.
12. **Validación de nombres:** los `format` `sfos-object-name*` no son asertivos (994 de 1.085 sin `pattern`); el cliente MCP debe implementar la validación documentada.
13. **Lista de no soportadas:** no es exhaustiva y es internamente inconsistente con el catálogo (wireless/hotspot, DHCP leases); no usarla como sustituto del contrato ni del firmware.
14. **Device Access y WAN:** el acceso desde WAN solo se documenta mediante una regla de excepción de Local service ACL por IP de origen; no existe una forma de habilitar "todo WAN", y Sophos lo desaconseja.

# 13. Decisión definitiva

| Área | Decisión |
|---|---|
| API | Sophos Firewall Configuration REST API v1, directamente contra el appliance |
| XML | Eliminado; sin compatibilidad |
| Contrato | YAML del repo, verificado con portal y firmware |
| Transporte | Cliente REST asíncrono compartido |
| Autenticación | API Key Bearer, admin dedicado y mínimo privilegio |
| TLS | Verificación por defecto |
| MCP SDK | Python SDK v2; fijar versión estable reproducible (v2.3.0 en esta revisión); `mcp>=2.3.0,<3` |
| MCP protocol | SDK gestiona revisión 2026-07-28 y compatibilidad con 2024-11-05…2025-11-25; no implementar handshake manual |
| Transporte MCP | stdio inicial; sin listener HTTP no solicitado |
| Herramientas | Operaciones de negocio tipadas y limitadas |
| Inputs | Pydantic/Annotated y schemas del SDK |
| Outputs | Modelos estructurados validados; raíz de objeto como convención de interoperabilidad, no como requisito de 2026-07-28 |
| Annotations | Title + readOnly/destructive/idempotent/openWorld como hints por herramienta, no ACL |
| Errors | ToolError para fallos de ejecución; MCPError para errores de protocolo |
| Router | Eliminado inicialmente |
| Raw REST | No exponer |
| Pruebas | Contrato por operación, unitarias, MCP y appliance de laboratorio |
| Organización | 9 issues, 3 bloques |

**La prioridad no es reproducir las 28 herramientas XML. Es construir una integración REST fiel a la especificación del appliance y una superficie MCP reducida, tipada, segura y verificable.**

La seguridad se debe diseñar en capas: permisos mínimos en el perfil Sophos (control efectivo en el firewall), restricción de IP de origen y HTTPS, secreto Bearer protegido en el proceso, schemas/tool surface mínimos y aprobación de mutaciones en el host cuando este la soporte. Las anotaciones MCP nunca deben tratarse como una ACL.

La auditoría completa del YAML y la verificación del firmware deben preceder a cualquier implementación de dominio. No se debe ocultar una función no soportada ni declarar una operación válida por semejanza con XML, la Web Admin Console u otro API de Sophos.

# 14. Auditoría independiente (15 de noviembre de 2026)

La revisión independiente se documenta en [INDEPENDENT_REVIEW_REPORT.md](./INDEPENDENT_REVIEW_REPORT.md). Resumen de lo que cambió en este plan:

- **Corregido:** la descripción de Device access vs Local service ACL (el acceso desde WAN solo se documenta mediante la regla de excepción, que forma parte de Device access); la atadura de versión del portal de API (no declara versión SFOS); la naturaleza del Firewall Health Check (cumplimiento de políticas, no salud general); `message` obligatorio (1–600) en la desconexión de live sessions; la lista de no soportadas (no exhaustiva e internamente inconsistente); la versión mínima de openapi-python-client (0.30.0, no 0.29.1); la matriz de Python (3.11–3.14); el alcance de `subscriptions=False` (solo clientes 2026-07-28); la semántica de `openWorldHint` (dominio de interacción, decidir por herramienta); la regla de raíz de objeto (convención de interoperabilidad, no requisito de 2026-07-28); el estado de Roots/Sampling/Logging (deprecados, no eliminados, con `ping`/`logging/setLevel`/`roots/list_changed` sí eliminados).
- **Añadido:** evidencia del propio `info.description` del YAML para PATCH, base URL, Bearer y formatos de nombre; las cuatro excepciones PATCH documentadas; los recuentos verificados (32 esquemas, 76 refs, 83 GET paginados, 260 operaciones name-or-id, 6 UUID-only, 17 sin tipar); la advertencia de que los `format` de nombre no son asertivos; el detalle de que `getSystemSettings` solo devuelve `hostname`, `loginDisclaimer` y `updatedAt`; la nota de que la advertencia de conectividad de interfaces está en la ayuda de administración, no en el API Reference.
- **Sin cambios:** REST-only, sin XML, sin raw REST, stdio inicial, mínimo privilegio Sophos, PATCH JSON Merge Patch por defecto, no reintentar escrituras ambiguas, TLS verificado por defecto, y el reparto de diez issues (#24–#32 y #35).
