# Plan de rediseño: Sophos Firewall MCP — REST API

**Revisión técnica:** 14 de noviembre de 2026  
**Estado:** diseño revisado; la implementación todavía no está realizada.  
**Repositorio:** [lordraiden/sophos-firewall-mcp](https://github.com/lordraiden/sophos-firewall-mcp)  
**Especificación versionada:** [firewall_config_openapi.yaml](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/firewall_config_openapi.yaml)  
**Blob SHA observado:** 40fca0b25d4d85866f86b90aec77e5559ae27214  
**Tamaño registrado por GitHub:** 8.934.475 bytes.  
**Documentación oficial de referencia:** Sophos Firewall Configuration API, OpenAPI 3.0, versión publicada del portal 1.0.0. La versión del portal no debe confundirse con info.version del fichero local: hay que verificar ambas en la Fase 0.

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

# 2. Qué API estamos implementando y qué exige Sophos

El objetivo es la **Sophos Firewall Configuration REST API del propio appliance**, no la Sophos Central Firewall Management API ni un API de inventario/gestión centralizada.

La API de configuración del appliance utiliza:

- Base URL: https://<firewall-hostname>:<admin-https-port>/api/firewall-config/v1.
- Autenticación por API Key en Authorization: Bearer <api-key>.
- JSON y operaciones HTTP descritas por OpenAPI 3.0.
- Acceso desde dispositivos/IP hosts permitidos por el propio firewall.

No añadir un API_VERSION configurable: v1 forma parte de la ruta base. Tampoco asumir un puerto universal; debe configurarse el puerto HTTPS del Web Admin Console del appliance. [R01] [R02]

## Prerrequisitos de seguridad del appliance

Para habilitar la API no basta con disponer de una API Key:

1. Activar REST API access en Administration → API access.
2. Añadir la IP, rango o red de origen a Allowed IP hosts.
3. Comprobar Device access: la zona desde la que se conecta el administrador debe tener acceso al Web Admin Console.
4. Crear un administrador dedicado con los permisos mínimos necesarios.
5. Generar la API Key con ese administrador.

Las API Keys heredan los permisos del administrador que las genera, tienen una validez de un año y dejan de mostrarse después de cerrar el diálogo de generación. La documentación también señala límites de claves por appliance y administrador. La rotación debe documentarse como una operación administrativa manual; no asumir que existe un endpoint de renovación automática. [R03] [R04]

## Firmware y limitaciones

La documentación de API consultada acompaña SFOS 23.0; sus release notes identifican SFOS 23.0 GA Build 371, publicado el 4 de noviembre de 2026. Esto **no demuestra** que el firewall destino del proyecto esté ejecutando esa versión ni que todas las operaciones se comporten igual en cualquier build. [R05]

Sophos publica una lista de funcionalidades no soportadas (entre ellas firewall rule groups, varias modalidades VPN, RED, wireless y determinadas funciones de estado), pero advierte que la lista no es exhaustiva. Para cada capacidad hay que consultar el endpoint en el API Reference y verificarlo en el firmware objetivo. [R04]

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

La referencia OpenAPI incluye muchos más módulos que las herramientas XML originales. La primera versión no tiene que exponer todo el catálogo. La Fase 0 debe inventariarlo por completo y seleccionar un alcance inicial coherente con las funciones actuales y las necesidades reales de administración.

| Dominio | Cobertura a investigar | Decisión inicial |
|---|---|---|
| Firewall rules | IPv4/IPv6, list/get/create/update/delete/move y bulk delete | Implementar operaciones individuales; no exponer bulk delete inicialmente |
| NAT rules | IPv4/IPv6, list/get/create/update/delete/move y bulk delete | Operaciones individuales; bulk delete fuera del alcance inicial |
| Network addresses | IPv4, IPv6, FQDN y otros tipos que aparezcan en el spec (por ejemplo MAC) | Priorizar IPv4/IPv6/FQDN; los demás se clasifican en cobertura |
| Address groups | Grupos por familia/tipo, incluyendo FQDN, IPv4, IPv6 y country según endpoints | No asumir grupos mixtos; seguir cada esquema |
| Network services | Servicios y grupos | Implementar esquemas/endpoints reales, no reutilizar modelos XML |
| Authentication users | Lista general paginada y recursos de usuarios de red | Separar listado general de CRUD de usuarios de red |
| Administrators | Operaciones de lectura y CRUD presentes en el catálogo | Documentar, pero excluir modificación de administradores/permisos de la primera versión por su impacto |
| Live sessions | Lista de sesiones activas y desconexión de una sesión | Implementar; el endpoint de listado documenta un array plano, no asumir paginación |
| VPN | IPsec profiles, failover groups, site-to-site y live state; SSL VPN remote access y otros recursos documentados | Seleccionar operaciones compatibles; documentar explícitamente exclusiones |
| Network interfaces | Operaciones documentadas para interfaces | Empezar por lectura; no inferir operaciones de escritura por analogía con UI/XML |
| System/health | Firewall health check y otros endpoints de estado/configuración documentados | Recuperar solo información que REST realmente proporcione; no prometer modelo/serial/uptime sin endpoint |

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

La referencia oficial distingue el listado paginado de usuarios (/authentication/users), operaciones de usuarios de red y operaciones de administradores. El endpoint de live users devuelve un array plano de sesiones activas; existe una operación POST independiente para desconectar una sesión con liveUserId y message. No asumir que el endpoint de sesiones tiene la misma paginación que el listado de usuarios. [R08] [R09] [R10]

La primera versión debe:

- Separar network users, administrator accounts y live sessions en modelos y nombres de herramientas.
- Implementar paginación solo en los endpoints que la documentan.
- Implementar desconexión individual solo con el endpoint oficial, identificador correcto y anotación destructiva.
- Excluir create/update/delete de administradores y cambios de privilegios.
- Tratar password y credenciales como write-only/sensitive; nunca devolverlas ni incluirlas en logs.

## VPN, interfaces y salud

No ofrecer “VPN management” genérico. Separar configuración y estado operativo. La cobertura de OpenAPI enumera recursos de perfiles/failover/IPsec y SSL VPN, pero las limitaciones publicadas excluyen modalidades concretas. Cada una se debe clasificar por operación y firmware. [R04] [R11]

Las interfaces y la información de salud deben basarse en los endpoints reales. El objetivo es recuperar las funciones útiles de system/status sin volver a prometer modelo, número de serie, firmware o uptime si no existe una operación que los entregue.

# 5. OpenAPI como contrato de implementación

El YAML versionado en el repositorio es el contrato que hay que auditar. La página del API Reference de Sophos es una proyección oficial de OpenAPI 3.0, pero no sustituye la inspección del fichero exacto ni confirma la versión de SFOS del usuario. [R01] [R02]

La Fase 0 debe registrar:

- Blob SHA, tamaño, openapi, info.title, info.version, servers/base URL, tags y security schemes.
- Diferencias entre el YAML local, la versión mostrada por Sophos online y la especificación descargable desde el appliance/Administration → API access.
- Cada path y método con operationId, parámetros, media type, request schema, response schema, códigos de respuesta y referencias.
- $ref, allOf, oneOf, anyOf, enums, defaults, required/readOnly/writeOnly, nullable, arrays, límites y formatos.
- Operaciones paginadas, filtros, ordenación/move, bulk operations y efectos colaterales.
- Operaciones presentes en OpenAPI pero no disponibles por permisos o firmware.
- Correspondencia de cada operación REST con una herramienta MCP, o razón explícita para excluirla.

## PATCH: no inferir semántica por el verbo

HTTP PATCH no implica JSON Merge Patch. RFC 7396 solo aplica cuando la operación declara ese media type/semántica. Para cada PATCH hay que leer requestBody.content, schema y descripciones del OpenAPI y verificar el comportamiento real. No asumir que propiedades omitidas, null o arrays se comportan igual entre endpoints. [R12]

## Respuestas y errores por operación

No crear un mapa universal de códigos HTTP que se aplique a todos los endpoints. Sophos documenta códigos distintos según operación. Ejemplos de la referencia actual:

- GET de reglas IPv4: 200, 400, 401, 403, 500.
- POST de creación de regla IPv4: 201, 400, 401, 403, 409, 500.
- PATCH de actualización: 200, 400, 401, 403, 404, 409, 500.
- POST para desconectar una live session: 200, 400, 401, 403, 500.

Los ejemplos no son una lista global: el cliente y las pruebas deben seguir las respuestas de cada operación del YAML. Los estados no documentados deben tratarse de forma segura como inesperados, no inventar envelopes o significados. [R06a] [R06b] [R07a] [R10]

## Paginación: tampoco inferir por el nombre

La matriz debe documentar página/tamaño/offset/cursor y respuesta para cada endpoint. Por ejemplo, /authentication/users se documenta paginado; /authentication/live-users se documenta como array plano. El MCP debe devolver página y continuation metadata o hacer una agregación acotada con indicador explícito de truncamiento. Nunca devolver silenciosamente una primera página como si fuese el conjunto completo. [R08] [R09]

# 6. Cliente REST y configuración

Una única abstracción de cliente asíncrono, reutilizable y testeable, debe encapsular HTTP. No exponerla como herramienta MCP.

Configuración recomendada:

| Variable | Propósito |
|---|---|
| SOPHOS_HOST | IP/DNS del appliance |
| SOPHOS_PORT | Puerto HTTPS actual del Web Admin Console |
| SOPHOS_API_KEY | API Key del administrador dedicado |
| SOPHOS_VERIFY_SSL | Verificación TLS; segura por defecto |
| SOPHOS_CA_BUNDLE | CA privada opcional |
| SOPHOS_TIMEOUT | Timeout configurable |

No definir SOPHOS_USERNAME, SOPHOS_PASSWORD ni SOPHOS_API_VERSION. No fijar un puerto como default salvo que el proyecto decida y documente uno como valor de conveniencia; el puerto efectivo es el admin HTTPS port del appliance.

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

Si se usa openapi-python-client, usar al menos 0.29.1: versiones anteriores están afectadas por una vulnerabilidad de generación arbitraria de código al procesar OpenAPI malicioso. Ejecutar generación en entorno aislado, tratar el YAML como entrada de confianza limitada y revisar el código generado. No introducir un SDK generado enorme en producción sin justificarlo. [R13]

No duplicar dos catálogos de schemas sin una prueba de drift. El diseño final puede ser cliente generado detrás de un adapter fino, modelos generados/derivados con transporte propio o HTTPX+Pydantic; debe decidirse por evidencia del POC, no por preferencia previa.

# 7. Arquitectura MCP y prácticas recomendadas

El proyecto actual usa mcp>=2. La línea estable del SDK Python es v2; a 14 de noviembre de 2026 la última release publicada consultada es v2.3.0. Esta release implementa la revisión de protocolo MCP 2026-07-28 y el SDK sirve también revisiones anteriores. Usar la API pública documentada del SDK y fijar una versión reproducible en el lockfile. [R14] [R15]

## Transporte inicial

- Mantener stdio como transporte soportado para la integración local/CLI del proyecto.
- No añadir Streamable HTTP ni un listener de red sin un requisito real de despliegue remoto.
- En Docker, mantener el canal stdio limpio; no activar TTY.
- No implementar manualmente un handshake MCP. En la revisión 2026-07-28 se retiraron initialize/initialized y las sesiones de transporte; el SDK gestiona la revisión de protocolo y compatibilidad. Las pruebas deben usar el cliente SDK y cubrir la revisión actual, no codificar un handshake antiguo. [R15]

## Lifespan y Context

Utilizar el lifespan oficial del SDK:

1. Validar configuración al iniciar.
2. Crear una instancia compartida del cliente REST.
3. Exponer un objeto AppContext tipado a los handlers.
4. Cerrar el cliente HTTP en el bloque de salida/finally.

Los handlers reciben el Context del SDK y acceden al objeto de lifespan a través del request context según la API pública de la versión fijada. No usar client: Any = None como parámetro visible del tool ni crear un pool HTTP por llamada. [R16]

## Herramientas e input schemas

- Usar async def para handlers que realizan I/O.
- Usar tipos Python, Pydantic, Annotated, Field, Literal/Enum y modelos de entrada cuando aporten claridad.
- Exponer operaciones de negocio delimitadas, no una herramienta genérica de REST.
- Nombres/títulos/descripciones claros. Cada descripción debe explicar cuándo usar la herramienta, efecto/side effect, identificadores requeridos y limitaciones relevantes.
- No publicar como parámetros argumentos internos como client, headers, contexto, host, URL, path o API Key.
- No crear una herramienta separada solo por una diferencia invisible de implementación; separar IPv4/IPv6 cuando los contratos o el significado lo justifiquen.
- No añadir opciones MCP, prompts, recursos o completions por inercia. Mantener únicamente recursos/prompts que aporten valor claro y estén actualizados.

## Output schemas y resultados

El SDK v2 puede inferir output_schema del tipo de retorno y validar el resultado; devuelve content para el modelo y structured_content para la aplicación. Usar modelos Pydantic/dataclasses/TypedDict de salida para los objetos estables del dominio. Normalizar y filtrar la respuesta Sophos; no devolver indiscriminadamente JSON crudo ni campos sensibles. Optar por salida de texto únicamente cuando un esquema estable no tenga sentido. [R17]

Para colecciones potencialmente grandes, devolver una página tipada con metadatos de paginación o una respuesta agregada acotada con truncated/continuation explícitos.

## Anotaciones y riesgo

Definir title, readOnlyHint, destructiveHint, idempotentHint y openWorldHint según el comportamiento real de cada herramienta. No copiar un set uniforme sin pensar. Las anotaciones son pistas para el cliente, no controles de autorización ni una barrera de confirmación garantizada. La seguridad efectiva se obtiene mediante API Key de mínimo privilegio, red/allowlist, implementación y políticas de aprobación del host. [R18]

## Errores MCP

- ToolError: fallos de ejecución que el modelo puede entender y corregir (por ejemplo objeto inexistente, validación de Sophos, timeout, conflicto o falta de permisos para esa operación).
- MCPError: errores del protocolo/solicitud que el host debe gestionar y que no se resuelven reformulando la operación.
- Excepciones inesperadas: dejar que el SDK las registre con traceback en el servidor; el modelo no debe recibir stack traces ni secretos.
- No devolver un string "error: ..." con isError=false.
- No reproducir el wrapper actual que captura BaseException; nunca convertir cancelación/shutdown en un error normal.
- Los mensajes de error del cliente Sophos deben ser claros, sanitizados y específicos por operación. [R19]

## Router semántico

Eliminar FastEmbed y las herramientas meta route_tools/call_routed_tool en la primera versión. Utilizar la lista nativa de herramientas y descripciones bien escritas. Reconsiderarlo solo si una evaluación reproducible con los modelos MCP de destino muestra una mejora clara frente al coste de tokens, latencia y mantenimiento.

# 8. Seguridad operativa y semántica de escritura

- API Key en secreto de despliegue, nunca en repo, imagen, salida, trazas o logs.
- Un administrador dedicado por automatización/servidor y permisos mínimos; no usar admin por conveniencia.
- Documentar expiración de un año y rotación/revocación manual de la clave.
- Respetar API Access allowlist y Device Access del firewall.
- No ofrecer raw REST, arbitrary path ni operaciones que permitan saltarse schemas de herramientas.
- En operaciones de escritura, validar referencias antes de mutar y devolver los IDs reales.
- No hacer read-modify-write si PATCH permite modificar de forma segura los campos solicitados. Si es necesario, preservar las propiedades no modificadas y probarlo.
- No interpretar timeout/cancelación como rollback. Tras escritura ambigua, realizar lectura de reconciliación antes de cualquier repetición.
- Solo declarar idempotencia cuando el contrato y la operación real lo garanticen; el verbo HTTP por sí solo no basta.
- Las anotaciones no sustituyen las aprobaciones/confirmaciones que tenga configuradas el host agente.

# 9. Organización de los trabajos: nueve issues

La ejecución se divide en 3 grupos, con un entregable verificable por issue.

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

**#31 — [M2] Implement Sophos VPN, Network Interface and Read-only Health tools**

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

- Usar pyproject.toml y un lockfile como fuente canónica. No mantener requirements.txt divergente; eliminarlo o derivarlo/validarlo automáticamente.
- Actualizar Dockerfile para no instalar FastEmbed ni descargar modelos.
- Docker Compose debe pasar únicamente configuración REST y secreto, mantener stdio y no asignar TTY.
- Revisar ejecución no-root, paquetes mínimos, señales y cierre ordenado.
- Pipelines deben instalar desde el mismo lockfile que construye la imagen y escanear ese conjunto real de dependencias.
- Matrix de Python según versiones que se declaren oficialmente soportadas.
- Añadir validación OpenAPI/drift reproducible.
- Actualizar README, .env.example, CHANGELOG, API-COVERAGE y release metadata.
- No publicar tag/imagen de release sin la aprobación de release habitual del propietario.

# 12. Riesgos y decisiones que no deben darse por resueltas

1. **Versión del spec local:** el SHA y tamaño están registrados, pero info.version y todos sus esquemas deben leerse del propio fichero en #24. No asumir que es idéntico al portal online.
2. **Firmware destino:** el target de prueba no está confirmado en este documento. Registrar build exacto; no declarar compatibilidad general a partir de SFOS 23 docs.
3. **Code generation:** no se decidió todavía. La ADR de #24 debe elegir con pruebas.
4. **PATCH semantics:** el verbo no define RFC 7396; verificar request content type por operación.
5. **Pagination:** endpoint-specific. No implementar cursor genérico si el API no lo usa.
6. **Status codes/errors:** endpoint-specific. No codificar 429 u otros status como contrato sin documentación o evidencia.
7. **Rule defaults:** comportamiento del Firewall AI Assistant no se debe extrapolar al REST POST.
8. **Administrators:** la API puede exponer operaciones de administradores; el primer release las excluye por seguridad, no porque el API carezca de ellas.
9. **System information:** no reconstruir información no expuesta; seleccionar health checks/status endpoints realmente documentados.

# 13. Decisión definitiva

| Área | Decisión |
|---|---|
| API | Sophos Firewall Configuration REST API v1, directamente contra el appliance |
| XML | Eliminado; sin compatibilidad |
| Contrato | YAML del repo, verificado con portal y firmware |
| Transporte | Cliente REST asíncrono compartido |
| Autenticación | API Key Bearer, admin dedicado y mínimo privilegio |
| TLS | Verificación por defecto |
| MCP SDK | Python SDK v2; fijar versión estable reproducible (v2.3.0 en esta revisión) |
| MCP protocol | SDK gestiona revisión 2026-07-28 y compatibilidad; no implementar handshake manual |
| Transporte MCP | stdio inicial; sin listener HTTP no solicitado |
| Herramientas | Operaciones de negocio tipadas y limitadas |
| Inputs | Pydantic/Annotated y schemas del SDK |
| Outputs | Modelos estructurados validados |
| Annotations | Title + readOnly/destructive/idempotent/openWorld como hints, no ACL |
| Errors | ToolError para fallos de ejecución; MCPError para errores de protocolo |
| Router | Eliminado inicialmente |
| Raw REST | No exponer |
| Pruebas | Contrato por operación, unitarias, MCP y appliance de laboratorio |
| Organización | 9 issues, 3 bloques |

**La prioridad no es reproducir las 28 herramientas XML. Es construir una integración REST fiel a la especificación del appliance y una superficie MCP reducida, tipada, segura y verificable.**

La auditoría completa del YAML y la verificación del firmware deben preceder a cualquier implementación de dominio. No se debe ocultar una función no soportada ni declarar una operación válida por semejanza con XML, la Web Admin Console u otro API de Sophos.
