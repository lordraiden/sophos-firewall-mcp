# Plan de rediseño: Sophos Firewall MCP — REST API

**Fecha:** 14 de noviembre de 2026  
**Estado:** propuesta técnica para organizar la adaptación; no implica que los cambios estén implementados.  
**Repositorio:** [lordraiden/sophos-firewall-mcp](https://github.com/lordraiden/sophos-firewall-mcp)  
**Especificación OpenAPI incorporada:** [firewall_config_openapi.yaml](https://github.com/lordraiden/sophos-firewall-mcp/blob/main/firewall_config_openapi.yaml)  
**Blob SHA de la especificación inspeccionada:** `40fca0b25d4d85866f86b90aec77e5559ae27214`  
**Tamaño registrado por GitHub:** 8.934.475 bytes.

> Este documento conserva el plan técnico acordado en la conversación y convierte las referencias externas en identificadores verificables que se desarrollan en [REFERENCES.md](./REFERENCES.md). La auditoría exhaustiva del YAML y la validación contra el firmware de destino siguen siendo trabajo de la Fase 0.

# 1. Decisión técnica

Mi recomendación es **reconstruir la implementación funcional sobre REST, aprovechando únicamente la infraestructura y los conocimientos válidos del proyecto actual**.

No haría una conversión progresiva del cliente XML ni intentaría adaptar sus clases para que acepten indistintamente JSON y XML.

Tampoco empezaría un repositorio nuevo: conservaría `lordraiden/sophos-firewall-mcp`, su identidad, historial, automatizaciones y estructura de distribución.

La distinción es importante:

## Reutilizar

- Repositorio, licencia y metadatos.
- Docker, GHCR y CI/CD, después de revisarlos.
- Estructura de pruebas y experiencia adquirida.
- Funcionalidades de administración que realmente necesitamos.
- Contratos MCP y conocimientos de los problemas encontrados.

## Reescribir

- Cliente Sophos y transporte HTTP.
- Autenticación y configuración.
- Modelos y validaciones de datos.
- Implementación de todas las herramientas.
- Registro MCP y gestión del ciclo de vida.
- Gestión de errores, resultados y seguridad.
- Recursos, prompts y enrutamiento, según su utilidad real.

## Eliminar

- `xmltodict`.
- Credenciales XML y `APIVersion`.
- Construcción de peticiones XML.
- Herramienta `sophos_raw_api_request`.
- Pruebas basadas exclusivamente en respuestas XML.
- Lógica de compatibilidad con la API anterior.

Hay una razón adicional para no adaptar directamente las herramientas actuales: la diferencia afecta a los propios contratos de datos. REST utiliza modelos JSON, referencias mediante nombres o UUID y actualizaciones PATCH con semántica JSON Merge Patch (RFC 7396), no las estructuras XML que actualmente manipula el proyecto. [R02] [R18]

# 2. Qué debería ser el nuevo proyecto

No lo plantearía como un simple MCP que envuelve una API REST. Lo plantearía como un **servidor MCP especializado en administrar Sophos Firewall**, que utiliza la API oficial como mecanismo de acceso.

La arquitectura debería ser sencilla:

```text
MCP Server
  |
  +-- Herramientas, esquemas, instrucciones y contratos MCP
  |
  +-- Domain Tools
  |     +-- Firewall
  |     +-- NAT
  |     +-- Network
  |     +-- Services
  |     +-- Users
  |     +-- VPN
  |     +-- System
  |
  +-- Sophos REST Client
        +-- HTTP
        +-- Bearer Authentication
        +-- JSON
        +-- TLS
        +-- Timeouts
        +-- Error mapping
        |
        +-- Sophos Firewall REST API v1
```

El objetivo es que las herramientas MCP no tengan que conocer detalles de HTTP, autenticación, códigos de estado o construcción de URLs.

Por ejemplo, `create_firewall_rule` debería recibir un modelo de regla validado, no construir manualmente una petición HTTP ni permitir que el modelo envíe cualquier ruta.

# 3. Qué ofrece realmente la nueva API

La especificación no es una actualización menor. Es una API de administración bastante amplia.

La referencia oficial de Sophos está generada desde OpenAPI 3.0 y su versión documentada es 1.0.0. Incluye administración, autenticación, objetos, redes, routing, VPN, reglas, NAT, protección y monitorización, entre otras áreas. [R01] [R02]

Esto nos permite plantear algo mejor que reproducir exactamente las 28 herramientas que tenía el proyecto.

## 4. Correspondencia entre el desarrollo actual y REST

Esta es la parte más importante para decidir qué funcionalidades reconstruir y cuáles replantear.

Hay que matizar la comparación: algunos dominios no tienen equivalencia funcional directa.

| Dominio actual | Nueva API REST | Decisión |
|---|---|---|
| Firewall Rules | IPv4 e IPv6, CRUD y ordenación | Reconstruir y ampliar |
| NAT Rules | IPv4 e IPv6, CRUD y ordenación | Reconstruir y ampliar |
| IP Hosts | Direcciones IPv4 e IPv6 | Rediseñar modelos |
| FQDN Hosts | Network Addresses FQDN | Reconstruir |
| Host Groups | Address Groups por tipo | Rediseñar |
| Services | Network Services | Reconstruir |
| Service Groups | Network Service Groups | Reconstruir |
| Users | Users, Network Users y Administrators | Separar conceptos |
| Live Users | Live sessions y desconexión | Reconstruir |
| IPsec VPN | Configuración y conexiones activas | Reconstruir |
| SSL VPN | Políticas de acceso remoto y configuración | Reconstruir parcialmente |
| Interfaces | Network Interfaces | Reconstruir |
| System Information | No hay equivalencia general de información de estado | Eliminar o redefinir |
| Service Status | Sin equivalencia general confirmada | Eliminar inicialmente |
| Raw XML API | No procede | Eliminar |

Referencias de Sophos: [R02] y sus operaciones de [reglas de firewall R05], [NAT R06], [objetos de red R07–R10], [servicios R11–R12], [interfaces R13], [usuarios/sesiones R14], [VPN R15–R17].

### Diferencias funcionales importantes

**Firewall y NAT**

La API REST contempla reglas IPv4 e IPv6, operaciones CRUD y operaciones adicionales para modificar su posición. Esto supone una oportunidad para mejorar el proyecto: no limitarlo a reproducir las operaciones que tenía XML.

En cambio, Sophos indica expresamente que los grupos de reglas de firewall no están soportados actualmente mediante REST. No debemos intentar implementarlos inventando operaciones equivalentes. [R04] [R05] [R06]

**Network Objects**

No deberíamos mantener una única entidad genérica `IPHost`.

REST diferencia direcciones IPv4, IPv6, FQDN y grupos. Las herramientas y modelos deben reflejar esas diferencias, especialmente al crear objetos y referenciarlos desde reglas. [R07] [R08] [R09] [R10]

**Usuarios**

Aquí hay una diferencia especialmente importante.

La API tiene:

- Un listado de usuarios con información básica y paginación.
- Operaciones CRUD específicas para usuarios de red.
- Operaciones independientes para administradores.

Por tanto, no trasladaría `sophos_create_user` y `sophos_delete_user` como herramientas genéricas. Separaría usuarios de red de administradores y dejaría la administración de cuentas privilegiadas fuera del alcance inicial. [R14] [R02]

**VPN**

Hay que distinguir configuración y estado operativo.

La API ofrece operaciones para conexiones IPsec y sus conexiones activas, además de políticas SSL VPN de acceso remoto. Sin embargo, Sophos excluye determinadas modalidades, como IPsec routes, GRE, L2TP, PPTP y los clientes y servidores SSL VPN site-to-site. [R15] [R16] [R17] [R04]

**System y monitorización**

No intentaría recuperar la herramienta actual `sophos_get_system_info` cambiando simplemente el endpoint.

El propio historial del proyecto documenta que la API XML no conseguía obtener modelo, número de serie, versión de firmware ni uptime en SFOS 22. La nueva documentación también enumera limitaciones de información de estado.

Hay que diseñar herramientas específicas para la información que REST realmente ofrece, no prometer un diagnóstico general del firewall que la API no puede proporcionar. [R04]

# 5. Decisiones arquitectónicas que tomaría

## A. OpenAPI como contrato de referencia

El archivo `firewall_config_openapi.yaml` debe convertirse en la fuente de verdad del contrato REST.

No mantendría las URLs, propiedades y estructuras JSON desperdigadas por las herramientas.

Mi propuesta es realizar una pequeña prueba técnica con `openapi-python-client`.

Es un generador de clientes Python para OpenAPI 3.0 y 3.1, aunque sigue siendo un proyecto en desarrollo y no soporta todas las características de OpenAPI. La versión 0.29.1, publicada el 30 de agosto de 2026, incorporó una corrección de seguridad importante relacionada con la generación de código. [R19]

Compararía dos alternativas:

| Alternativa | Ventaja | Inconveniente |
|---|---|---|
| Cliente generado desde OpenAPI | Modelos y operaciones derivados de la especificación | Puede generar muchísimo código y tener limitaciones con ciertos esquemas |
| Cliente HTTPX propio con modelos Pydantic | Control completo y superficie pequeña | Mayor responsabilidad de mantener los contratos |

**Mi preferencia:** un cliente REST propio y ligero como interfaz interna, utilizando modelos tipados derivados de la especificación. Si el generador funciona correctamente con el YAML de Sophos, podemos aprovechar su código generado detrás de esa interfaz.

No haría que el generador expusiera directamente todas sus operaciones como herramientas MCP.

Tampoco mantendría dos definiciones independientes del mismo esquema sin pruebas que detectasen su divergencia.

## B. Cliente REST centralizado

Una única implementación de `SophosRestClient` debería encargarse de:

- Construir la URL base.
- Gestionar `Authorization: Bearer`.
- Serializar y deserializar JSON.
- Validar respuestas.
- Aplicar timeouts.
- Interpretar errores HTTP.
- Registrar diagnósticos sin divulgar credenciales.
- Gestionar las referencias de recursos.

Configuración prevista:

| Variable | Función |
|---|---|
| `SOPHOS_HOST` | Dirección del firewall |
| `SOPHOS_PORT` | Puerto HTTPS de administración |
| `SOPHOS_API_KEY` | Bearer token |
| `SOPHOS_VERIFY_SSL` | Verificación TLS |
| `SOPHOS_CA_BUNDLE` | CA privada, si procede |
| `SOPHOS_TIMEOUT` | Timeout configurable |

Utilizaría `verify=True` por defecto y no permitiría redirecciones automáticas a otros destinos. Las credenciales deben quedar fuera de los mensajes MCP, resultados y registros.

La URL base sigue el formato oficial:

`https://<firewall-host>:<port>/api/firewall-config/v1`

[R01] [R02]

## C. Ciclo de vida del cliente

Esta es una mejora importante sobre la arquitectura actual.

Ahora muchas funciones crean y cierran su propio `SophosFirewallClient`. Eso significa que cada herramienta puede establecer una conexión HTTP independiente.

El SDK Python actual de MCP ofrece `lifespan` para gestionar recursos compartidos durante la vida del servidor.

Lo aprovecharía así:

1. Al arrancar MCP, se crea un único `httpx.AsyncClient`.
2. Se inicializa el cliente Sophos con la configuración validada.
3. Todas las herramientas reutilizan el mismo cliente.
4. Al detenerse el servidor, se cierra el cliente HTTP.

Los handlers recibirían `Context[AppContext]`, utilizando la inyección propia del SDK. Este contexto no aparece como argumento que deba proporcionar el modelo. [R20] [R21]

Esto también permite eliminar el parámetro `client: Any = None` que encontramos en las funciones actuales.

## D. Herramientas MCP de calidad

No copiaría literalmente el diseño actual de herramientas.

El SDK permite utilizar modelos Pydantic, `Annotated`, `Field`, restricciones de valores y enumeraciones para construir los esquemas de entrada. [R20]

Aplicaría estas reglas:

- Nombres claros, en inglés y `snake_case`.
- Una herramienta para una operación de negocio bien delimitada.
- Parámetros explícitos y tipados.
- Enumeraciones para valores como IPv4/IPv6, protocolos y estados.
- Modelos específicos para creación y actualización.
- Descripciones de uso claras, no simples traducciones de los endpoints REST.
- Resultados con esquemas estructurados.
- Identificadores estables para poder reutilizar objetos entre llamadas.

Por ejemplo, no expondría una herramienta genérica que permita ejecutar cualquier petición REST.

Expondría herramientas como:

- `list_firewall_rules`
- `get_firewall_rule`
- `create_firewall_rule`
- `update_firewall_rule`
- `delete_firewall_rule`
- `move_firewall_rule`

Y modelos de entrada distintos cuando IPv4 e IPv6 tengan diferencias reales en sus esquemas.

**Una precisión importante sobre PATCH:** no se debe convertir una actualización parcial en una reconstrucción completa del objeto. La API utiliza JSON Merge Patch, salvo excepciones documentadas. Una propiedad omitida conserva su valor y una propiedad enviada a `null` se elimina. Los arrays requieren especial atención porque normalmente se sustituyen completos. [R18] [R02]

## E. Resultados y errores

No quiero que las herramientas devuelvan diccionarios arbitrarios con respuestas HTTP prácticamente sin procesar.

Propondría modelos de salida con:

- Identificador del objeto.
- Nombre.
- Propiedades relevantes.
- Estado de la operación.
- Información de paginación cuando corresponda.

Utilizaría `outputSchema` y `structuredContent` para que los resultados sean útiles tanto para el modelo como para el cliente MCP. [R22]

También cambiaría el tratamiento de errores.

El SDK diferencia entre:

- `ToolError`: errores de ejecución que el modelo puede entender y eventualmente corregir.
- `MCPError`: errores que deben rechazarse a nivel de protocolo.
- Excepciones inesperadas: errores internos que deben registrarse con sus trazas.

No reproduciría el envoltorio genérico actual que captura prácticamente todas las excepciones con `BaseException`. Usaría el mecanismo de errores del SDK y excepciones propias para los errores conocidos de Sophos. [R20]

Hay un caso que merece especial tratamiento: los timeouts durante una modificación.

Sophos advierte que la ausencia de respuesta no significa que la modificación haya fallado. Por tanto:

- GET puede reintentarse de forma segura.
- POST, PATCH y DELETE no deben repetirse automáticamente ante un resultado ambiguo.
- Después de un timeout de escritura se debe consultar el estado real del objeto antes de intentar de nuevo.

Esto evita duplicar operaciones o dejar una configuración distinta de la esperada. [R03]

# 6. Qué eliminaría del diseño MCP actual

No trasladaría automáticamente todos los componentes actuales.

| Componente | Decisión | Motivo |
|---|---|---|
| `client.py` | Reescribir | Cliente XML |
| `server.py` | Reescribir | Nueva organización y contexto |
| `_guard.py` | Eliminar su envoltorio genérico | Gestión de errores del SDK |
| `_env_guard.py` | Revisar | Mantener solo comprobaciones realmente necesarias |
| `router.py` | Eliminar inicialmente | Complejidad y dependencia adicionales |
| `resources.py` | Rediseñar | Conservar solo recursos útiles |
| `prompts.py` | Revisar | No trasladar prompts que referencien herramientas antiguas |
| `tools/*` | Reconstruir | Los esquemas de entrada y salida cambian |
| `tests/*` | Reescribir | Contratos JSON y REST |

No mantendría el router semántico FastEmbed de momento.

Con un conjunto de herramientas bien diseñado, el descubrimiento nativo de MCP debería ser suficiente. El router introduce un segundo mecanismo de selección, dependencias adicionales, un índice de embeddings y dos herramientas meta.

Solo lo recuperaría si una evaluación con los modelos que realmente utilizas demostrase una mejora relevante.

Lo mismo ocurre con los recursos y prompts: son capacidades de MCP útiles, pero no hay que mantenerlas por el mero hecho de que existiesen en XML.

# 7. Organización de los trabajos

Organizaría la adaptación en cinco fases técnicas, agrupadas en dos issues principales para no fragmentar excesivamente el proyecto.

## Fase 0 · Auditoría y decisiones de diseño

**Objetivo:** conocer completamente el contrato REST antes de implementar herramientas.

Trabajos:

- Parsear el YAML exacto del repositorio.
- Obtener todos los `paths`, métodos, `operationId`, parámetros y esquemas.
- Validar las referencias entre esquemas.
- Identificar operaciones paginadas.
- Identificar autenticación y permisos.
- Documentar funcionalidades disponibles y no soportadas.
- Probar `openapi-python-client` contra el archivo completo.
- Decidir la estrategia definitiva de modelos y cliente.

**Entregables:** `docs/API-COVERAGE.md` y una decisión arquitectónica documentada (ADR).

**Criterio de salida:** no queda ninguna duda sobre qué operaciones REST se implementarán en la primera versión.

## Fase 1 · Nueva infraestructura REST

**Objetivo:** construir una base limpia y fiable.

Trabajos:

- Crear configuración tipada.
- Implementar `SophosRestClient`.
- Implementar autenticación Bearer.
- Implementar TLS y timeouts.
- Centralizar el tratamiento de errores.
- Crear modelos de petición y respuesta.
- Integrar el cliente con el `lifespan` MCP.
- Eliminar el transporte XML y dependencias antiguas.

**Entregables:** cliente REST funcional y probado, sin herramientas XML ni compatibilidad heredada.

**Criterio de salida:** conexión real y operaciones REST básicas verificadas con el firewall.

## Fase 2 · Reconstrucción de herramientas MCP

**Objetivo:** implementar los dominios funcionales.

Orden de implementación:

1. **Firewall Rules:** lectura, creación, modificación, eliminación, ordenación y soporte IPv4/IPv6.
2. **Network Objects y Services:** IPv4, IPv6, FQDN, grupos, servicios y grupos de servicios.
3. **NAT Rules:** CRUD, IPv4/IPv6 y gestión del orden de reglas cuando corresponda.
4. **Users y Sessions:** usuarios de red, listados paginados, sesiones activas y desconexiones.
5. **VPN y Network Interfaces:** conexiones IPsec, estado de conexiones, políticas SSL VPN compatibles e interfaces.

**Entregable:** conjunto coherente de herramientas MCP con contratos tipados y operaciones realmente implementadas.

**Criterio de salida:** todas las herramientas anunciadas funcionan contra los endpoints oficiales y respetan sus esquemas.

## Fase 3 · Seguridad y calidad MCP

**Objetivo:** garantizar que un agente no pueda interpretar incorrectamente una operación ni provocar cambios imprevistos.

Trabajos:

- Revisar todas las anotaciones MCP.
- Validar argumentos antes de realizar peticiones.
- Evitar exposición de secretos.
- Aplicar permisos mínimos.
- Comprobar actualizaciones parciales.
- Proteger operaciones destructivas.
- Comprobar paginación y resultados parciales.
- Validar schemas MCP y resultados estructurados.
- Ejecutar pruebas mediante MCP Inspector.

**Entregable:** servidor MCP con herramientas verificadas y comportamiento consistente.

**Criterio de salida:** herramientas, errores, anotaciones y resultados validados desde un cliente MCP real.

## Fase 4 · Limpieza y publicación

**Objetivo:** dejar el proyecto listo para su uso habitual.

Trabajos:

- Actualizar Dockerfile y Docker Compose.
- Revisar imagen GHCR.
- Unificar dependencias y lockfile.
- Actualizar `.env.example`.
- Actualizar README y documentación.
- Actualizar CHANGELOG.
- Corregir pipelines de seguridad.
- Ejecutar pruebas completas.
- Publicar versión nueva.

**Entregable:** versión REST lista para desplegar.

# 8. Cómo dividiría el trabajo en GitHub

No crearía decenas de issues. Utilizaría dos issues principales con checklists internos.

## Issue 1 — Replace XML API integration with a typed Sophos REST foundation

Contenido:

- Auditoría de OpenAPI y ADR.
- Selección de estrategia de generación de modelos.
- Configuración y autenticación REST.
- Cliente HTTP compartido.
- Gestión de errores y timeouts.
- Integración de `lifespan`.
- Eliminación completa de XML.
- Pruebas del cliente.

**Infraestructura.**

## Issue 2 — Rebuild Sophos Firewall MCP tools using the REST API

Contenido:

- Reconstrucción de los dominios funcionales.
- Modelos Pydantic y esquemas MCP.
- Implementación de operaciones CRUD.
- IPv4 e IPv6 donde corresponda.
- Paginación y referencias UUID/nombre.
- Seguridad de las herramientas.
- Pruebas de integración MCP.
- Docker, documentación y publicación.

**Funcionalidad.**

El segundo issue dependerá de las decisiones y contratos establecidos en el primero.

Los PR deberían ser revisables: primero infraestructura, después herramientas de lectura, después modificaciones y finalmente empaquetado. No agruparía todas las funcionalidades en un único PR enorme.

# 9. Pruebas y criterios de aceptación

No repetiría el enfoque de considerar que un alto porcentaje de tests unitarios equivale a una implementación fiable.

El proyecto tiene pruebas XML bastante amplias, pero eso no demuestra que el nuevo cliente REST funcione.

Necesitamos diferentes niveles:

| Tipo | Qué debe demostrar |
|---|---|
| OpenAPI validation | La especificación es válida y sus referencias se resuelven |
| API client tests | Métodos, URLs, headers, parámetros y JSON correctos |
| Model tests | Validación de peticiones y respuestas |
| Domain tests | Comportamiento de cada operación |
| Error tests | 400, 401, 403, 404, 409, 500 y errores de red |
| Security tests | Credenciales ocultas y TLS seguro |
| MCP schema tests | Argumentos, anotaciones y resultados |
| Integration tests | Comportamiento real contra Sophos |
| MCP Inspector | Inicialización, listado de herramientas y ejecución |

Prestaría especial atención a tres escenarios:

1. Una regla de firewall creada correctamente debe poder recuperarse y modificarse sin alterar otras propiedades.
2. Una modificación que termina en timeout no debe repetirse automáticamente.
3. Las herramientas no deben revelar propiedades sensibles de respuestas de Sophos, aunque la API las incluya.

Para el cliente MCP utilizaría MCP Inspector y pruebas con el cliente oficial Python. La documentación actual recomienda comprobar inicialización, herramientas anunciadas, esquemas, resultados, errores y autorizaciones. [R23] [R20]

La integración real debe probarse con el firmware del firewall que se vaya a utilizar, no únicamente con respuestas simuladas.

# 10. Aspectos de seguridad y despliegue

La nueva autenticación modifica también los requisitos operativos.

Sophos establece que:

- El acceso REST está desactivado por defecto.
- Hay que habilitarlo y permitir las IP de origen.
- Cada API Key hereda los permisos del administrador que la genera.
- Las claves tienen una vigencia de un año.
- Se recomienda crear una cuenta dedicada con permisos mínimos y no utilizar el administrador principal.

Esto debe quedar documentado en el README y en `.env.example`. [R03] [R04]

También aprovecharía esta transición para resolver inconsistencias existentes:

- `pyproject.toml` requiere MCP 2.x, mientras que `requirements.txt` mantiene la restricción anterior a MCP 2.
- El pipeline de seguridad analiza `requirements.txt`, aunque la instalación de producción utiliza `pyproject.toml`.
- El Dockerfile instala las dependencias opcionales de FastEmbed que dejarían de ser necesarias.
- El `.env.example` recomienda desactivar TLS, aunque el código actual utiliza verificación habilitada por defecto.
- Docker Compose habilita TTY mientras que el README advierte que no se debe utilizar TTY para comunicaciones MCP mediante stdio.

Son aspectos que merece la pena corregir aprovechando el rediseño, no trasladar a la nueva implementación.

# 11. Riesgos y decisiones pendientes

## Especificación completa

**Pendiente de validación.**

El YAML está en GitHub, pero su tamaño (8,9 MB) ha impedido recuperar su contenido íntegro mediante la conexión disponible durante esta revisión. He contrastado las familias principales con el portal oficial, cuya referencia documenta OpenAPI 3.0, versión 1.0.0. No he podido confirmar que el `info.version` del archivo concreto del repositorio sea exactamente ese, ni calcular el inventario completo de operaciones. La fase 0 debe resolverlo.

## Compatibilidad con el firmware instalado

**Pendiente de prueba real.**

Hay que confirmar qué operaciones están disponibles en la versión concreta de SFOS que utilizaremos y qué restricciones impone el perfil de administrador.

## Generación de código

**Decisión técnica en fase 0.**

No conviene comprometerse a generar automáticamente un SDK gigantesco sin probar antes la calidad del resultado con el OpenAPI de Sophos.

## Alcance funcional

**Definir en ADR.**

No incluiría todos los módulos de Sophos en la primera entrega. Empezaría por los dominios actuales y las ampliaciones que tengan sentido para administrar el firewall.

# 12. Mi propuesta definitiva

Tomaría estas decisiones como base del proyecto:

| Decisión | Propuesta |
|---|---|
| API | Exclusivamente REST |
| XML | Eliminado |
| Compatibilidad heredada | Ninguna |
| OpenAPI | Fuente de verdad |
| Transporte | HTTPX asíncrono |
| Modelos | Pydantic tipado |
| Cliente HTTP | Compartido mediante lifespan |
| MCP | SDK Python MCP 2.x |
| Herramientas | Manuales, especializadas y bien delimitadas |
| Salidas | Esquemas estructurados |
| Router semántico | Eliminar inicialmente |
| Raw API | No exponer |
| Seguridad | API Key, TLS y mínimo privilegio |
| Pruebas | Unitarias, contractuales e integración real |
| Organización | Dos issues principales |

## Conclusión

**La prioridad no debería ser recuperar cuanto antes las 28 herramientas antiguas. Debería ser construir una base REST correcta y después implementar un conjunto de herramientas MCP que represente bien las capacidades reales de Sophos.**

Esto evitará reproducir las limitaciones del código anterior y permitirá aprovechar las funcionalidades que aparecen por primera vez en la API REST.

**No se han realizado cambios de implementación ni se han abierto issues como parte de este plan.** El resultado de este análisis es la guía técnica para organizar esos trabajos.
