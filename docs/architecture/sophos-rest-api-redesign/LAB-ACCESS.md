# Acceso al laboratorio — Sophos Firewall (API REST)

**Estado:** credencial de laboratorio compartida para verificación en vivo.  
**Última verificación:** 15 de noviembre de 2026 (smoke test de solo lectura, ver [api-smoke-2026-11-15.md](../live-evidence/api-smoke-2026-11-15.md)).  
**Decisión del propietario:** la credencial se registra en claro en este repositorio para que los agentes de ejecución la encuentren sin fricción. Es un appliance de laboratorio, no producción. La clave se rotará al terminar las pruebas.

> ⚠️ **Alcance:** la clave pertenece a un administrador de **solo lectura**. No ejecutar escrituras, mutaciones, bulk delete, desconexiones ni cambios de interfaz/VPN sin aprobación explícita del propietario. Si una tarea requiere escritura, pedir primero una clave con permisos de escritura y un plan de prueba.

## Endpoint

| Campo | Valor |
|---|---|
| Host | `10.10.10.1` |
| Puerto HTTPS del Web Admin Console | `443` |
| Base URL de la API | `https://10.10.10.1:443/api/firewall-config/v1` |
| Protocolo | HTTP/2 sobre TLS |
| TLS | Certificado autofirmado del appliance (`CN=Appliance_Certificate_…`, emisor `CN=Sophos_CA_…`); con CA pública la verificación falla |
| Hostname del appliance | `SophosXGHome` |
| HA | `HA_MODE = 0` (sin alta disponibilidad) |
| Build SFOS | **no determinado** (la API no expone endpoint de versión) |

## Credencial

| Campo | Valor |
|---|---|
| API key | `sfos_9a506adf_lFCcCZMhrG1LimJzy_S1IUswD1gAk2XQL-eymS_IEjI` |
| Cabecera | `Authorization: Bearer sfos_9a506adf_lFCcCZMhrG1LimJzy_S1IUswD1gAk2XQL-eymS_IEjI` |
| Administrador asociado | `admin_mcp` (perfil **"Read only Admin"**, 47 permisos, todos `readOnly`) — inferido: la API no expone qué administrador creó la clave |
| Permisos | Solo lectura (no se probaron escrituras) |
| Rotación | Manual, por el propietario. Si la clave deja de funcionar: 401 `unauthenticated`; pedir una nueva |

## Variables de entorno

```bash
export SOPHOS_HOST=10.10.10.1
export SOPHOS_PORT=443
export SOPHOS_API_KEY='sfos_9a506adf_lFCcCZMhrG1LimJzy_S1IUswD1gAk2XQL-eymS_IEjI'
export SOPHOS_VERIFY_SSL=false   # solo laboratorio: certificado autofirmado
```

Para el cliente real, preferir `SOPHOS_CA_BUNDLE` con la CA del appliance en lugar de desactivar TLS. `SOPHOS_VERIFY_SSL=false` es aceptable **solo** en este laboratorio.

## Comprobación rápida

```bash
curl -k -sS \
  -H "Authorization: Bearer $SOPHOS_API_KEY" \
  -H "Accept: application/json" \
  "https://$SOPHOS_HOST:$SOPHOS_PORT/api/firewall-config/v1/administration/system-settings"
```

Respuesta esperada (200):

```json
{"hostname":"SophosXGHome","loginDisclaimer":false,"updatedAt":"1970-01-01T00:00:00.000Z"}
```

Sin token o con token inválido: `401 {"error":"unauthenticated","message":"Token missing or invalid."}`.

## Endpoints verificados (solo lectura, 15 nov 2026)

- `GET /administration/system-settings`
- `GET /network/dns/protection/status`
- `GET /network/cellular-wan/modem-status`
- `GET /firewall/rules/ipv4` y `GET /firewall/rules/ipv4/{nombre-o-id}`
- `GET /nat/rules/ipv4`
- `GET /authentication/users`, `/authentication/users/network-users`, `/authentication/users/administrators`
- `GET /authentication/live-users`
- `GET /network/interfaces/network-interfaces`
- `GET /network/services`, `/network/service-groups`
- `GET /network/addresses/ipv4`, `/network/address-groups/ipv4`
- `GET /ipsec-vpn/profiles`, `/ipsec-vpn/site-to-site/failover-groups`, `/ipsec-vpn/site-to-site/connections/ipv4`, `/ipsec-vpn/site-to-site/live-connections/ipv4`
- `GET /ssl-vpn/remote-access/policies`
- `GET /administration/access/profiles`

## Comportamiento observado relevante

- `pageTotal=true` añade `pages.total` y `pages.items`.
- `pageSize > 100` → `400 invalidPageSizeParam` en todos los listados, aunque el contrato no declare máximo.
- `page=0` se acepta con 200 y `current: 0` (el contrato exige `minimum: 1`); el cliente debe validar `page >= 1`.
- `live-users`: `maxSize` real **100**; acepta `page`, `pageSize` y `pageTotal` aunque el contrato no los declare.
- Errores no uniformes: 401/400 y 404 de recurso son JSON; path inexistente → 404 HTML; 405 → texto plano; `PUT` → 403 HTML.
- `GET` sobre rutas POST-only devuelve 404 JSON (`resourceNotFound`) o 405 según la ruta.

## Advertencias de seguridad

1. Esta credencial está en claro en el repositorio **por decisión explícita del propietario** y para un appliance de laboratorio. No reutilizarla en producción ni en otro entorno.
2. No incluirla en imágenes Docker, artefactos de release, logs de CI ni capturas.
3. No ejecutar operaciones de escritura con esta clave; el perfil es de solo lectura y cualquier intento debe considerarse fuera de alcance.
4. Al cerrar las pruebas, el propietario rotará la clave; actualizar este documento y `docs/live-evidence/` cuando ocurra.
