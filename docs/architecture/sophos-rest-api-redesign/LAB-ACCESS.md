# Acceso al laboratorio — Sophos Firewall (API REST)

> ⚠️ **Security notice (15 Nov 2026, amended 17 Nov 2026).** A previous lab API key was committed in
> clear text in this file while the repository was public. It must be considered **compromised** and
> rotated on the appliance. The value was removed from the working tree on 15 Nov 2026; it remains in
> the git history, so rotation — not deletion — is the remediation. Never commit a key again: provide
> it through `SOPHOS_API_KEY` / `SOPHOS_API_KEY_FILE` or the `live-lab` environment secrets.
>
> **The credential in use is not read-only.** On 16 Nov 2026 the active lab key was used to create and
> then delete a disposable MAC address object, which demonstrates write capability at that time. See
> [api-write-capability-2026-11-16.md](../live-evidence/api-write-capability-2026-11-16.md). The
> earlier "read-only" characterisation in this file was an inference from the administrator profile
> name and is withdrawn.

**Estado:** credencial de laboratorio compartida para verificación en vivo. **Su alcance de permisos
no está verificado y su capacidad de escritura está demostrada.**  
**Última verificación:** 16 de noviembre de 2026 (capacidad de escritura, ver
[api-write-capability-2026-11-16.md](../live-evidence/api-write-capability-2026-11-16.md)); el smoke
test de solo lectura del 15 de noviembre sigue siendo válido para lo que probó
([api-smoke-2026-11-15.md](../live-evidence/api-smoke-2026-11-15.md)).  
**Decisión del propietario:** la credencial **no** se guarda en el repositorio. Se proporciona por `SOPHOS_API_KEY` / `SOPHOS_API_KEY_FILE` o por los secretos del entorno `live-lab`. La clave anterior quedó expuesta y **debe rotarse**.

> ⚠️ **Alcance:** **no** se ha verificado que la clave pertenezca a un administrador de solo lectura, y
> el 16 de noviembre se demostró que puede escribir. Tratar la credencial como **lectura y escritura**
> hasta que el propietario aporte evidencia de la consola. No ejecutar escrituras, mutaciones, bulk
> delete, desconexiones ni cambios de interfaz/VPN sin aprobación explícita del propietario y un plan
> de prueba con objetos desechables. La contención real es la rotación, no el perfil del administrador.

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
| Modelo | **SFVH** (instalación virtual, no appliance físico) |
| Build SFOS | **SFOS 23.0.0 GA-Build371** (proporcionado por el propietario; la API no expone endpoint de versión). La API REST de configuración es la misma en todas las versiones de SFOS, así que las herramientas no dependen del build. |

## Credencial

| Campo | Valor |
|---|---|
| API key | `<REDACTED — ask the owner>` |
| Cabecera | `Authorization: Bearer <REDACTED — ask the owner>` |
| Administrador asociado | **No verificado.** `admin_mcp` (perfil mostrado como "Read only Admin") es una inferencia anterior: la API no expone qué administrador creó la clave y nadie ha comprobado la asociación en la consola |
| Permisos | **Escritura demostrada el 16 nov 2026** (objeto MAC desechable creado y borrado). El alcance efectivo por módulo no está verificado |
| Rotación | Manual, por el propietario. Si la clave deja de funcionar: 401 `unauthenticated`; pedir una nueva |

### Estado de la credencial (tres hechos distintos, no confundirlos)

| Hecho | Estado | Evidencia |
|---|---|---|
| La clave anterior quedó expuesta en el historial público de Git | **Confirmado** | Commit histórico; el valor se retiró del árbol de trabajo el 15 nov 2026 |
| La clave activa puede **escribir** | **Demostrado el 16 nov 2026** | [api-write-capability-2026-11-16.md](../live-evidence/api-write-capability-2026-11-16.md) |
| La clave expuesta ha sido revocada | **No verificado** | Sin evidencia de revocación en el repositorio |
| El administrador propietario y su perfil efectivo | **No verificado** | Requiere la consola del firewall; la API no lo expone |

Mientras las dos últimas filas sigan sin verificar, este documento **no** puede afirmar que la
exposición esté contenida. La rotación es la acción de contención y corresponde al propietario.

## Variables de entorno

```bash
export SOPHOS_HOST=10.10.10.1
export SOPHOS_PORT=443
export SOPHOS_API_KEY='<REDACTED — ask the owner>'
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

1. La credencial no se guarda en el repositorio. La clave anterior quedó expuesta en el historial público y **debe rotarse**; no reutilizarla en producción ni en otro entorno.
2. No incluirla en imágenes Docker, artefactos de release, logs de CI ni capturas.
3. **No asumir que la clave es de solo lectura.** El 16 nov 2026 se demostró que puede escribir. No ejecutar operaciones de escritura sin aprobación explícita del propietario y un plan con objetos desechables; cualquier escritura no autorizada debe considerarse fuera de alcance.
4. La clave anterior debe rotarse **ahora**; actualizar este documento y `docs/live-evidence/` cuando ocurra, registrando la fecha de revocación, el administrador verificado y el alcance de permisos — **nunca** el material de la clave.
5. La rotación es la contención. Cambiar el nombre del perfil del administrador no demuestra nada: la API no expone la asociación clave↔administrador y el perfil debe comprobarse en la consola.
