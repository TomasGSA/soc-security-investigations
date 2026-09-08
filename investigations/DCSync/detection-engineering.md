# Detection Engineering: actividad DCSync

## 1. Objetivo

Diseñar una detección de alta fidelidad para identificar solicitudes de replicación de Active Directory desde cuentas o sistemas no autorizados, evitando alertas generadas únicamente por la presencia textual de un GUID dentro de un descriptor de seguridad.

## 2. Problema encontrado

Una búsqueda amplia del GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` devolvió eventos `5136` porque el GUID estaba incluido dentro de `nTSecurityDescriptor`.

La lógica inicial no distinguía entre:

```text
GUID almacenado dentro de una ACL
```

Y:

```text
GUID incluido en Properties de un evento 4662 con AccessMask 0x100
```

Esto puede producir falsos positivos cuando Active Directory actualiza o normaliza descriptores de seguridad.

## 3. Fuentes de datos requeridas

### Obligatorias

- Windows Security Event Log en todos los controladores de dominio.
- Event ID `4662`.
- Event ID `4624` para correlación de sesión.
- Inventario actualizado de nombres e IP de controladores de dominio.

### Recomendadas

- Event ID `5136` para cambios de permisos.
- Telemetría EDR del sistema origen.
- Tráfico RPC/MS-DRSR.
- Registros de firewall o NDR.
- Inventario de cuentas y aplicaciones con derechos de replicación delegados.

## 4. Requisitos de auditoría

La detección basada en `4662` depende de:

1. Habilitar `Audit Directory Service Access` en los controladores de dominio.
2. Configurar una SACL adecuada sobre los objetos relevantes.
3. Recopilar el canal Security sin pérdida relevante de eventos.
4. Extraer correctamente `SubjectUserName`, `SubjectLogonId`, `ObjectType`, `ObjectName`, `AccessMask` y `Properties`.

La falta de resultados no debe tratarse como prueba de ausencia hasta validar estos controles.

## 5. Lógica recomendada

### Condiciones principales

- `EventCode=4662`.
- `AccessMask=0x100`.
- `Properties` contiene al menos un GUID de replicación.
- El objeto corresponde al dominio o contexto de nombres relevante.
- La identidad o la fuente no pertenece al conjunto autorizado.

### GUID supervisados

```text
1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
89e95b76-444d-4c62-991a-0facbeda640c
```

## 6. Consulta base de Splunk

```spl
index=* EventCode=4662 earliest=-15m
(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    OR "89e95b76-444d-4c62-991a-0facbeda640c"
)
| eval dc=coalesce(ComputerName, host, dest)
| eval requester=coalesce(SubjectUserName, Account_Name, user, src_user)
| eval requester_domain=coalesce(SubjectDomainName, Account_Domain)
| eval logon_id=coalesce(SubjectLogonId, Subject_Logon_ID, Logon_ID)
| eval access_mask=lower(coalesce(AccessMask, Access_Mask))
| eval object_type=coalesce(ObjectType, Object_Type)
| where access_mask="0x100" OR like(_raw, "%Access Mask:%0x100%")
| table _time dc requester_domain requester logon_id object_type
        ObjectName access_mask Properties
```

## 7. Correlación con eventos 4624

La detección debe enriquecer el `SubjectLogonId` del `4662` con el evento `4624` correspondiente.

Campos de interés:

- `TargetUserName`.
- `TargetDomainName`.
- `TargetLogonId`.
- `IpAddress`.
- `WorkstationName`.
- `LogonType`.
- `AuthenticationPackageName`.
- `ProcessName`.

Consulta de investigación:

```spl
index=* EventCode=4624 earliest=[EARLIEST] latest=[LATEST]
| eval logon_id=coalesce(TargetLogonId, Target_Logon_ID, SubjectLogonId,
                          Subject_Logon_ID, Logon_ID)
| where lower(logon_id)=lower("[LOGON_ID]")
| table _time host TargetDomainName TargetUserName logon_id LogonType
        IpAddress WorkstationName AuthenticationPackageName ProcessName
| sort 0 _time
```

## 8. Enriquecimiento por inventario

Mantener una lookup con fuentes autorizadas:

```text
hostname,ip,asset_type,domain,authorized_replication,owner
```

Ejemplo conceptual:

```spl
| lookup ad_authorized_replication_sources hostname as source_host
    OUTPUT authorized_replication owner asset_type
| eval authorized_replication=coalesce(authorized_replication, "false")
| where authorized_replication!="true"
```

No se recomienda excluir automáticamente todas las cuentas terminadas en `$`. Una cuenta de equipo comprometida o un servidor no DC también puede disponer indebidamente de derechos de replicación.

## 9. Exclusiones seguras

Las exclusiones deben exigir varias condiciones:

- Cuenta de equipo esperada.
- Host origen presente en inventario.
- IP dentro del conjunto autorizado.
- Sistema clasificado como controlador de dominio o servicio aprobado.
- Actividad dentro de un patrón temporal o operacional conocido.

### Exclusión no recomendada

```spl
| search NOT SubjectUserName="*$"
```

Esta exclusión puede ocultar cuentas de equipo no autorizadas.

### Enfoque recomendado

```spl
| lookup authorized_dc_inventory hostname as source_host
    OUTPUT is_domain_controller authorized_ip
| where is_domain_controller!="true" OR source_ip!=authorized_ip
```

## 10. Supresiones de falsos positivos

No generar una alerta DCSync cuando se cumplan únicamente estas condiciones:

- `EventCode=5136`.
- `AttributeLDAPDisplayName=nTSecurityDescriptor`.
- El GUID se encuentra dentro de `AttributeValue` o `Value`.
- El objeto pertenece a `dnsNode`, `MicrosoftDNS` o `DomainDnsZones`.
- No existe un `4662` relacionado que demuestre el ejercicio del derecho.

Los eventos `5136` pueden alimentar una detección distinta para **cambios en permisos de replicación**, pero no deben mezclarse con la detección de ejecución DCSync.

## 11. Detecciones separadas recomendadas

### Regla A: solicitud de replicación desde origen no autorizado

**Severidad:** alta o crítica.

Condiciones:

- Evento `4662` compatible.
- Derecho de replicación ejercido.
- IP o host origen no incluido en inventario de DC o aplicaciones autorizadas.

### Regla B: cuenta de usuario ejerce derechos de replicación

**Severidad:** crítica, salvo cuenta de servicio expresamente autorizada.

Condiciones:

- Evento `4662` compatible.
- `SubjectUserName` no es una cuenta de DC autorizada.
- Correlación con `4624` disponible.

### Regla C: modificación de derechos de replicación

**Severidad:** alta.

Condiciones:

- Evento `5136` sobre `nTSecurityDescriptor` del objeto de dominio.
- Diferencia entre valor anterior y nuevo.
- Se añade una ACE que concede uno de los GUID de replicación.
- Principal beneficiario no está autorizado.

Esta regla detecta la preparación o delegación del privilegio, no el ejercicio de DCSync.

## 12. Puntuación de riesgo sugerida

| Condición | Puntos |
|---|---:|
| `4662` con GUID de replicación y `AccessMask=0x100` | 40 |
| Origen no DC | 30 |
| Cuenta de usuario interactiva | 20 |
| Cuenta no incluida en lista autorizada | 20 |
| Evidencia EDR de herramienta asociada | 40 |
| Tráfico RPC/MS-DRSR desde estación de trabajo | 30 |
| Solo coincidencia en `5136/nTSecurityDescriptor` | -40 |

Orientación:

- `80+`: crítica.
- `50-79`: alta.
- `30-49`: media e investigación requerida.
- `<30`: informativa o evento de contexto.

## 13. Pruebas de validación

Antes de desplegar la regla:

- Confirmar que existen eventos `4662` reales en el entorno.
- Validar los nombres exactos de campos en eventos XML y normalizados.
- Probar contra replicación legítima entre DC.
- Probar con una cuenta autorizada de sincronización, si existe.
- Confirmar que los eventos `5136` con GUID dentro de ACL no disparan la regla DCSync.
- Medir volumen, cardinalidad y tasa de falsos positivos.
- Validar la correlación de Logon ID teniendo en cuenta reinicios y ventanas largas.
- Revisar retrasos de ingestión y diferencias de zona horaria.

## 14. Información de alerta recomendada

La alerta debe mostrar:

```text
Timestamp
Destination domain controller
Requester account and domain
Subject Logon ID
Source IP and workstation
Logon type
Object type and object name
Replication GUID detected
Access mask
Authorization status
Asset classification
Related endpoint evidence
Detection version
```

## 15. Métricas operativas

- Porcentaje de DC con cobertura `4662`.
- Número de fuentes autorizadas de replicación.
- Alertas por cuenta y origen.
- Porcentaje de alertas correlacionadas con `4624`.
- Tasa de falsos positivos.
- Tiempo medio de clasificación.
- Cambios de ACL con derechos de replicación detectados.
