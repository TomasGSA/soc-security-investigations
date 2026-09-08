# Playbook: investigación de posible DCSync

## 1. Objetivo

Determinar si una alerta o búsqueda relacionada con derechos de replicación de Active Directory representa:

- Un DCSync malicioso.
- Replicación legítima entre controladores de dominio.
- Actividad de una aplicación autorizada.
- Un cambio de permisos.
- Una coincidencia del GUID dentro de una ACL.
- Un caso inconcluso por falta de telemetría.

## 2. Datos requeridos

Completar antes de iniciar:

```text
Ventana temporal: [EARLIEST] a [LATEST]
Dominio: [DOMAIN]
DN del dominio: [DOMAIN_DN]
Controladores de dominio: [DC_HOSTNAMES]
IPs de controladores: [DC_IPS]
Cuenta observada: [ACCOUNT]
Logon ID: [LOGON_ID]
Host origen: [SOURCE_HOST]
IP origen: [SOURCE_IP]
Índice / sourcetype: [INDEX] / [SOURCETYPE]
```

## 3. Flujo operativo

### Paso 1: validar cobertura de Event ID 4662

```spl
index=* EventCode=4662 earliest=-24h
| stats count min(_time) as first_seen max(_time) as last_seen
    by host ComputerName source sourcetype
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

**Interpretación:**

- Resultados presentes: continuar con la investigación.
- Cero resultados en todos los DC: validar auditoría, SACL e ingestión.
- Resultados solo en algunos DC: registrar brecha de cobertura.

### Paso 2: buscar los derechos de replicación

```spl
index=* EventCode=4662 earliest=[EARLIEST] latest=[LATEST]
(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    OR "89e95b76-444d-4c62-991a-0facbeda640c"
)
| eval dc=coalesce(ComputerName, host, dest)
| eval account=coalesce(SubjectUserName, Account_Name, user, src_user)
| eval account_domain=coalesce(SubjectDomainName, Account_Domain)
| eval logon_id=coalesce(SubjectLogonId, Subject_Logon_ID, Logon_ID)
| table _time dc account_domain account logon_id ObjectServer ObjectType
        ObjectName AccessMask Properties _raw
| sort 0 _time
```

Revisar:

- `Properties`.
- `AccessMask`.
- `ObjectType`.
- `ObjectName`.
- `SubjectUserName`.
- `SubjectLogonId`.

### Paso 3: validar Control Access

```spl
index=* EventCode=4662 earliest=[EARLIEST] latest=[LATEST]
(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    OR "89e95b76-444d-4c62-991a-0facbeda640c"
)
| eval access_mask=lower(coalesce(AccessMask, Access_Mask))
| eval object_type=coalesce(ObjectType, Object_Type)
| where access_mask="0x100" OR like(_raw, "%Access Mask:%0x100%")
| table _time host SubjectDomainName SubjectUserName SubjectLogonId
        object_type ObjectName access_mask Properties
| sort 0 _time
```

Una coincidencia de GUID sin `4662`, sin `Properties` y sin `AccessMask=0x100` no debe considerarse confirmación de DCSync.

### Paso 4: identificar la cuenta

Clasificar la identidad como:

- Cuenta de controlador de dominio.
- Cuenta de equipo no DC.
- Cuenta de usuario.
- Cuenta de servicio.
- `SYSTEM`.
- Identidad desconocida.

Validar:

- Propietario de la cuenta.
- Grupos privilegiados.
- Derechos de replicación delegados.
- Antigüedad y cambios recientes.
- Uso esperado.
- Incidentes relacionados.

### Paso 5: correlacionar el Logon ID

```spl
index=* EventCode=4624 earliest=[EARLIEST] latest=[LATEST]
| eval logon_id=coalesce(TargetLogonId, Target_Logon_ID, SubjectLogonId,
                          Subject_Logon_ID, Logon_ID)
| where lower(logon_id)=lower("[LOGON_ID]")
| table _time host ComputerName TargetDomainName TargetUserName logon_id
        LogonType IpAddress WorkstationName AuthenticationPackageName ProcessName
| sort 0 _time
```

Ampliar la ventana si la sesión es de larga duración. Los Logon ID son locales al sistema y pueden reutilizarse después de un reinicio.

### Paso 6: validar el origen

Comparar `IpAddress` y `WorkstationName` contra:

- Inventario de controladores de dominio.
- Jump servers administrativos.
- Plataformas IAM.
- Soluciones de respaldo.
- Herramientas de sincronización.
- Aplicaciones con replicación delegada.

Un origen no DC eleva significativamente el riesgo.

### Paso 7: buscar actividad del endpoint

Buscar en EDR procesos y comandos relacionados con:

```text
mimikatz
lsadump::dcsync
secretsdump
impacket
drsuapi
DsGetNCChanges
```

Consulta SIEM genérica:

```spl
index=* earliest=[EARLIEST] latest=[LATEST]
(
    "mimikatz" OR "lsadump::dcsync" OR "secretsdump"
    OR "impacket" OR "drsuapi" OR "DsGetNCChanges"
)
| table _time host user process_name Image CommandLine ParentImage src_ip dest_ip
| sort 0 _time
```

La ausencia de un nombre de herramienta no descarta DCSync. La técnica puede realizarse mediante código o herramientas renombradas.

### Paso 8: revisar tráfico de red

Buscar:

- RPC desde el origen hacia un DC.
- MS-DRSR o `DsGetNCChanges`.
- Comunicación desde estaciones de trabajo hacia servicios de replicación.
- Volumen o frecuencia anómalos.
- Conexiones coincidentes temporalmente con el `4662`.

### Paso 9: revisar eventos 5136

```spl
index=* EventCode=5136 earliest=[EARLIEST] latest=[LATEST]
| eval ldap_attribute=coalesce(AttributeLDAPDisplayName, LDAP_Display_Name)
| where ldap_attribute="nTSecurityDescriptor"
| eval object_dn=coalesce(ObjectDN, DN)
| eval object_class=coalesce(ObjectClass, Class)
| eval change_type=coalesce(OperationType, Change_Type)
| eval correlation_id=coalesce(OpCorrelationID, Correlation_ID)
| table _time host SubjectDomainName SubjectUserName SubjectLogonId
        object_dn object_class change_type correlation_id AttributeValue Value
| sort 0 _time
```

Determinar si el GUID:

- Ya estaba presente en el descriptor anterior.
- Fue añadido en el nuevo descriptor.
- Fue eliminado.
- Aparece en ambos valores por normalización o reordenación.

### Paso 10: agrupar los cambios 5136

```spl
index=* EventCode=5136 earliest=[EARLIEST] latest=[LATEST]
| eval ldap_attribute=coalesce(AttributeLDAPDisplayName, LDAP_Display_Name)
| where ldap_attribute="nTSecurityDescriptor"
| eval object_dn=coalesce(ObjectDN, DN)
| eval object_class=coalesce(ObjectClass, Class)
| eval change_type=coalesce(OperationType, Change_Type)
| eval correlation_id=coalesce(OpCorrelationID, Correlation_ID)
| eval descriptor=coalesce(AttributeValue, Value)
| stats min(_time) as first_seen max(_time) as last_seen
        values(change_type) as operations values(descriptor) as descriptors
        values(SubjectUserName) as accounts values(SubjectLogonId) as logon_ids
        count by host correlation_id object_dn object_class
| convert ctime(first_seen) ctime(last_seen)
| sort 0 first_seen
```

## 4. Árbol de decisión

1. **¿Existe Event ID 4662?**
   - Sí: continuar.
   - No: validar cobertura antes de concluir.

2. **¿El GUID aparece en `Properties` y existe `AccessMask=0x100`?**
   - Sí: posible ejercicio de derecho de replicación.
   - No: revisar si se trata de una coincidencia textual o cambio de ACL.

3. **¿El objeto corresponde al dominio?**
   - Sí: aumenta la relevancia.
   - No: revisar la finalidad del objeto y no asumir DCSync.

4. **¿La cuenta está autorizada?**
   - Sí: validar el sistema origen y el cambio o tarea.
   - No: escalar.

5. **¿El origen es un DC autorizado?**
   - Sí: posible replicación legítima.
   - No: tratar como actividad de alto riesgo.

6. **¿Existe evidencia EDR o de red adicional?**
   - Sí: priorizar contención.
   - No: mantener investigación hasta resolver identidad y origen.

## 5. Criterios de clasificación

### Malicioso o confirmado

- `4662` compatible con replicación.
- Cuenta o sistema no autorizado.
- Origen no DC.
- Evidencia contextual adicional.

### Sospechoso

- `4662` compatible.
- Identidad u origen sin validar.
- Cobertura parcial de telemetría.

### Legítimo

- Fuente autorizada.
- Cuenta esperada.
- Operación validada por el propietario.
- Sin indicadores adicionales.

### Falso positivo

- El GUID aparece únicamente dentro de `nTSecurityDescriptor` en un `5136`.
- No existe evidencia de ejercicio del derecho.
- La actividad corresponde a objetos o procesos administrativos esperados.

### Inconcluso

- No existen eventos suficientes.
- No está validada la cobertura de `4662`.
- No puede determinarse el origen.

## 6. Acciones si se confirma actividad maliciosa

- Aislar el sistema origen cuando sea operacionalmente viable.
- Deshabilitar o restringir la cuenta implicada mediante el procedimiento de emergencia.
- Revocar derechos de replicación no autorizados.
- Preservar eventos, memoria, EDR y tráfico de red.
- Buscar uso posterior de credenciales o tickets.
- Revisar cambios de grupos privilegiados, cuentas y persistencia.
- Coordinar con Active Directory e Incident Response la recuperación de credenciales.
- No realizar rotaciones críticas improvisadas sin un plan de recuperación de dominio.

## 7. Checklist de cierre

- [ ] Cobertura de eventos `4662` verificada.
- [ ] GUID revisado en el campo correcto.
- [ ] `AccessMask` documentado.
- [ ] `ObjectType` y `ObjectName` documentados.
- [ ] Cuenta solicitante identificada.
- [ ] Derechos de la cuenta validados.
- [ ] Logon ID correlacionado o limitación registrada.
- [ ] Host e IP origen identificados.
- [ ] Origen comparado con inventario autorizado.
- [ ] Actividad EDR revisada.
- [ ] Tráfico RPC/MS-DRSR revisado cuando está disponible.
- [ ] Cambios `5136` agrupados y comparados.
- [ ] Conclusión basada en evidencia, no únicamente en ausencia de eventos.
- [ ] Acciones y owner documentados.

## 8. Plantilla de findings

```text
Alert / hypothesis:
Time window:
Domain controllers reviewed:
Replication GUIDs:
Event 4662 coverage:
Requester account:
Subject Logon ID:
Source host and IP:
ObjectType and ObjectName:
AccessMask and Properties:
Related Event 4624:
Related Event 5136:
Endpoint evidence:
Network evidence:
Authorization or change reference:
Assessment:
Telemetry limitations:
Recommended actions:
```

