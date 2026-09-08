# Investigación de posible actividad DCSync

> **Clasificación del documento:** uso interno  
> **Estado:** investigación completada con limitaciones de telemetría  
> **Sanitización:** los nombres de dominio, hosts, direcciones IP, cuentas, identificadores de sesión y objetos han sido sustituidos por valores genéricos.

## 1. Objetivo

El objetivo de esta investigación es determinar si la actividad observada representa un intento o ejecución de **DCSync**, una operación legítima de replicación de Active Directory, un cambio administrativo de permisos o un falso positivo causado por una búsqueda demasiado amplia de GUID de replicación.

La investigación busca responder las siguientes preguntas:

1. ¿Existe evidencia de que una identidad ejerció derechos de replicación de Active Directory?
2. ¿La actividad fue ejecutada por una cuenta y desde un sistema autorizados?
3. ¿El GUID de replicación aparece en el contexto de una operación de acceso o únicamente como contenido de un descriptor de seguridad?
4. ¿La telemetría disponible permite descartar razonablemente una actividad maliciosa?
5. ¿Es necesario escalar el caso, mejorar la auditoría o ajustar la lógica de detección?

La presencia aislada de un GUID asociado a replicación no se considera prueba suficiente de DCSync. La validación debe apoyarse en el contexto del evento, el campo donde aparece el GUID, el derecho ejercido, el objeto afectado, la identidad solicitante y el sistema de origen.

---

## 2. Descripción del comportamiento

La investigación se inició después de identificar el siguiente GUID en eventos de seguridad de Active Directory:

```text
1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
```

Este GUID corresponde al derecho extendido:

```text
DS-Replication-Get-Changes-All
```

La búsqueda inicial intentó localizar eventos Windows Security `4662`, utilizados habitualmente para identificar operaciones realizadas sobre objetos de Active Directory. Sin embargo, los resultados disponibles correspondían a eventos `5136`.

Los eventos observados presentaban el siguiente patrón:

- Modificación del atributo `nTSecurityDescriptor`.
- Objetos de clase `dnsNode`.
- Objetos almacenados en particiones DNS integradas en Active Directory.
- Actividad registrada en controladores de dominio.
- Operaciones ejecutadas bajo el contexto `NT AUTHORITY\SYSTEM`.
- Pares de cambios `Value Deleted` y `Value Added`.
- Presencia del GUID dentro de una ACE del descriptor de seguridad.
- Ausencia de campos propios de una operación `4662`, como `AccessMask`, `Properties` y contexto completo del acceso.

Representación sanitizada del contexto observado:

```text
Domain: <INTERNAL_DOMAIN>
Domain Controller: <DC_HOST_01>
Domain Controller IP: <DC_IP_01>
Secondary Domain Controller: <DC_HOST_02>
Secondary Domain Controller IP: <DC_IP_02>
Account: NT AUTHORITY\SYSTEM
Subject Logon ID: <LOGON_ID>
Object class: dnsNode
Attribute: nTSecurityDescriptor
Directory partition: <AD_DNS_PARTITION>
```

El GUID aparecía dentro de una estructura ACE similar a la siguiente:

```text
(OA;CIID;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;ED)
```

Esta estructura indica que el GUID formaba parte de un descriptor de seguridad. No demuestra, por sí sola, que una cuenta hubiera utilizado el derecho para solicitar secretos del dominio.

---

## 3. Hipótesis

### H1. DCSync malicioso

Una cuenta comprometida o un sistema no autorizado ejerció derechos de replicación para solicitar información sensible de Active Directory.

**Evidencia esperada:**

- Evento `4662`.
- `AccessMask=0x100`.
- GUID de replicación dentro de `Properties`.
- Operación sobre el objeto de dominio o contexto de nombres relevante.
- Cuenta solicitante no autorizada o inesperada.
- Origen desde un host que no es un controlador de dominio.
- Correlación con autenticación, RPC/MS-DRSR o telemetría EDR sospechosa.

### H2. Replicación legítima

La actividad corresponde a replicación normal entre controladores de dominio o a una aplicación autorizada con derechos de replicación.

**Evidencia esperada:**

- Evento `4662` compatible con replicación.
- Cuenta de controlador de dominio o servicio autorizado.
- Sistema e IP incluidos en el inventario autorizado.
- Ausencia de procesos o indicadores sospechosos.
- Patrón consistente con actividad administrativa conocida.

### H3. Modificación legítima de una ACL

El GUID aparece porque el descriptor de seguridad de un objeto fue actualizado, reemplazado, heredado o normalizado.

**Evidencia esperada:**

- Evento `5136`.
- Atributo `nTSecurityDescriptor`.
- Operaciones `Value Deleted` y `Value Added`.
- GUID incluido dentro de una ACE.
- Actividad generada por `SYSTEM`, AD DS, DNS u otro proceso administrativo autorizado.
- Objetos afectados compatibles con la función administrativa observada.

### H4. Falso positivo de la lógica de búsqueda

La alerta o búsqueda detectó la cadena del GUID en cualquier campo, sin diferenciar entre un derecho almacenado en una ACL y un derecho ejercido durante una operación.

**Evidencia esperada:**

- Coincidencia textual del GUID en `AttributeValue`, `Value` o `_raw`.
- Ausencia de `EventCode=4662`.
- Ausencia de `AccessMask=0x100`.
- Ausencia del GUID dentro de `Properties`.
- Ausencia de origen no autorizado o evidencia complementaria.

### H5. Caso inconcluso por falta de telemetría

No existe evidencia positiva de DCSync, pero tampoco puede descartarse completamente debido a una cobertura insuficiente de auditoría o ingestión.

**Evidencia esperada:**

- Ausencia generalizada de eventos `4662` en los controladores de dominio.
- Configuración de SACL no validada.
- Pérdida o ausencia de eventos del canal Security.
- Imposibilidad de correlacionar el Logon ID.
- Falta de telemetría EDR o de red del posible origen.

---

## 4. Datos mínimos de entrada

Antes de iniciar una investigación equivalente, se deben recopilar al menos los siguientes datos:

| Categoría | Dato mínimo | Finalidad |
|---|---|---|
| Alerta | Nombre, identificador y lógica de detección | Conocer por qué se generó el caso. |
| Tiempo | Hora inicial, final y zona horaria | Construir una ventana de búsqueda reproducible. |
| Dominio | Nombre sanitizado y DN raíz | Identificar el contexto de nombres investigado. |
| Destino | Host e IP del controlador de dominio | Saber dónde se registró la operación. |
| Identidad | Cuenta, dominio de cuenta y SID | Identificar al principal solicitante o ejecutor. |
| Sesión | Subject Logon ID o Target Logon ID | Correlacionar con autenticaciones. |
| Evento | Event ID, canal, proveedor y resultado | Distinguir acceso de modificación. |
| Objeto AD | ObjectType, ObjectName, ObjectDN y ObjectClass | Determinar el objeto afectado. |
| Acceso | AccessMask y Properties | Verificar si se ejerció un derecho extendido. |
| Cambio | Atributo, valor anterior, valor nuevo y Correlation ID | Analizar cambios de ACL mediante `5136`. |
| Origen | IP, hostname y tipo de activo | Comparar con sistemas autorizados. |
| Inventario | DC y aplicaciones con replicación autorizada | Reducir falsos positivos de forma controlada. |
| Endpoint | Proceso, padre, línea de comandos y usuario | Buscar herramientas o ejecución sospechosa. |
| Red | RPC/MS-DRSR y comunicación hacia el DC | Confirmar el origen técnico de la solicitud. |

Formato recomendado para registrar los valores sin exponer información sensible:

```text
Domain: <INTERNAL_DOMAIN>
Domain DN: <DOMAIN_DN>
Domain Controller: <DC_HOST_01>
Domain Controller IP: <DC_IP_01>
Requester Account: <ACCOUNT_01>
Subject Logon ID: <LOGON_ID_01>
Source Host: <SOURCE_HOST_01>
Source IP: <SOURCE_IP_01>
Investigation Window: <START_TIME> to <END_TIME> <TIME_ZONE>
```

---

## 5. Dominios de evidencia

### 5.1 Eventos de acceso a Active Directory

El evento principal para validar el ejercicio de derechos de replicación es `4662`.

Campos prioritarios:

- `SubjectUserName`.
- `SubjectDomainName`.
- `SubjectUserSid`.
- `SubjectLogonId`.
- `ObjectServer`.
- `ObjectType`.
- `ObjectName`.
- `AccessMask`.
- `Properties`.

La combinación de mayor interés es:

```text
EventCode=4662
AccessMask=0x100
Properties contains <REPLICATION_GUID>
ObjectType corresponds to the domain
```

### 5.2 Eventos de cambios en Active Directory

El evento `5136` permite identificar modificaciones de atributos, incluyendo `nTSecurityDescriptor`.

Campos prioritarios:

- `SubjectUserName`.
- `SubjectLogonId`.
- `ObjectDN`.
- `ObjectClass`.
- `AttributeLDAPDisplayName`.
- `AttributeValue`.
- `OperationType`.
- `OpCorrelationID`.

Estos eventos permiten determinar si un derecho fue añadido o eliminado de una ACL, pero no prueban que el derecho haya sido ejercido.

### 5.3 Autenticación

Los eventos `4624` permiten correlacionar el Logon ID y obtener:

- Cuenta autenticada.
- Tipo de inicio de sesión.
- Dirección IP.
- Estación de origen.
- Paquete de autenticación.
- Proceso asociado.

La ausencia del `4624` correlacionado puede deberse a una ventana temporal insuficiente, una sesión de larga duración, un reinicio, diferencias de formato o problemas de ingestión.

### 5.4 Identidad y permisos

Debe revisarse:

- Membresía en grupos privilegiados.
- Derechos de replicación delegados.
- Propietario y finalidad de la cuenta.
- Cambios recientes de permisos.
- Uso de cuentas de servicio.
- Cuentas de equipo que no pertenecen a controladores de dominio.

### 5.5 Endpoint

En el posible sistema origen se debe buscar:

- Procesos inusuales.
- PowerShell, Python u otras herramientas administrativas.
- Comandos relacionados con replicación.
- Evidencia de Mimikatz, Impacket, SecretsDump o `DsGetNCChanges`.
- Acceso a credenciales o material de autenticación.
- Persistencia, movimiento lateral o abuso posterior de cuentas.

Los nombres de herramientas son indicadores útiles, pero no obligatorios. Una técnica DCSync puede ejecutarse mediante código personalizado o herramientas renombradas.

### 5.6 Red

La evidencia de red debe incluir, cuando esté disponible:

- Comunicación RPC hacia un controlador de dominio.
- Tráfico MS-DRSR.
- Solicitudes desde hosts no clasificados como DC.
- Correspondencia temporal entre red y eventos de seguridad.
- Dirección IP real del origen, teniendo en cuenta NAT, proxies o sensores intermedios.

### 5.7 Inventario y contexto administrativo

Se debe validar el origen contra:

- Inventario de controladores de dominio.
- Servidores administrativos.
- Soluciones IAM.
- Herramientas de respaldo.
- Aplicaciones de sincronización.
- Cuentas con delegación de replicación aprobada.
- Cambios planificados y tickets asociados.

---

## 6. Interpretación

### 6.1 Interpretación de Event ID 4662

Un evento `4662` puede proporcionar evidencia de que una identidad realizó una operación sobre un objeto de Active Directory. Para considerarlo compatible con DCSync se debe validar el conjunto completo de campos, no únicamente el GUID.

```text
4662 + AccessMask 0x100 + replication GUID in Properties
```

representa una señal de uso de un derecho extendido. La legitimidad depende de la cuenta, el origen, el objeto y la autorización.

### 6.2 Interpretación de Event ID 5136

Un evento `5136` indica que un objeto de Active Directory fue modificado.

```text
5136 + nTSecurityDescriptor + replication GUID in AttributeValue
```

indica que el GUID está contenido en el descriptor de seguridad escrito o reemplazado. Puede representar:

- Una ACE preexistente.
- Un permiso nuevo.
- Un permiso eliminado.
- Herencia de permisos.
- Reordenación o normalización del descriptor.
- Una actualización automática del objeto.

Para determinar cuál de estas posibilidades ocurrió es necesario comparar el valor eliminado con el valor añadido dentro del mismo `Correlation ID`.

### 6.3 Interpretación del contexto `SYSTEM`

La ejecución bajo `NT AUTHORITY\SYSTEM` en un controlador de dominio es compatible con procesos internos, pero no debe considerarse automáticamente benigna.

Debe evaluarse junto con:

- Tipo de objeto.
- Servicio implicado.
- Host donde ocurrió.
- Frecuencia y periodicidad.
- Cambios exactos realizados.
- Existencia de un origen remoto.
- Evidencia EDR y de red.

### 6.4 Interpretación del objeto `dnsNode`

Los objetos `dnsNode` bajo particiones DNS integradas en Active Directory son consistentes con operaciones del servicio DNS, actualizaciones dinámicas, cambios de propietarios y reaplicación de ACL.

Este contexto reduce la probabilidad de que los eventos analizados representen una extracción de credenciales, especialmente cuando no existe un `4662` correlacionado sobre el objeto de dominio.

### 6.5 Interpretación consolidada del caso

En los datos analizados:

- El GUID fue encontrado dentro de `nTSecurityDescriptor`.
- Los eventos eran `5136`.
- Los objetos afectados eran `dnsNode`.
- La actividad estaba asociada a `SYSTEM` en controladores de dominio.
- Se observaron pares de reemplazo del atributo.
- No se encontró evidencia disponible de un `4662` con derecho de replicación ejercido.
- No se identificó una cuenta o fuente no autorizada.

El comportamiento es más consistente con una modificación automática o administrativa de ACL que con un DCSync confirmado.

---

## 7. Matriz de evidencia

| Evidencia | Resultado sanitizado | Apoya | Peso | Observación |
|---|---|---|---|---|
| GUID `1131f6ad...` detectado | Presente | H3 / H4 | Bajo por sí solo | Su significado depende del evento y del campo. |
| Event ID `4662` | No observado en el conjunto analizado | H5 | Alto como limitación | Debe validarse cobertura antes de interpretar su ausencia. |
| Event ID `5136` | Presente | H3 / H4 | Alto | Demuestra modificación de objetos AD. |
| Atributo `nTSecurityDescriptor` | Presente | H3 / H4 | Alto | Sitúa el GUID dentro de un descriptor de seguridad. |
| GUID dentro de `Properties` | No observado | Contra H1 | Alto | No hay evidencia disponible de derecho ejercido. |
| `AccessMask=0x100` | No observado | Contra H1 | Alto | No se confirmó una operación Control Access. |
| Objetos `dnsNode` | Presentes | H3 | Medio-alto | Contexto compatible con DNS integrado en AD. |
| Objeto raíz del dominio | No observado | Contra H1 | Medio | Reduce la compatibilidad con el patrón esperado. |
| Cuenta `SYSTEM` | Presente | H2 / H3 | Medio | Compatible con actividad interna, pero requiere contexto. |
| Actividad en controladores de dominio | Presente | H2 / H3 | Medio-alto | Origen local esperado para servicios internos. |
| Fuente no DC | No identificada | Contra H1 | Alto | No se encontró un origen no autorizado. |
| Pares `Value Deleted` / `Value Added` | Presentes | H3 | Alto | Patrón normal de reemplazo de atributo en `5136`. |
| Correlation ID por operación | Presente | H3 | Medio | Permite agrupar el valor anterior y nuevo. |
| Evidencia de herramientas DCSync | No observada en los datos disponibles | Contra H1 | Medio | La ausencia no descarta herramientas renombradas o código propio. |
| Evidencia RPC/MS-DRSR | No disponible | H5 | Alto como limitación | Impide validar el origen mediante red. |
| Cobertura de auditoría `4662` | No confirmada | H5 | Crítico | La conclusión debe conservar esta reserva. |

### Evaluación de hipótesis

| Hipótesis | Estado | Justificación |
|---|---|---|
| H1. DCSync malicioso | No sustentada | No se observó `4662`, `AccessMask=0x100`, GUID en `Properties` ni origen no autorizado. |
| H2. Replicación legítima | No demostrada directamente | No se observó una solicitud `4662`; el contexto de DC y `SYSTEM` es compatible, pero los eventos eran cambios de objetos DNS. |
| H3. Modificación legítima de ACL | Más probable | Los eventos `5136` modificaban `nTSecurityDescriptor` sobre objetos `dnsNode`. |
| H4. Falso positivo de búsqueda | Sustentada | El GUID fue localizado mediante coincidencia textual dentro de una ACL. |
| H5. Telemetría insuficiente | Parcialmente aplicable | La cobertura de eventos `4662` no quedó demostrada. |

---

## 8. Clasificación

### Clasificación del caso

```text
Probable benign administrative or automated activity
with a false-positive GUID match
```

### Estado de confianza

```text
Medium confidence
```

La confianza no se considera alta porque la cobertura de auditoría e ingestión de eventos `4662` debe validarse de forma independiente.

### Criterios utilizados

**Factores que reducen la sospecha:**

- Los eventos eran `5136`, no `4662`.
- El GUID estaba incluido en `nTSecurityDescriptor`.
- Los objetos eran registros DNS integrados en Active Directory.
- La actividad se ejecutó como `SYSTEM` en controladores de dominio.
- Se observaron pares estándar de reemplazo de atributo.
- No se identificó una fuente no DC.
- No se observó evidencia complementaria de herramientas o tráfico DCSync.

**Factores que impiden un cierre sin reservas:**

- No se ha demostrado la cobertura completa de eventos `4662`.
- No se dispone de telemetría RPC/MS-DRSR en el conjunto analizado.
- No se ha identificado el proceso exacto que originó cada modificación.
- La comparación semántica completa de los descriptores anterior y nuevo puede requerir datos sin truncamiento.

### Disposición recomendada

```text
Close as likely benign / detection false positive
only after validating Event ID 4662 audit coverage.
```

Si no es posible validar la cobertura, utilizar:

```text
Inconclusive regarding DCSync execution due to telemetry limitations.
Observed events are consistent with benign AD-integrated DNS ACL updates.
```

---

## 9. Limitaciones

1. **Cobertura de auditoría no confirmada:** la generación de eventos `4662` depende de `Audit Directory Service Access` y de una SACL adecuada.
2. **Ingestión no validada:** no se confirmó que todos los controladores de dominio enviaran la totalidad del canal Security al SIEM.
3. **Ausencia de telemetría de red:** no se dispuso de evidencia RPC/MS-DRSR para confirmar o descartar solicitudes desde sistemas no DC.
4. **Correlación de sesión limitada:** los Logon ID pueden pertenecer a sesiones de larga duración y su evento `4624` puede quedar fuera de la ventana inicial.
5. **Posible truncamiento:** los valores de `nTSecurityDescriptor` pueden estar truncados por el origen, el agente o la plataforma de búsqueda.
6. **Normalización de campos:** los nombres de campo varían según el Technology Add-on y pueden impedir búsquedas exactas si no se revisa `_raw`.
7. **Proceso originador no identificado:** el evento `5136` no siempre permite atribuir directamente el cambio al proceso responsable.
8. **Inventario externo al conjunto de datos:** la autorización de cuentas y sistemas debe confirmarse con los propietarios de Active Directory.
9. **Ausencia de indicador nominal no concluyente:** no encontrar nombres como Mimikatz o SecretsDump no descarta código personalizado o herramientas renombradas.
10. **Sanitización:** esta versión sustituye identificadores sensibles, por lo que no debe utilizarse como única fuente para reconstruir la cronología operacional original.

---

## 10. Conclusión

La investigación no encontró evidencia suficiente para confirmar una ejecución DCSync.

El GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` fue identificado dentro del atributo `nTSecurityDescriptor` de eventos `5136`. Los objetos afectados eran de clase `dnsNode`, estaban almacenados en particiones DNS integradas en Active Directory y fueron modificados bajo el contexto `NT AUTHORITY\SYSTEM` en controladores de dominio.

Estos elementos indican que el GUID representaba un derecho contenido en una ACL que estaba siendo actualizada, heredada o normalizada. No se observó como una propiedad accedida dentro de un evento `4662`, ni se identificaron `AccessMask=0x100`, una cuenta solicitante no autorizada, un sistema origen no DC o evidencia complementaria de red y endpoint.

Por tanto, la explicación más probable es una actualización automática o administrativa del descriptor de seguridad de objetos DNS, combinada con un falso positivo producido por una búsqueda textual amplia del GUID.

La conclusión final debe expresarse de la siguiente forma:

```text
No evidence of DCSync execution was identified in the available telemetry.
The observed events correspond to modifications of security descriptors on
Active Directory-integrated DNS objects. The replication GUID was present as
part of an ACL and does not demonstrate that the right was exercised.
Event ID 4662 audit and ingestion coverage must be validated before definitive closure.
```

### Acciones finales recomendadas

- Validar la generación e ingestión de eventos `4662` en todos los controladores de dominio.
- Confirmar la SACL de auditoría sobre el objeto raíz del dominio.
- Ajustar la detección para exigir el GUID dentro de `Properties` de un `4662` y `AccessMask=0x100`.
- Mantener una detección separada para cambios de derechos de replicación mediante `5136`.
- Enriquecer futuras alertas con inventario de DC, cuentas autorizadas, Logon ID, IP de origen y telemetría RPC/MS-DRSR.
- Evitar exclusiones globales basadas únicamente en cuentas `SYSTEM` o terminadas en `$`.

