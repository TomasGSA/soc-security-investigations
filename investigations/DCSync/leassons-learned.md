 Lessons learned: investigación de posible DCSync

> Nota: el nombre del archivo conserva `leassons-learned.md` para ajustarse a la estructura solicitada. La forma correcta en inglés sería `lessons-learned.md`.

## 1. Resumen

La investigación demostró que una coincidencia con un GUID de replicación de Active Directory no equivale automáticamente a una ejecución DCSync.

El GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` fue encontrado dentro del valor de `nTSecurityDescriptor` en eventos `5136`. El contexto mostraba modificaciones de seguridad sobre objetos DNS integrados en Active Directory, ejecutadas por `SYSTEM` desde controladores de dominio.

No se identificaron eventos `4662` que demostraran una solicitud de replicación mediante `AccessMask=0x100` y el GUID dentro de `Properties`.

## 2. Qué funcionó correctamente

### Búsqueda por indicador técnico

Buscar el GUID permitió localizar actividad relevante para comprender dónde aparecía el derecho de replicación dentro de los registros.

### Revisión del tipo de evento

Distinguir entre `5136` y `4662` evitó clasificar incorrectamente un cambio de descriptor como ejecución DCSync.

### Análisis del objeto afectado

La identificación de objetos `dnsNode` bajo `MicrosoftDNS` y `DomainDnsZones` proporcionó contexto administrativo y redujo la probabilidad de que los eventos representaran acceso al objeto raíz del dominio.

### Revisión de la identidad

La actividad ejecutada como `NT AUTHORITY\SYSTEM` directamente en controladores de dominio era más compatible con procesos internos que con una solicitud externa desde una estación de trabajo.

### Correlación por operación

Los pares `Value Deleted` y `Value Added`, junto con los identificadores de correlación, ayudaron a interpretar los eventos como modificaciones del mismo atributo.

## 3. Qué podía mejorarse

### La búsqueda inicial era demasiado amplia

Buscar el GUID en todo el evento generó coincidencias sin considerar el campo donde aparecía. Para DCSync, la lógica debe centrarse en:

```text
EventCode=4662
AccessMask=0x100
Properties=<replication GUID>
```

### No se validó inicialmente la cobertura de auditoría

Antes de interpretar la ausencia de eventos `4662`, debía comprobarse si:

- La política `Audit Directory Service Access` estaba habilitada.
- La SACL estaba configurada.
- Los eventos se enviaban al SIEM.
- Todos los DC tenían cobertura.

### El origen de la operación no estaba disponible directamente

Los eventos `5136` encontrados no proporcionaban el mismo contexto de acceso esperado en `4662`. La investigación requería correlación adicional con eventos `4624`, inventario y telemetría de red.

### Era necesario comparar las ACL completas

Ver el GUID en el valor anterior y nuevo puede significar que el derecho ya existía y no fue añadido durante el evento. Las reglas de Detection Engineering deben calcular diferencias entre descriptores cuando sea posible.

## 4. Principales aprendizajes técnicos

### Aprendizaje 1: el contexto del campo es esencial

Una cadena puede tener significados diferentes según su ubicación:

```text
Properties de 4662
```

puede reflejar un derecho ejercido.

```text
AttributeValue de 5136 para nTSecurityDescriptor
```

refleja contenido de una ACL modificada.

### Aprendizaje 2: presencia no significa uso

Un principal puede tener un derecho representado en una ACE sin haberlo ejercido durante el periodo investigado.

### Aprendizaje 3: cambio de permisos y uso de permisos son casos distintos

Deben existir detecciones separadas para:

1. Concesión o modificación de derechos de replicación.
2. Ejercicio de derechos de replicación.

### Aprendizaje 4: el inventario es parte de la detección

Una lógica DCSync necesita conocer:

- Controladores de dominio autorizados.
- IP de cada DC.
- Cuentas de equipo correspondientes.
- Herramientas de sincronización autorizadas.
- Cuentas de servicio con delegación aprobada.

Sin ese contexto, la regla tendrá baja fidelidad.

### Aprendizaje 5: no excluir todas las cuentas de equipo

Las cuentas terminadas en `$` no son automáticamente legítimas. Una cuenta de equipo no DC puede estar comprometida o disponer de permisos indebidamente.

### Aprendizaje 6: la ausencia de logs no demuestra ausencia de actividad

Cuando la auditoría o ingestión no están validadas, la conclusión correcta es:

```text
No evidence found in the available telemetry.
```

No:

```text
The activity did not occur.
```

### Aprendizaje 7: SYSTEM no es una conclusión automática de benignidad

`SYSTEM` en un DC puede ser normal, pero siempre debe analizarse junto con:

- Objeto afectado.
- Servicio o proceso.
- Origen de red.
- Frecuencia.
- Correlación temporal.

## 5. Mejoras propuestas

### Auditoría

- [ ] Confirmar `Audit Directory Service Access` en todos los DC.
- [ ] Revisar SACL sobre el objeto raíz del dominio.
- [ ] Verificar generación real de eventos `4662`.
- [ ] Comprobar retención e ingestión del canal Security.

### Detection Engineering

- [ ] Restringir la detección DCSync a `4662` con `AccessMask=0x100`.
- [ ] Validar que el GUID se encuentra en `Properties`.
- [ ] Enriquecer con inventario de DC y fuentes autorizadas.
- [ ] Correlacionar automáticamente el Logon ID con `4624`.
- [ ] Separar cambios de ACL de solicitudes de replicación.
- [ ] Evitar exclusiones globales basadas únicamente en `$` o `SYSTEM`.

### Investigación

- [ ] Empezar validando cobertura de datos.
- [ ] Ampliar la ventana temporal alrededor de la alerta.
- [ ] Revisar `_raw` si los campos no están extraídos.
- [ ] Documentar todas las limitaciones de visibilidad.
- [ ] Utilizar una plantilla común de findings.

### Procesos

- [ ] Mantener listado de cuentas con derechos de replicación.
- [ ] Asociar cada cuenta autorizada a un owner y justificación.
- [ ] Revisar periódicamente delegaciones de Active Directory.
- [ ] Definir un procedimiento de escalada para posible compromiso de dominio.

## 6. Resultado aplicable a casos futuros

Ante cualquier búsqueda que devuelva un GUID de replicación:

1. Confirmar el Event ID.
2. Identificar el campo exacto donde aparece el GUID.
3. Distinguir entre ACL y derecho ejercido.
4. Validar `AccessMask`.
5. Identificar cuenta y Logon ID.
6. Obtener el origen.
7. Comparar con inventario autorizado.
8. Revisar EDR y red.
9. Registrar limitaciones.
10. Clasificar con evidencia positiva.

## 7. Conclusión

El principal valor de esta investigación fue convertir una coincidencia potencialmente alarmante en una distinción técnica reproducible:

```text
DCSync is not identified by the GUID alone.
It is identified by the combination of event context, exercised access,
requesting identity, source system and authorization status.
```

Esta distinción debe incorporarse tanto al playbook del SOC como a la lógica de detección para reducir falsos positivos sin perder visibilidad sobre solicitudes reales de replicación.

