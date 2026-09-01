# RPC Targeted Recon Playbook

## Objetivo

Investigar y clasificar alertas de RPC Targeted Recon utilizando Vectra AI, Splunk y Windows Security Events.

## Severidad inicial

- **Media:** origen interno sin actividad posterior confirmada.
- **Alta:** origen inesperado, destinos críticos, credenciales anómalas o ejecución remota.
- **Crítica:** evidencia de compromiso, movimiento lateral o impacto en sistemas críticos.

## Fase 1: preparación

- [ ] Copiar la IP de origen.
- [ ] Registrar el hostname.
- [ ] Copiar la ventana temporal exacta.
- [ ] Ampliar la búsqueda entre 10 y 30 minutos antes y después.
- [ ] Identificar destinos.
- [ ] Registrar la acción allowed o blocked.
- [ ] Confirmar si la IP corresponde a NAT, VIP, proxy, gateway o jump server.
- [ ] Consultar la función del activo en CMDB.

## Fase 2: validación de la alerta

- [ ] Confirmar que el origen coincide entre Vectra y Splunk.
- [ ] Verificar el volumen real.
- [ ] Confirmar los destinos.
- [ ] Revisar la ventana temporal.
- [ ] Determinar si existe un problema de normalización.
- [ ] Revisar si hay eventos duplicados.

## Fase 3: alcance de red

- [ ] Contar destinos únicos.
- [ ] Revisar los puertos.
- [ ] Revisar los protocolos.
- [ ] Comprobar acciones allowed o blocked.
- [ ] Revisar bytes y duración.
- [ ] Identificar destinos críticos.
- [ ] Determinar si afecta a varias subredes.
- [ ] Identificar destinos nuevos.

## Fase 4: patrón temporal

- [ ] Agrupar la actividad por minuto.
- [ ] Identificar ráfagas.
- [ ] Determinar si los destinos fueron contactados secuencialmente.
- [ ] Revisar si el patrón es diario.
- [ ] Comparar el horario con tareas conocidas.
- [ ] Determinar si la actividad es sostenida o automatizada.

## Fase 5: autenticaciones

Revisar:

- [ ] Event ID 4624.
- [ ] Event ID 4625.
- [ ] Event ID 4648.
- [ ] Event ID 4776.
- [ ] Usuarios.
- [ ] Logon Types.
- [ ] Equipos destino.
- [ ] Fallos seguidos de éxito.
- [ ] Cuentas privilegiadas.
- [ ] Uso de credenciales explícitas.

## Fase 6: recursos compartidos

- [ ] Buscar Event ID 5140.
- [ ] Buscar Event ID 5145.
- [ ] Identificar shares.
- [ ] Revisar `ADMIN$`.
- [ ] Revisar `C$`.
- [ ] Revisar `IPC$`.
- [ ] Registrar objetos accedidos.
- [ ] Validar la disponibilidad de auditoría.

Si no existen eventos, registrar una de estas conclusiones:

```text
Acceso no observado.
```

o:

```text
No existe cobertura suficiente para validar el acceso a recursos compartidos.
```

## Fase 7: actividad posterior

- [ ] Buscar Event ID 4688.
- [ ] Buscar procesos hijos de `WmiPrvSE.exe`.
- [ ] Buscar procesos hijos de `services.exe`.
- [ ] Buscar `cmd.exe`.
- [ ] Buscar `powershell.exe`.
- [ ] Buscar `pwsh.exe`.
- [ ] Buscar `wmic.exe`.
- [ ] Buscar `sc.exe`.
- [ ] Buscar `schtasks.exe`.
- [ ] Buscar `net.exe`.
- [ ] Buscar `reg.exe`.
- [ ] Buscar Event ID 7045.
- [ ] Buscar Event ID 4697.
- [ ] Buscar Event ID 4698.
- [ ] Buscar Event ID 4702.

## Fase 8: contexto

- [ ] Confirmar propietario.
- [ ] Confirmar función del activo.
- [ ] Revisar CMDB.
- [ ] Confirmar herramientas instaladas.
- [ ] Revisar cambios aprobados.
- [ ] Revisar mantenimientos.
- [ ] Validar tareas programadas.
- [ ] Confirmar las cuentas utilizadas.
- [ ] Revisar privilegios.
- [ ] Validar destinos esperados.

## Fase 9: histórico

- [ ] Comparar al menos 30 días.
- [ ] Identificar primera aparición.
- [ ] Comparar destinos por hora.
- [ ] Comparar volumen.
- [ ] Comparar horario.
- [ ] Revisar cambios en el patrón.
- [ ] Identificar desviaciones.

## Fase 10: decisión

Seleccionar una clasificación:

- [ ] Malicious True Positive.
- [ ] Benign True Positive.
- [ ] False Positive.
- [ ] Inconclusive.

Documentar:

- [ ] Evidencia que apoya la decisión.
- [ ] Evidencia que contradice la decisión.
- [ ] Telemetría ausente.
- [ ] Validaciones realizadas.
- [ ] Acciones aplicadas.
- [ ] Recomendaciones de tuning.

## Acciones si es malicioso

- [ ] Escalar a incidente.
- [ ] Conservar la línea temporal.
- [ ] Contener el sistema origen.
- [ ] Restringir RPC o SMB cuando sea viable.
- [ ] Proteger las credenciales.
- [ ] Ampliar la búsqueda a otros sistemas.
- [ ] Revisar los destinos.
- [ ] Solicitar análisis EDR.
- [ ] Evaluar adquisición forense.

## Acciones si es benigno

- [ ] Registrar herramienta.
- [ ] Registrar propietario.
- [ ] Registrar cuenta.
- [ ] Registrar destinos.
- [ ] Registrar horario.
- [ ] Confirmar autorización.
- [ ] Proponer tuning contextual.
- [ ] Establecer fecha de revisión.

## Acciones si es inconcluso

- [ ] Documentar la telemetría faltante.
- [ ] Solicitar validación al propietario.
- [ ] Revisar firewall.
- [ ] Revisar EDR.
- [ ] Revisar Vectra.
- [ ] Revisar logs de destinos.
- [ ] Mantener la alerta abierta o escalar.

## Plantilla de cierre

```text
Resumen:
Vectra detectó un volumen elevado de comunicaciones RPC originadas desde
{SOURCE_IP} durante {TIME_RANGE}.

Alcance:
Se identificaron {DESTINATION_COUNT} destinos únicos y actividad en los
puertos {DESTINATION_PORTS}.

Patrón:
La actividad presentó un comportamiento {BURST_OR_SUSTAINED} y las
comunicaciones fueron {ALLOWED_OR_BLOCKED}.

Identidades:
Se observaron los usuarios {USERS}, con los eventos {EVENT_IDS} y los tipos
de inicio de sesión {LOGON_TYPES}.

Recursos compartidos:
{CONFIRMED_NOT_OBSERVED_OR_NO_TELEMETRY}

Actividad posterior:
{REMOTE_EXECUTION_FINDINGS}

Histórico:
{HISTORICAL_FINDINGS}

Contexto:
{ASSET_ROLE_AND_OWNER_VALIDATION}

Clasificación:
{MALICIOUS_TP_BENIGN_TP_FP_OR_INCONCLUSIVE}

Justificación:
{EVIDENCE_BASED_JUSTIFICATION}

Acciones:
{RESPONSE_VALIDATION_OR_TUNING}
```
