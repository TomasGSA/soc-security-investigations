# Classification Criteria

## Principio general

La clasificación debe basarse en múltiples fuentes de evidencia.

No aplicar un veredicto utilizando únicamente:

- Una IP.
- Un puerto.
- Un hostname.
- Una cuenta.
- Una alerta.
- La ausencia de eventos.

## Malicious True Positive

La actividad es real y existen evidencias suficientes de intención o impacto malicioso.

Indicadores:

- Origen inesperado.
- Destinos nuevos.
- Ráfaga automatizada.
- Cuentas anómalas.
- Fallos seguidos de éxito.
- Ejecución remota.
- Persistencia.
- Actividad posterior.
- Desviación significativa.
- Destinos críticos.

Acción:

- Escalar.
- Contener.
- Ampliar el alcance.
- Proteger credenciales.
- Preservar evidencias.

## Benign True Positive

La detección representa actividad real, pero autorizada.

Indicadores:

- Herramienta validada.
- Propietario conocido.
- Cuenta autorizada.
- Destinos esperados.
- Horario aprobado.
- Histórico estable.
- Cambio documentado.

Acción:

- Documentar.
- Cerrar como benigno.
- Evaluar tuning.
- Establecer fecha de revisión.

## False Positive

La detección no representa el comportamiento descrito.

Indicadores:

- IP incorrecta.
- NAT o proxy.
- Duplicación.
- Campos incorrectos.
- Error de normalización.
- Lógica defectuosa.
- Volumen calculado incorrectamente.

Acción:

- Corregir normalización.
- Ajustar la lógica.
- Validar nuevamente.
- Documentar la causa.

## Inconclusive

No existe evidencia suficiente.

Causas:

- Falta de logs.
- Falta de propietario.
- Falta de CMDB.
- Falta de histórico.
- Atribución no fiable.
- Cuenta no validada.
- Campo ausente.
- Ventana temporal incompleta.

Acción:

- Documentar qué falta.
- Solicitar información.
- Mantener abierto.
- Escalar según criticidad.

## Modelo de decisión

Evaluar los siguientes dominios:

1. Red.
2. Identidad.
3. Endpoint.
4. Activo.
5. Histórico.
6. Contexto.
7. Actividad posterior.
8. Cobertura de telemetría.

La confianza aumenta cuando varios dominios independientes apoyan la misma conclusión.
