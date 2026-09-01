# RPC Targeted Recon

## Resumen

Esta investigación describe una metodología para analizar alertas en las que un sistema origina un volumen elevado de solicitudes RPC hacia múltiples destinos.

El objetivo es determinar si el comportamiento corresponde a:

- Reconocimiento interno malicioso.
- Preparación de movimiento lateral.
- Actividad administrativa autorizada.
- Herramientas de inventario o monitorización.
- Sistemas de backup o distribución de software.
- Una atribución incorrecta de red.
- Una detección inconclusa por falta de telemetría.

## Fuente de detección

- **Producto:** Vectra AI
- **Detección:** RPC Targeted Recon
- **Fuentes complementarias:** Splunk, Windows Security Events y telemetría de red
- **Severidad inicial:** Media o alta según el contexto

## Hipótesis de amenaza

Un sistema comprometido puede estar utilizando RPC para enumerar servicios, usuarios, recursos compartidos, endpoints y sistemas accesibles con el objetivo de preparar acciones posteriores.

Sin embargo, los mismos patrones pueden ser generados por herramientas administrativas legítimas.

## Principio de análisis

Una conexión a los puertos 135 o 445 no confirma por sí sola un reconocimiento malicioso.

La clasificación debe combinar:

- Alcance.
- Velocidad.
- Destinos.
- Puertos.
- Autenticaciones.
- Identidades.
- Función del activo.
- Histórico.
- Actividad posterior.
- Disponibilidad de telemetría.

## Contenido

- [`investigation.md`](investigation.md): metodología y análisis.
- [`playbook.md`](playbook.md): procedimiento operativo.
- [`splunk-queries.md`](splunk-queries.md): consultas de investigación.
- [`detection-engineering.md`](detection-engineering.md): mejoras de detección y tuning.
- [`lessons-learned.md`](lessons-learned.md): conocimientos reutilizables.

## Datos mínimos requeridos

```text
{SOURCE_IP}
{SOURCE_HOST}
{EARLIEST}
{LATEST}
{DESTINATIONS}
{USERS}
{NETWORK_ACTION}
```

## Clasificaciones posibles

- Malicious True Positive.
- Benign True Positive.
- False Positive.
- Inconclusive.

## Estado

```yaml
title: RPC Targeted Recon
version: 1.0
status: operational
original_date: 2026-08-27
last_reviewed: 2026-09-01
review_cycle: 180-days
```
