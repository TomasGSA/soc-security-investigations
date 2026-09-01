# SOC Security Investigations

Repositorio de investigaciones de ciberseguridad orientado a documentar, estandarizar y mejorar los procesos de análisis realizados por un equipo de SOC

EL propósito de este proyecto es transformar investigaciones individuales en conocimiento reutilizable, incluyendo procedimientos de análisis, consultas, criterios de clasificaciones, oportunidades de mejora y lecciones aprendidas.

> ** Aviso de sanitización**
>
> Las direcciones IP, nombres de equipos, dominios, cuentas de usuario, identificadores,
> fechas y otros datos relacionados con entornos han sido eliminados o reemplazados por
> valores genéricos.
>
> El contenido de este repositorio se publica exclusivamente con fines educativos y
> defensivos.
>

## Objetivos

Los principales objetivos del repositorio son:

- Documentar investigaciones de alertas de seguridad.
- Crear procedimientos de análisis repetibles.
- Centralizar consultas utilizadas durante las investigaciones
- Identificar oportunidades de mejora en las reglas de detección
- Registrar limitaciones de telemetría y visibilidad.
- Conservar las lecciones aprendidas en cada caso.
- Facilitar la transferencia de conocimiento entre analistas.
- Promover la mejora continua de los procesos SOC.

## Alcance:

El repositorio puede incluir investigaciones relacionadas con:

- Alertas de Network Detection and Response.
- Actividad sospechosa detectada por soluciones EDR.
- Eventos de seguridad de Windows.
- Autenticaciones anómalas.
- Reconocimiento interno.
- Movimiento lateral.
- Ejecución Remota.
- Persistencia.
- Actividad relacionada con credenciales.
- Acceso a recursos compartidos.
- Creación de servicios y tareas programadas.
- Análisis de procesos y líneas de comandos.
- Mejoras y ajustes de reglas de deteccion.

## Tecnologías y fuentes de datos

Las investigaciones pueden utilizar informacion procedente de herramientas como:

- Vectra ID
- CrowdStrike
- Windows Security Events
- Firewall y telemetría de red.
- Active Directory.

Las consultas y procedimientos deben adaptarse a los nombres de índices, sorucetypes, campos y políticas de auditoria de cada entorno.


## Estructura del repositorio


```text
soc-security-investigation
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── investigations/
│   ├── [investiation name]/
│   │   ├── README.md
│   │   ├── investigation.md
│   │   ├── playbook.md
│   │   ├── [tool]-queries.md
│   │   ├── detection-engineering.md
│   │   └── lessons-learned.md
│   └── other-investigation/
├── templates/
│   ├── investigation-template.md
│   ├── playbook-template.md
│   └── detection-template.md
└── resources/
    ├── windows-event-ids.md
    ├── classification-criteria.md
    └── field-mapping.md
```

## Metodología
 
Las investigaciones siguen un enfoque basado en la convergencia de evidencias:
 
1. Definir la hipótesis de amenaza.
2. Validar la alerta original.
3. Confirmar el origen y la ventana temporal.
4. Determinar el alcance.
5. Analizar el patrón temporal.
6. Revisar la evidencia de red.
7. Revisar las identidades involucradas.
8. Analizar la telemetría del endpoint.
9. Comparar la actividad con el histórico.
10. Validar el contexto operativo.
11. Clasificar la actividad.
12. Documentar la conclusión.
13. Proponer acciones de respuesta o tuning.
14. Registrar las lecciones aprendidas.
  
Una alerta no debe clasificarse mediante un único indicador. La decisión debe considerar la combinación de evidencias de red, identidad, endpoint, activo, histórico y contexto operativo.

## Clasificaciones utilizadas

- Malicious True Positive: actividad real con evidencias suficientes de comportamiento malicioso.
- Benign True Positive: actividad real detectada correctamente, pero asociada con un uso autorizado.
- False Positive: la detección no representa el comportamiento descrito por la regla.
- Inconclusive: la evidencia disponible no permite establecer una conclusión fiable.
 
## Investigaciones disponibles

### RPC Targeted Recon
 
Metodología para investigar comunicaciones RPC originadas desde un único sistema hacia múltiples destinos.
 
Incluye:
 
- Alcance de red.
- Concentración temporal.
- Puertos RPC y SMB.
- Autenticaciones de Windows.
- Acceso a recursos compartidos.
- Procesos, servicios y tareas.
- Comparación histórica.
- Criterios de clasificación.
- Recomendaciones de respuesta.
- Propuestas de tuning.
 
Ubicación:

```text
investigations/rpc-targeted-recon/
```

## Formato Placeholders

Los datos específicos de cada entorno deben reemplazarse por valores genéricos

```text
{SOURCE_IP}
{SOURCE_HOST}
{DESTINATION_IP}
{DESTINATION_HOST}
{USERNAME}
{DOMAIN}
{EARLIEST}
{LATEST}
{ALERT_ID}
```





