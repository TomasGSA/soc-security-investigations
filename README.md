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


``text
soc-security-investigation
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── investigations/
│   ├── rpc-targeted-recon/
│   │   ├── README.md
│   │   ├── investigation.md
│   │   ├── playbook.md
│   │   ├── splunk-queries.md
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
