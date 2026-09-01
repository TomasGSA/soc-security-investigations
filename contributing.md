# Contributing

Gracias por contribuir a este repositorio de investigaciones SOC.

El propósito de las contribuciones es mejorar la calidad de las investigaciones, estandarizar los procedimientos y compartir conocimientos defensivos sin revelar información confidencial.

## Tipos de contribuciones

Se aceptan contribuciones relacionadas con:

- Nuevas investigaciones
- Mejoras de playbooks.
- Correcciones de consultas.
- Nuevas consultas SIEM
- Mejoras de documentación
- Notas de ingeniería de detección.
- Criterios de clasificación.
- Mapeos de campos.
- Referencias técnicas.
- Lecciones aprendidas.
- Identificación de limitaciones de telemetria.

## Proceso para añadir una investigación

1. Crear una nueva carpeta dentro de `investigations/`.
2. Utilizar un nombre descriptivo en minúsculas y separado por guiones.
3. Copiar las plantillas disponibles en `templates/`-
4. Completar la investigación con información sanitizada.
5. Validar las consultas en un entorno autorizado.
6. Documentar fuentes de datos necesarias.
7. Indicar las limitaciones conocidas.
8. Añadir criterios de clasificacion.
9. Incluir oportunidades de mejora.
10. Actualizar el `README.md` principal.

Ejemplo:

```text
investigations/scheduled-task-creation/
├── README.md
├── investigation.md
├── playbook.md
├── splunk-queries.md
├── detection-engineering.md
└── lessons-learned.md
```

## Convención de nombres

Utilizar nombres descriptivos:

```text
rpc-targeted-recon
scheduled-task-creation
possible-ntds-extraction
as-rep-roasting
suspicious-msiexec-execution
remote-service-creation
```
Evitar:

```text
investigation-1
alert-new
case-final
test-folder
```

## Requisitos mínimos

Toda investigación debe incluir:

- Descripción del comportamiento.
- Hipótesis de amenaza.
- Datos mínimos de entrada.
- Fuentes de telemetría.
- Procedimiento de investigación.
- Evidencias que deben revisarse.
- Criterios de clasificación.
- Limitaciones.
- Acciones recomendadas. 
- Lecciones aprendidas.
 
 
## Sanitización

Antes de enviar una contribución, eliminar o reemplazar:

- Direcciones IP reales.
- Hostnames.
- Dominios internos.
- Usuarios.
- Cuentas de servicio.
- Direcciones de correo electrónico.
- Identificadores de alertas.
- Identificadores de incidentes.
- Nombres de clientes.
- Rutas internas sensibles.
- URLs privadas.
- Tokens.
- Cookies.
- Claves.
- Credenciales.
- Capturas con información confidencial.
- Configuraciones internas sensibles.
 
 
Utilizar placeholders como:

```text
{SOURCE_IP}
{HOSTNAME}
{USERNAME}
{DOMAIN}
{TIME_RANGE}
```
## Requisitos para consultas

Cada consulta debe incluir:
 
1. Objetivo.
2. Fuente de datos.
3. Placeholders requeridos.
4. Consulta.
5. Resultado esperado.
6. Campos importantes.
7. Indicadores que deben revisarse.
8. Limitaciones conocidas.
 
No incluir consultas destructivas ni acciones de contención automática sin advertencias y controles adecuados.
 
## Calidad de las conclusiones
 
Las conclusiones deben diferenciar claramente entre:
 
- Evidencia confirmada.
- Interpretación analítica.
- Suposiciones.
- Información no disponible.
- Limitaciones de cobertura.
 
La ausencia de eventos no debe presentarse como prueba de ausencia de actividad cuando la fuente de telemetría no esté disponible o no esté correctamente configurada.
 
## Estados del contenido
 
Cada investigación puede utilizar uno de estos estados:

- draft
- validated
- reviewed
- operational
- deprecated
 
## Pull requests
 
Las solicitudes de cambio deben explicar:
 
- Qué se modifica.
- Por qué es necesario.
- Qué investigación resulta afectada.
- Cómo se validaron las consultas.
- Si existen riesgos derivados del cambio.
- Si se añadieron nuevas dependencias de telemetría.
 
 
## Revisión
 
Antes de aprobar una contribución se debe comprobar:
 
- [ ] El contenido está sanitizado.
- [ ] La metodología es reproducible.
- [ ] Las consultas utilizan placeholders.
- [ ] Las limitaciones están documentadas.
- [ ] Las conclusiones no dependen de un único indicador.
- [ ] El contenido mantiene un enfoque defensivo.
- [ ] El historial de cambios está actualizado.
