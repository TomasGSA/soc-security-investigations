# Security Policy

## Propósito
 
Este repositorio contiene procedimientos, consultas y documentación de seguridad defensiva. Ningún contenido debe exponer información confidencial de clientes, organizaciones o entornos reales.
 
## Información que no debe publicarse
 
No se debe incluir:
 
- Credenciales.
- Contraseñas.
- Tokens de acceso.
- Claves privadas.
- Certificados privados.
- Cookies de sesión.
- Direcciones IP asociadas con clientes.
- Hostnames reales.
- Dominios internos.
- Cuentas de usuario.
- Cuentas de servicio.
- Direcciones de correo electrónico.
- Identificadores de incidentes.
- Identificadores de alertas.
- Nombres de clientes.
- Diagramas internos no autorizados.
- URLs privadas.
- Capturas de herramientas con datos sensibles.
- Reglas que revelen controles internos sensibles.
- Información que permita identificar debilidades activas de una organización.
 
## Sanitización obligatoria
 
Antes de publicar cualquier investigación:
 
1. Reemplazar valores reales por placeholders.
2. Revisar capturas de pantalla y metadatos.
3. Eliminar comentarios que identifiquen al cliente.
4. Verificar el historial de Git antes de realizar el push.
5. Comprobar que no existan secretos en archivos eliminados o versiones anteriores.
6. Validar que los ejemplos no permitan reconstruir el entorno original.
 
## Reporte de problemas de seguridad
 
Si se identifica información sensible en el repositorio:
 
1. No abrir un issue público.
2. Contactar de forma privada con el responsable del repositorio.
3. Indicar el archivo y la línea afectados.
4. Describir el tipo de información expuesta.
5. No redistribuir ni copiar la información.
6. Esperar la remediación antes de realizar una divulgación adicional.
 
 
## Respuesta ante una exposición
 
Cuando se confirme una exposición:
 
1. Retirar temporalmente el contenido.
2. Evaluar si existen credenciales o secretos comprometidos.
3. Revocar o rotar los secretos cuando corresponda.
4. Eliminar la información del historial de Git.
5. Revisar forks y copias cuando sea posible.
6. Documentar la causa.
7. Aplicar controles para evitar recurrencias.
 
## Uso responsable
 
El contenido debe utilizarse exclusivamente para:
 
- Investigación defensiva.
- Detección de amenazas.
- Respuesta a incidentes.
- Formación de analistas.
- Mejora de controles.
- Validación de telemetría.
 
Las consultas deben ejecutarse únicamente en sistemas para los que se disponga de autorización.
