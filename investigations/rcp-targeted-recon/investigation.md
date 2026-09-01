# RPC Targeted Recon Investigation

## 1. Objetivo

Determinar si un volumen elevado de solicitudes RPC originadas desde una única IP corresponde a reconocimiento malicioso, actividad administrativa autorizada, una herramienta corporativa o una detección incorrecta.

## 2. Descripción del comportamiento

La detección identifica un sistema que establece comunicaciones RPC con múltiples destinos.

Este comportamiento puede estar relacionado con:

- Descubrimiento de sistemas.
- Enumeración de servicios.
- Enumeración de recursos compartidos.
- Descubrimiento de usuarios o cuentas.
- Resolución de endpoints RPC.
- Administración remota.
- Preparación de movimiento lateral.

También puede aparecer en:

- Servidores de administración.
- Jump servers.
- SCCM u otras plataformas de distribución.
- Sistemas de inventario.
- Herramientas de backup.
- Sistemas de monitorización.
- Escáneres autorizados.
- Infraestructura de dominio.

## 3. Hipótesis

### Hipótesis maliciosa

El sistema origen está realizando reconocimiento interno automatizado para identificar destinos, servicios o recursos que puedan utilizarse en una fase posterior.

### Hipótesis benigna

El sistema origen realiza una función administrativa autorizada y el patrón coincide con su rol, propietario, horario, cuentas y comportamiento histórico.

### Hipótesis de falso positivo

La actividad fue atribuida incorrectamente debido a NAT, proxy, VIP, gateway, duplicación, normalización incorrecta o interpretación errónea de los campos.

## 4. Datos mínimos de entrada

- IP de origen.
- Hostname de origen.
- Función del activo.
- Propietario.
- Hora de inicio.
- Hora de finalización.
- Destinos.
- Puertos.
- Protocolos.
- Acción de red.
- Usuarios relacionados.
- Criticidad de los destinos.
- Histórico del origen.

## 5. Dominios de evidencia

### 5.1 Red

Determinar:

- Cantidad de destinos.
- Destinos únicos.
- Puertos utilizados.
- Protocolos.
- Acciones allowed o blocked.
- Bytes transferidos.
- Duración.
- Distribución entre subredes.
- Destinos nuevos.
- Criticidad de los destinos.

### 5.2 Patrón temporal

Determinar:

- Número de destinos por minuto.
- Concentración de conexiones.
- Actividad secuencial.
- Repetición diaria.
- Horario habitual.
- Primera aparición.
- Comportamiento sostenido o en ráfaga.

### 5.3 Identidad

Revisar los siguientes eventos:

- 4624: autenticación exitosa.
- 4625: autenticación fallida.
- 4648: credenciales explícitas.
- 4776: validación NTLM.

Determinar:

- Usuarios involucrados.
- Tipos de inicio de sesión.
- Sistemas destino.
- Fallos seguidos de éxito.
- Cuentas privilegiadas.
- Cuentas humanas frente a cuentas de servicio.

### 5.4 Recursos compartidos

Buscar eventos:

- 5140.
- 5145.

Clasificar el resultado como:

- Acceso confirmado.
- Acceso no observado.
- Sin cobertura suficiente.

La ausencia de estos eventos no confirma que no hubiera actividad SMB, porque su disponibilidad depende de la auditoría y de la ingestión.

### 5.5 Endpoint y actividad posterior

Buscar:

- Creación de procesos.
- Ejecución remota.
- Creación de servicios.
- Creación o modificación de tareas.
- Procesos hijos de `WmiPrvSE.exe`.
- Procesos hijos de `services.exe`.
- Uso de shells o herramientas administrativas.
- Comandos codificados.
- Rutas temporales.
- Binarios no estándar.

Eventos relevantes:

- 4688.
- 7045.
- 4697.
- 4698.
- 4702.

## 6. Interpretación

### Indicadores de riesgo elevado

- Muchos destinos en uno o dos minutos.
- Destinos nuevos o secuenciales.
- Varias subredes afectadas.
- Conexiones a puertos administrativos.
- Puerto 135 seguido de puertos RPC dinámicos.
- Múltiples autenticaciones fallidas.
- Fallos seguidos de éxito.
- Cuentas inesperadas.
- Creación posterior de servicios o tareas.
- Ejecución mediante WMI.
- Primera aparición del comportamiento.
- Destinos críticos.

### Indicadores de actividad potencialmente benigna

- Origen identificado como herramienta corporativa.
- Cuenta de servicio validada.
- Destinos dentro del alcance esperado.
- Patrón estable y recurrente.
- Horario aprobado.
- Actividad vinculada a un cambio.
- Propietario conocido.
- Volumen consistente con el histórico.

## 7. Matriz de evidencia

### Red

- **Bajo:** pocos destinos conocidos.
- **Medio:** varios destinos parcialmente conocidos.
- **Alto:** muchos destinos nuevos o secuenciales.

### Tiempo

- **Bajo:** actividad sostenida y recurrente.
- **Medio:** picos moderados.
- **Alto:** ráfaga rápida.

### Identidades

- **Bajo:** cuenta de servicio validada.
- **Medio:** usuario administrativo esperado.
- **Alto:** múltiples cuentas inesperadas o numerosos fallos.

### Actividad posterior

- **Bajo:** herramienta autorizada.
- **Medio:** sin visibilidad suficiente.
- **Alto:** WMI, servicios, tareas o comandos sospechosos.

### Histórico

- **Bajo:** patrón estable.
- **Medio:** histórico insuficiente.
- **Alto:** primera aparición o desviación significativa.

## 8. Clasificación

### Malicious True Positive

Aplicar cuando exista convergencia entre varios indicadores:

- Origen no administrativo.
- Ráfaga horizontal.
- Destinos nuevos.
- Cuentas inesperadas.
- Fallos o éxitos anómalos.
- Ejecución remota.
- Persistencia.
- Actividad posterior sospechosa.

### Benign True Positive

Aplicar cuando:

- La detección refleje actividad RPC real.
- La herramienta o tarea esté autorizada.
- El propietario confirme el comportamiento.
- Los destinos estén dentro del alcance esperado.
- El patrón coincida con el histórico.

### False Positive

Aplicar cuando:

- La IP esté mal atribuida.
- Exista NAT, VIP o proxy.
- Los eventos estén duplicados.
- Los campos estén mal normalizados.
- El volumen real no cumpla la lógica de detección.

### Inconclusive

Aplicar cuando:

- Falten registros esenciales.
- No se conozca la función del activo.
- No pueda validarse el usuario.
- No exista histórico.
- No se pueda confirmar el propietario.
- La atribución de red no sea fiable.

## 9. Limitaciones

- Sin Sysmon no puede atribuirse directamente una conexión de red a un proceso mediante Event ID 3.
- Event ID 4688 requiere auditoría de creación de procesos.
- La línea de comandos de 4688 necesita configuración adicional.
- Los eventos 5140 y 5145 dependen de la auditoría de recursos compartidos.
- El puerto 445 no confirma acceso a una carpeta compartida.
- Los puertos altos pueden corresponder a endpoints RPC dinámicos.
- Una IP puede representar NAT, proxy, VIP, gateway o un sistema compartido.
- Los nombres de campos pueden variar según el add-on y el sourcetype.

## 10. Conclusión

La clasificación debe basarse en la convergencia de evidencias.

No debe asumirse que la actividad es maliciosa únicamente por observar comunicaciones hacia los puertos 135 o 445. Tampoco debe cerrarse como benigna únicamente por el nombre o función aparente del activo.
