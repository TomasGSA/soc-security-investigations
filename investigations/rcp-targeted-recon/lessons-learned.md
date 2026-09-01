# Lessons Learned: RPC Targeted Recon

## Lecciones técnicas

1. El tráfico hacia TCP 445 no confirma acceso a una carpeta compartida.
2. RPC puede comenzar en TCP 135 y continuar mediante puertos dinámicos.
3. Una ráfaga contra muchos destinos es más sospechosa que una comunicación sostenida con pocos sistemas conocidos.
4. Una autenticación exitosa no confirma actividad maliciosa.
5. Los eventos 5140 y 5145 dependen de la configuración de auditoría.
6. La ausencia de eventos no demuestra ausencia de actividad.
7. Event ID 4688 puede no contener la línea de comandos.
8. Sin Sysmon Event ID 3 resulta más difícil atribuir conexiones a procesos.
9. NAT, VIP, proxies y gateways pueden afectar la atribución.
10. El histórico es esencial para diferenciar administración de reconocimiento.

## Lecciones de proceso

- Confirmar siempre la función del activo.
- Validar el propietario antes de cerrar.
- Documentar qué telemetría falta.
- Diferenciar entre “no observado” y “sin cobertura”.
- No utilizar un único indicador como veredicto.
- No crear allowlists basadas únicamente en IP.
- Establecer una fecha de revisión para las excepciones.
- Separar la conclusión del ticket de las recomendaciones de tuning.
- Mantener consultas parametrizadas.
- Adaptar los campos al entorno.

## Mejoras identificadas

- Mantener una baseline de conexiones RPC por activo.
- Enriquecer con CMDB.
- Añadir criticidad de destino.
- Identificar activos administrativos.
- Correlacionar red, identidad y endpoint.
- Mejorar la cobertura de eventos 5140 y 5145.
- Habilitar líneas de comandos en Event ID 4688.
- Documentar activos detrás de NAT o VIP.
- Revisar excepciones periódicamente.

## Preguntas para futuras investigaciones

- ¿El origen suele contactar los mismos destinos?
- ¿El comportamiento coincide con una tarea programada?
- ¿La cuenta pertenece al sistema?
- ¿Los destinos corresponden al alcance esperado?
- ¿Existió actividad posterior?
- ¿La detección ocurre siempre en el mismo horario?
- ¿Qué cambió respecto al histórico?
- ¿La ausencia de logs se debe a actividad inexistente o falta de cobertura?
