# Detection Engineering: RPC Targeted Recon

## Objetivo de detección

Identificar sistemas internos que contacten múltiples destinos mediante puertos RPC o SMB dentro de una ventana temporal reducida.

## Señales potenciales

- Una fuente contacta numerosos destinos internos.
- Las conexiones se concentran en pocos minutos.
- Se observa TCP 135 seguido de puertos dinámicos.
- La fuente contacta destinos nuevos.
- Se accede a varias subredes.
- Aparecen fallos de autenticación en múltiples sistemas.
- Se utilizan cuentas inesperadas.
- Se crean servicios o tareas después del reconocimiento.
- Se observan procesos asociados con administración remota.

## Enriquecimientos recomendados

- Función del activo.
- Propietario.
- Criticidad del origen.
- Criticidad de los destinos.
- Tipo de sistema.
- Cuenta asociada.
- Privilegios de la cuenta.
- Herramientas instaladas.
- Cambio aprobado.
- Ventana de mantenimiento.
- Histórico de destinos.
- Clasificación NAT, VIP, proxy o gateway.
- Estado del activo en EDR.

## Lógica conceptual

Una detección de mayor confianza debería combinar:

```text
Número elevado de destinos
+
Ventana temporal reducida
+
Puertos RPC o SMB
+
Desviación del histórico
+
Origen no administrativo
```

La severidad debería aumentar cuando exista:

```text
Autenticación anómala
+
Ejecución remota
+
Creación de servicio o tarea
+
Destino crítico
```

## Tuning recomendado

Considerar una reducción de severidad únicamente cuando:

- El origen sea una plataforma administrativa validada.
- La cuenta utilizada sea una cuenta de servicio autorizada.
- Los destinos pertenezcan al alcance esperado.
- El horario coincida con una ventana aprobada.
- El patrón sea consistente con el histórico.
- El propietario confirme el caso de uso.

## Tuning de riesgo elevado

Evitar exclusiones basadas únicamente en:

- IP.
- Hostname.
- Puerto.
- Cuenta.
- Subred.
- Nombre del producto.
- Ausencia de alertas EDR.

## Telemetría recomendada

- Eventos de tráfico normalizados.
- Event ID 4624.
- Event ID 4625.
- Event ID 4648.
- Event ID 4776.
- Event ID 5140.
- Event ID 5145.
- Event ID 4688.
- Event ID 4697.
- Event ID 4698.
- Event ID 4702.
- Event ID 7045.
- Telemetría EDR.
- CMDB.
- Información de identidad.
- Historial de cambios.

## Oportunidades de mejora

1. Crear una baseline por activo.
2. Calcular destinos únicos por minuto.
3. Identificar destinos nunca vistos.
4. Añadir criticidad de los destinos.
5. Diferenciar activos administrativos.
6. Correlacionar fallos y éxitos de autenticación.
7. Correlacionar procesos y servicios posteriores.
8. Añadir una puntuación por convergencia.
9. Establecer caducidad para las excepciones.
10. Revisar periódicamente las fuentes sin cobertura.

## Validación de la detección

- [ ] Verificar campos normalizados.
- [ ] Validar el cálculo de destinos únicos.
- [ ] Confirmar la ventana temporal.
- [ ] Revisar duplicados.
- [ ] Probar contra herramientas conocidas.
- [ ] Evaluar NAT y proxies.
- [ ] Confirmar puertos dinámicos.
- [ ] Comparar con casos maliciosos.
- [ ] Comparar con casos benignos.
- [ ] Documentar falsos positivos.
