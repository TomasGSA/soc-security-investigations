# Splunk Queries: RPC Targeted Recon

## Placeholders

```text
{SOURCE_IP}
{EARLIEST}
{LATEST}
```

Los nombres de índices y campos deben adaptarse al entorno.

## 1. Visión general del tráfico

### Objetivo

Identificar destinos, puertos, protocolos, acciones, volumen y duración.

```spl
| tstats summariesonly=false count
    min(_time) as first_seen
    max(_time) as last_seen
    sum(All_Traffic.bytes) as bytes
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src="{SOURCE_IP}"
  by All_Traffic.dest
     All_Traffic.dest_port
     All_Traffic.transport
     All_Traffic.action
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

### Revisar

- Cantidad de destinos.
- Puertos 135, 445 y 593.
- Puertos entre 49152 y 65535.
- Acciones allowed o blocked.
- Bytes.
- Destinos no habituales.
- Varias subredes.

---

## 2. Concentración RPC por minuto

### Objetivo

Identificar una posible ráfaga de enumeración automatizada.

```spl
| tstats summariesonly=false count
    dc(All_Traffic.dest) as unique_destinations
    values(All_Traffic.dest_port) as destination_ports
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src="{SOURCE_IP}"
    AND (
        All_Traffic.dest_port=135
        OR All_Traffic.dest_port=445
        OR All_Traffic.dest_port=593
        OR (
            All_Traffic.dest_port>=49152
            AND All_Traffic.dest_port<=65535
        )
    )
  by _time span=1m
| sort _time
```

### Interpretación

- Muchos destinos en uno o dos minutos: compatible con barrido automatizado.
- Pocos destinos durante horas: compatible con actividad sostenida.
- Mismo patrón diario: posible tarea o herramienta corporativa.
- Puerto 135 seguido de puertos altos: compatible con comunicación RPC.
- Solo eventos blocked: posible intento frustrado.

---

## 3. Acceso a recursos compartidos

### Objetivo

Buscar eventos 5140 y 5145 relacionados con el origen.

```spl
index="windows*" earliest="{EARLIEST}" latest="{LATEST}"
(EventCode=5140 OR EventCode=5145)
(
    IpAddress="{SOURCE_IP}"
    OR SourceAddress="{SOURCE_IP}"
)
| eval source_ip=coalesce(IpAddress,SourceAddress)
| eval username=coalesce(SubjectUserName,Account_Name,user)
| eval share=coalesce(ShareName,Share_Path)
| stats
    count
    values(RelativeTargetName) as accessed_objects
    values(AccessMask) as access_masks
  by host source_ip username share
| sort - count
```

### Validación de cobertura

```spl
index="windows*" earliest="{EARLIEST}" latest="{LATEST}"
(EventCode=5140 OR EventCode=5145)
| stats count by host EventCode
```

Si no existen eventos generales, registrar que la auditoría o ingestión puede no estar disponible.

---

## 4. Autenticaciones relacionadas

### Objetivo

Identificar autenticaciones exitosas, fallidas, uso explícito de credenciales y validaciones NTLM.

```spl
index="windows*" earliest="{EARLIEST}" latest="{LATEST}"
(
    EventCode=4624
    OR EventCode=4625
    OR EventCode=4648
    OR EventCode=4776
)
(
    IpAddress="{SOURCE_IP}"
    OR Source_Network_Address="{SOURCE_IP}"
    OR Workstation="{SOURCE_IP}"
)
| eval source_ip=coalesce(IpAddress,Source_Network_Address)
| eval username=coalesce(TargetUserName,Account_Name,user)
| stats
    count
    values(host) as destination_hosts
    dc(host) as unique_hosts
    values(Logon_Type) as logon_types
    values(status) as statuses
  by EventCode username source_ip
| sort - count
```

### Revisar

- Event ID.
- Usuario.
- Destinos.
- Logon Types.
- Resultado.
- Fallos seguidos de éxito.
- Cuentas privilegiadas.
- Uso de NTLM.

---

## 5. Procesos creados

### Objetivo

Buscar comandos o procesos que puedan indicar ejecución remota.

```spl
index="windows*" earliest="{EARLIEST}" latest="{LATEST}"
EventCode=4688
| eval process=coalesce(NewProcessName,ProcessName,process_name)
| eval command=coalesce(CommandLine,Process_Command_Line,process_command_line)
| eval parent=coalesce(ParentProcessName,Creator_Process_Name,parent_process_name)
| search process IN (
    "*\\cmd.exe",
    "*\\powershell.exe",
    "*\\pwsh.exe",
    "*\\wmic.exe",
    "*\\sc.exe",
    "*\\schtasks.exe",
    "*\\net.exe",
    "*\\net1.exe",
    "*\\reg.exe"
)
OR parent IN (
    "*\\WmiPrvSE.exe",
    "*\\services.exe"
)
| table _time host SubjectUserName parent process command
| sort _time
```

---

## 6. Servicios y tareas

### Objetivo

Identificar creación de servicios o tareas programadas.

```spl
index="windows*" earliest="{EARLIEST}" latest="{LATEST}"
(EventCode=7045 OR EventCode=4697 OR EventCode=4698 OR EventCode=4702)
| table
    _time
    host
    EventCode
    SubjectUserName
    ServiceName
    ImagePath
    TaskName
    TaskContent
| sort _time
```

---

## 7. Histórico de 30 días

### Objetivo

Determinar si el comportamiento es recurrente, nuevo o anómalo.

```spl
| tstats summariesonly=false count
    dc(All_Traffic.dest) as unique_destinations
  from datamodel=Network_Traffic.All_Traffic
  where earliest=-30d@d latest=now
    All_Traffic.src="{SOURCE_IP}"
    AND (
        All_Traffic.dest_port=135
        OR All_Traffic.dest_port=445
        OR All_Traffic.dest_port=593
        OR (
            All_Traffic.dest_port>=49152
            AND All_Traffic.dest_port<=65535
        )
    )
  by _time span=1h
| timechart span=1h
    max(unique_destinations) as destinations_per_hour
    sum(count) as connections
```

## Limitaciones

- Los nombres de campos dependen del add-on.
- La ausencia de 5140 o 5145 puede indicar falta de auditoría.
- Event ID 4688 puede no incluir la línea de comandos.
- La telemetría de red puede identificar una IP compartida.
- Los puertos RPC dinámicos requieren correlación temporal.
