# Investigación de posible DCSync en Active Directory

Repositorio técnico que documenta la investigación de una posible actividad **DCSync** detectada mediante búsquedas de derechos de replicación de Active Directory.

La investigación comenzó tras localizar el GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, asociado a **DS-Replication-Get-Changes-All**. El análisis posterior determinó que el GUID aparecía dentro del atributo `nTSecurityDescriptor` de eventos **5136**, y no como un derecho ejercido dentro de las propiedades de un evento **4662**.

## Resultado ejecutivo

**Clasificación provisional:** actividad probablemente legítima o falso positivo de la búsqueda por GUID.

Los registros analizados mostraron:

- Eventos Windows Security `5136`.
- Modificaciones del atributo `nTSecurityDescriptor`.
- Objetos de clase `dnsNode` bajo `MicrosoftDNS` y `DomainDnsZones`.
- Operaciones ejecutadas como `NT AUTHORITY\\SYSTEM`.
- Pares de eventos `Value Deleted` y `Value Added`.
- Actividad registrada directamente en controladores de dominio.
- Ausencia de eventos `4662` que demuestren el ejercicio de derechos de replicación.
- Ausencia de una cuenta o dirección IP no autorizada asociada a una solicitud de replicación.

La presencia de un GUID de replicación dentro de una ACE o descriptor de seguridad **no demuestra por sí sola la ejecución de DCSync**.

## Estructura del repositorio

```text
.
├── README.md
├── investigation.md
├── detection-engineering.md
├── playbook.md
└── leassons-learned.md
```

| Archivo | Finalidad |
|---|---|
| `README.md` | Resumen, contexto y navegación del repositorio. |
| `investigation.md` | Evidencias, análisis, hipótesis y conclusión del caso. |
| `detection-engineering.md` | Propuesta de lógica de detección y reducción de falsos positivos. |
| `playbook.md` | Procedimiento reutilizable para futuras investigaciones. |
| `leassons-learned.md` | Lecciones aprendidas y acciones de mejora. |

## Distinción técnica principal

```text
5136 + GUID dentro de nTSecurityDescriptor
= el GUID forma parte de una ACL que fue escrita, reemplazada o normalizada

4662 + AccessMask 0x100 + GUID en Properties
= una identidad ejerció un derecho de control de acceso potencialmente relacionado
  con una solicitud de replicación
```

## GUID relevantes

| GUID | Derecho de Active Directory |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

## Uso del contenido

1. Consulta [`investigation.md`](investigation.md) para revisar el razonamiento del caso.
2. Utiliza [`playbook.md`](playbook.md) durante investigaciones futuras.
3. Adapta las consultas documentadas en [`detection-engineering.md`](detection-engineering.md) al esquema de campos de tu SIEM.
4. Revisa [`leassons-learned.md`](leassons-learned.md) antes de modificar reglas de alertado.

## Consideraciones

- Las consultas utilizan nombres de campo comunes en Splunk, pero pueden requerir adaptación.
- La ausencia de eventos `4662` no descarta DCSync si la auditoría, las SACL o la ingestión no están correctamente configuradas.
- Las exclusiones deben basarse en inventarios y fuentes autorizadas, no únicamente en nombres de cuenta.
- Los valores de hosts, cuentas e IP incluidos corresponden al caso analizado y deben sustituirse en futuras investigaciones.

## Referencias técnicas

- [Microsoft Learn: Event 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662)
- [Microsoft Learn: Event 5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)
- [Splunk Security Content: AD Replication Request from Unsanctioned Location](https://research.splunk.com/endpoint/50998483-bb15-457b-a870-965080d9e3d3/)

## Estado

Investigación documentada y preparada para reutilización por equipos SOC, DFIR, Active Directory y Detection Engineering.
