## VirusTotal API

**Analiza la reputación y características de dominios mediante motores antivirus e inteligencia colaborativa.**

| Variable                            | Descripción                                                 | Tipo de dato      | Rango/Valores posibles        | Fuente de datos |
|-------------------------------------|-------------------------------------------------------------|-------------------|-------------------------------|-----------------|
| Domain                              | Nombre del dominio analizado.                               | string            | Dominio válido (ej: google.com) | VirusTotal      |
| Categories                          | Clasificación temática asignada.                            | lista de string   | Tecnología, Finanzas, etc.    | VirusTotal      |
| Creation Date                       | Fecha de creación del dominio.                              | timestamp (int)   | Desde 1970 en UNIX time       | VirusTotal      |
| Last Analysis Date                  | Última fecha de análisis realizado.                         | timestamp (int)   | UNIX time                     | VirusTotal      |
| Last Analysis Stats - Harmless      | Nº de motores que lo consideran seguro.                     | int               | 0 a n                         | VirusTotal      |
| Last Analysis Stats - Malicious     | Nº de motores que lo marcan como malicioso.                 | int               | 0 a n                         | VirusTotal      |
| Last Analysis Stats - Suspicious    | Nº de motores que lo marcan como sospechoso.                | int               | 0 a n                         | VirusTotal      |
| Last Analysis Stats - Timeout       | Nº de motores que no completaron el análisis.               | int               | 0 a n                         | VirusTotal      |
| Last Analysis Stats - Undetected    | Nº de motores que no detectaron nada relevante.             | int               | 0 a n                         | VirusTotal      |
| Last Modification Date              | Fecha de la última modificación en el registro.             | timestamp (int)   | UNIX time                     | VirusTotal      |
| Reputation Score                    | Puntuación global de reputación del dominio.                | int               | 0 a 1000+                     | VirusTotal      |
| Tags                                | Etiquetas asociadas al dominio.                             | lista de string   | CDN, Ads, etc. o vacío        | VirusTotal      |
| Total Votes - Harmless              | Nº de votos como seguro por parte de usuarios.              | int               | 0 a n                         | VirusTotal      |
| Total Votes - Malicious             | Nº de votos como malicioso por parte de usuarios.           | int               | 0 a n                         | VirusTotal      |

---

## AbuseIPDB API

**Provee reputación y reportes comunitarios sobre direcciones IP con comportamiento abusivo.**

| Variable              | Descripción                                           | Tipo de dato       | Rango/Valores posibles                      | Fuente de datos |
|----------------------|-------------------------------------------------------|--------------------|---------------------------------------------|-----------------|
| ipAddress            | Dirección IP analizada.                               | string             | IPv4 o IPv6                                 | AbuseIPDB       |
| isPublic             | Si la IP es pública.                                  | boolean            | true / false                                | AbuseIPDB       |
| ipVersion            | Versión del protocolo IP.                             | int                | 4 o 6                                       | AbuseIPDB       |
| isWhitelisted        | Si la IP está en lista blanca.                        | boolean            | true / false                                | AbuseIPDB       |
| abuseConfidenceScore | Puntuación de confianza en los reportes de abuso.     | int                | 0 a 100                                     | AbuseIPDB       |
| countryCode          | Código de país asociado.                              | string             | ISO 3166-1 (ej. US, CO, DE)                  | AbuseIPDB       |
| usageType            | Tipo de uso de la IP.                                 | string             | CDN, ISP, Residencial, Empresarial, etc.     | AbuseIPDB       |
| isp                  | Proveedor de servicios de Internet.                   | string             | Nombre del ISP                               | AbuseIPDB       |
| domain               | Dominio asociado a la IP.                             | string             | Vacío o dominio válido                       | AbuseIPDB       |
| hostnames            | Nombres de host vinculados a la IP.                   | lista de string    | dns.google, etc.                             | AbuseIPDB       |
| isTor                | Si la IP pertenece a la red Tor.                      | boolean            | true / false                                | AbuseIPDB       |
| totalReports         | Número de reportes de abuso recibidos.                | int                | 0 a n                                        | AbuseIPDB       |
| numDistinctUsers     | Nº de usuarios únicos que reportaron la IP.           | int                | 0 a n                                        | AbuseIPDB       |
| lastReportedAt       | Fecha del último reporte recibido.                    | string (RFC 3339)  | Formato ISO 8601 con zona horaria            | AbuseIPDB       |

---

## Whois RDAP API

**Entrega detalles administrativos sobre bloques IP, entidades registrantes y eventos de asignación.**

| Variable                    | Descripción                                           | Tipo de dato           | Rango/Valores posibles                    | Fuente de datos |
|----------------------------|-------------------------------------------------------|------------------------|-------------------------------------------|-----------------|
| rdapConformance            | Estándares y perfiles RDAP soportados.               | lista de string        | nro_rdap_profile_0, cidr0, etc.           | Whois RDAP      |
| notices                    | Avisos legales y enlaces de términos.                | lista de diccionarios  | Términos, Copyright, etc.                 | Whois RDAP      |
| handle                     | Identificador del bloque IP asignado.                | string                 | NET-xxx-xxx-xxx                           | Whois RDAP      |
| startAddress               | IP inicial del bloque asignado.                      | string (IP)            | IP válida                                 | Whois RDAP      |
| endAddress                 | IP final del bloque.                                  | string (IP)            | IP válida                                 | Whois RDAP      |
| ipVersion                  | Protocolo IP utilizado.                               | string                 | "v4" o "v6"                               | Whois RDAP      |
| name                       | Nombre del recurso.                                   | string                 | Identificador amigable del registrante    | Whois RDAP      |
| type                       | Tipo de asignación.                                   | string                 | DIRECT ALLOCATION, REASSIGNED, etc.       | Whois RDAP      |
| parentHandle               | Recurso padre, si existe.                             | string                 | NET-xxx-xxx-xxx                           | Whois RDAP      |
| events                     | Registro de eventos (registro y cambios).            | lista de diccionarios  | evento + fecha ISO                        | Whois RDAP      |
| links                      | Enlaces asociados al recurso.                         | lista de diccionarios  | self, alternate                           | Whois RDAP      |
| entities                   | Información de contacto de entidades registrantes.   | lista de objetos       | registrante, técnico, abuso               | Whois RDAP      |
| port43                     | Dirección del servidor Whois tradicional.             | string                 | whois.arin.net                            | Whois RDAP      |
| status                     | Estado del recurso.                                   | lista de string        | active, validated, etc.                   | Whois RDAP      |
| objectClassName            | Tipo de objeto RDAP.                                  | string                 | ip network, entity                        | Whois RDAP      |
| cidr0_cidrs                | Bloques CIDR asociados.                               | lista de diccionarios  | v4prefix + longitud CIDR                  | Whois RDAP      |
| arin_originas0_originautnums | ASN asociado (si aplica).                         | lista                  | lista vacía o ASNs                        | Whois RDAP      |

---

## Shodan API

**Detecta servicios expuestos y propiedades técnicas de una dirección IP en Internet.**

| Variable          | Descripción                                               | Tipo de dato        | Rango/Valores posibles                         | Fuente de datos |
|------------------|-----------------------------------------------------------|---------------------|------------------------------------------------|-----------------|
| ip               | IP en formato numérico.                                   | int                 | Número entero                                  | Shodan          |
| ip_str           | IP en formato legible.                                    | string              | IPv4 o IPv6                                    | Shodan          |
| city             | Ciudad geolocalizada de la IP.                            | string              | Cualquier nombre de ciudad                     | Shodan          |
| region_code      | Código de región o estado.                                 | string              | Ej: CA, NY, etc.                               | Shodan          |
| country_code     | Código ISO del país.                                       | string              | Ej: US, CO                                     | Shodan          |
| country_name     | Nombre del país.                                           | string              | Ej: United States                              | Shodan          |
| latitude          | Latitud geográfica.                                       | float               | -90.0 a 90.0                                   | Shodan          |
| longitude         | Longitud geográfica.                                      | float               | -180.0 a 180.0                                 | Shodan          |
| area_code        | Código telefónico (si aplica).                             | int/null            | entero o null                                  | Shodan          |
| os               | Sistema operativo detectado.                               | string/null         | Linux, Windows, desconocido                    | Shodan          |
| hostnames        | Nombres de host asociados.                                 | lista de string     | Ej: dns.google                                 | Shodan          |
| domains          | Dominios relacionados a la IP.                             | lista de string     | Ej: google.com                                 | Shodan          |
| isp              | Proveedor de Internet.                                     | string              | Ej: Google LLC                                 | Shodan          |
| org              | Organización responsable de la IP.                         | string              | Ej: Google LLC                                 | Shodan          |
| tags             | Etiquetas descriptivas.                                    | lista               | IoT, control, industrial, etc.                 | Shodan          |
| ports            | Puertos detectados abiertos.                               | lista de int        | Ej: 443, 53, 22                                | Shodan          |
| last_update      | Última fecha de escaneo o actualización.                  | string (ISO 8601)   | Fecha y hora ISO                               | Shodan          |
| asn              | Número de sistema autónomo.                                | string              | Ej: AS15169                                    | Shodan          |
| data             | Información detallada por puerto y protocolo.              | lista de objetos    |