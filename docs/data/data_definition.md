# Definición de los datos

## Origen de los datos

- [ ] Los datos provienen debases de datos abiertas. Hay dos tipos de fuentes de datos utilizadas en este proyecto, la primera es una lista de IPs/dominios que indican tráfico malicioso, y la otra fuente de datos, va a estar dada por conexión a las APIs de terceros, como se indica a continuación:
  - Maltrail: un repositorio que proveé información de tráfico malicioso, utilizando listas de bloqueo públicas.
  - VirusTotal: Un sistema que permite obtener información de inteligencia de amenazas, asociadas a diferentes indicadores de compromiso, para este proyecto se enfoca en IPv4 y dominios.
  - AbuseIPDB: Este sitio contiene información relacionada con la reputación de las ips, indicando el motivo del reporte, en los casos que esté disponible. 
  - Shodan: es un motor de búsqueda que permite extraer información de los dispositivos conectados a internet, incluye información muy útil para investigación en ciberseguridad.  

## Especificación de los scripts para la carga de datos

- [ ] Para la carga de datos, se hace uso de scripts/data_acquisition/dfaq_main.py, que va a actuar como gestor de las APIs que se van a consultar. 

## Referencias a rutas o bases de datos origen y destino

#### TODO especificar cómo vamos a almacenar los datos extraídos de las apis. 
- [ ] Especificar las rutas o bases de datos de origen y destino para los datos.

### Rutas de origen de datos

- [ ] Los archivos de origen se extraen de las bases de datos, a través de las APIs de terceros, y se almacenan en la carpeta de outputs. Este proceso garantiza la recolección sistemática de información bruta de diversas plataformas de inteligencia de amenazas y OSINT.
- [ ] Los archivos de origen tienen una estructura de documentos tipo JSON, cuyos campos varían dependiendo de la API consultada y de cada caso particular. 
  - VirusTotal: Documentos JSON que incluyen un veredicto consolidado de exposición o nivel de compromiso (ej., malicioso, sospechoso, limpio, no detectado), el ratio de detección por motores antivirus, etiquetas contextuales relevantes (ej., phishing, malware, C2), y metadatos sobre comunicaciones o archivos asociados.
  - Shodan: Los documentos de Shodan detallan configuraciones de red, puertos abiertos, servicios específicos (con versiones y banners), información de geolocalización, la organización o ISP asociada y posibles vulnerabilidades (CVEs) detectadas.
  - AbuseIPDB: Proporciona una métrica de medición de abuso, el número y las categorías de los reportes recibidos (ej., DDoS Attack, Fraud, Port Scan), y metadatos sobre el último reporte, aunque los detalles específicos de cada incidente reportado pueden variar para cada caso.
  - WHOIS: La estructura del WHOIS varía significativamente según el _top level domain_ (TLD) y las políticas de privacidad. Generalmente incluye el registrant, fechas importantes como la creación, actualización y/o expiración del dominio; nombre de servidores (DNS), y detalles de contacto.
- [ ] Para los procesos de entendimiento de los datos, se aprovecha una de las capacidades de los modelos grandes de lenguaje, y es la capacidad de poder trabajar con datos en diferentes estructuras, por lo que el agente deberá integrar en su respuesta los valores que considere relevantes.

### Base de datos de destino

#### TO-DO definir base de datos destino
- [ ] Especificar la base de datos de destino para los datos.
- [ ] Especificar la estructura de la base de datos de destino.
- [ ] Describir los procedimientos de carga y transformación de los datos en la base de datos de destino.
