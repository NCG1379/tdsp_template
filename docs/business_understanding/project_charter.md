# Project Charter - Entendimiento del Negocio

## Nombre del Proyecto

Creación de agente IA usando LangChain Framework

## Objetivo del Proyecto

Implementar un agente de AI que tenga acceso a herramientas de inteligencia abierta (OSINT) para enriquecer indicadores de compromiso de red (IPs y Dominios), y establecer un nivel de riesgo potencial. 

## Alcance del Proyecto

### Incluye:

- Acceso a diferentes APIs abiertas: 
  - Virus Total: esta plataforma incluye información sobre la clasificación de _maliciousness_ de diferentes vendedores de ciberseguridad. 
  - AbuseIPDB: permite acceder a reportes de IPs siendo instrumentalizadas para ataques.
  - Whois: Entrega información de registro de IPs, así como características de geolocalización, organización y rangos de enrutamiento CIDR (Classless Inter-Domain Routing). 
- Se espera que el agente sea capaz de entregar información relacionada con las posibles amenazas asociadas a un indicador de compromiso, junto con un veredicto potencial de riesgo. Se espera que el agente sea capaz de invocar o utilizar las APIs o herramientas que se le incluirán. 
- Se considera un proyecto exitoso, si:
  - El agente es capaz de realizar búsquedas autónomas con las herramientas que tiene a disposición y le puedan brindar información relevante para una tarea dada.
  - El agente logre brindar información sobre la tarea que se le asigne (respecto a IPs o dominios), para facilitar la tarea de validación de _maliciousness_. 
  - Se entrega información reducida para el proceso de validación de IOCs, por ejemplo, una versión digerible o reducida del Whois. 

### Excluye:

- No se espera que genere reportes que se puedan exportar.
- Análisis con otros indicadores de compromiso, que no sean los mencionados en el proyecto. Por ejemplo:
  - IPv6.
  - URLs.
  - Hashes (MD5, Sha1, Sha26, etc.)
- Búsquedas en Internet
- Resolución de dominios o _Web Scrapping_

## Metodología

[Descripción breve de la metodología que se utilizará para llevar a cabo el proyecto]

## Cronograma

| Etapa | Duración Estimada | Fechas |
|------|---------|-------|
| Entendimiento del negocio y carga de datos | 1 semanas | del 25 de junio al 1 de julio |
| Preprocesamiento, análisis exploratorio | 1 semanas | del 2 de julio al 8 de julio |
| Modelamiento y extracción de características | 1 semanas | del 9 de julio al 15 de julio |
| Despliegue | 1 semanas | del 16 de julio al 22 de julio |
| Evaluación y entrega final | 1 semanas | del 23 de julio al 30 de julio |

Hay que tener en cuenta que estas fechas son de ejemplo, estas deben ajustarse de acuerdo al proyecto.

## Equipo del Proyecto

- Líder Proyecto - Diego Valero
- Científico de Datos - Jose Ávila
- Ciéntífico de Datos - Nicolas Cubillos

## Presupuesto

Integraciones
- Entorno: El proyecto se va a ejecutar sobre las máquinas de los integrantes del grupo, y se expondrá a través de un túnel con ngrok, lo que facilitará la interacción con el sistema, por lo que no se espera un costo adicional derivado de este componente. 
- Se harán pruebas con APIs que ofrecen un límite gratuito de consultas mensuales, suficiente para cubrir el alcance del proyecto. 
- Para el acceso a modelos grandes de lenguaje, se dispone de un crédito de 5 dólares en OpenAI, que se utilizará con el modelo de gpt-4.1-nano, que cuesta \$0.10 USD por 1M de tokens de entrada, y \$0.40 USD para 1M de tokens de salida.

Total presupuesto: \$5 USD

## Stakeholders

- [Nombre y cargo de los stakeholders del proyecto]
- [Descripción de la relación con los stakeholders]
- [Expectativas de los stakeholders]

## Aprobaciones

- [Nombre y cargo del aprobador del proyecto]
- [Firma del aprobador]
- [Fecha de aprobación]
