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

En este proyecto se va a utilizar la metodología CRISP-DM, enfocada a la implementación un agente de inteligencia artificial capaz de extraer información de varias fuentes de datos de ciber inteligencia, ofreciendo un frontend para poder traer información de las IPs y dominios que un profesional en ciberseguridad requiera para en análisis de riesgo de indicadores de compromiso.

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*hcyFS7bnLbg2tmthUnLuVQ.png" width="80%">

Se presentan las fases con el alcance que van a tener en el proyecto:

### Entendimiendo del negocio:

* Entender el contexto del proyecto.
* Definir lo esperado con alcance.
* Definir las métricas de éxito.
* Conocer los stakeholders del proyecto.
* Validar las fuentes de los datos.

### Entendimiendo de los datos:

* Validar la conexión de las APIs mediante los tokens.
* Traer datos de las APIs.
* Trabajar los datos de las APIs para entender los parámetros.
* Confirmar que las fuentes funcionan de manera adecuada para la implementación.

### Preparación de los datos:

* Preparar las consultas del agente.
* Validar las funciones que el agente va a usar.

### Análisis y Modelado:

* Implementar el agente AI con el LLM de OpenAI.
* Agregar las funciones de consulta de las APIs.
* Uso del framework de LangChain para mejora en el procesamiento de la información y templates de consulta.
* Configurar el frontend para que muestre la información consultada.

### Validación:

* Se va buscar IPs y dominios en reportes de CTI para extración de IoCs del último mes.
* Validación manual de mínimo 30 IoCs para categorización por parte del agente.
* Tabulación de resultados de la categorización del agente.

### Presentación y visualización:

* Frontend expuesto mediante pyngrok para que el web service del frontend pueda ser usado desde la web.


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

- Gerente de Ciberseguridad: es el encargado de aprobar la facturación previamente informado por el equipo SOC y de cacería de amenazas del cumplimiento de los acuerdos de éxito del proyecto.
- Analista SOC: profesional capacitado en la revisión de eventos y gestión de incidentes de ciberseguridad.
- Cazador de Amenazas: profesional capacitado en la revisión de eventos e indicadores de compromiso para validar la efectividad de los controles en una empresa para la detección de los ciberatacantes.
- Profesionales de ciberseguridad: profesionales de las diferentes ramas interesados en validar IoCs de IPs y dominios maliciosos.


- Los stakeholders esperan que esta herramienta de inteligencia artificial pueda apoyarlos en su día a día, para revisar y comprobar los IoC que les llegan diariamente o los que se detectan por las herramientas de monitoreo, para comprobar su nivel de riesgo, facilitando la tarea de búsqueda y priorización de los riesgos.

## Aprobaciones

- Diego Valero (Product Manager)
- Diego Fernando Valero Molano
- 30/06/2025
