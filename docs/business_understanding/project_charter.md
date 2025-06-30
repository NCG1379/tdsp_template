# Project Charter - Entendimiento del Negocio

## Nombre del Proyecto

Creación de agente IA usando LangChain Framework

## Objetivo del Proyecto

[Descripción breve del objetivo del proyecto y por qué es importante]

## Alcance del Proyecto

### Incluye:

- [Descripción de los datos disponibles]
- [Descripción de los resultados esperados]
- [Criterios de éxito del proyecto]

### Excluye:

- [Descripción de lo que no está incluido en el proyecto]

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

[Descripción del presupuesto asignado al proyecto]

## Stakeholders

- [Nombre y cargo de los stakeholders del proyecto]
- [Descripción de la relación con los stakeholders]
- [Expectativas de los stakeholders]

## Aprobaciones

- [Nombre y cargo del aprobador del proyecto]
- [Firma del aprobador]
- [Fecha de aprobación]
