# Reporte del Modelo Final

## Resumen Ejecutivo

El modelo final ofrece un análisis robusto y consistente para IPs y dominios, integrando datos de VirusTotal, WHOIS, AbuseIPDB y Shodan. La revisión humana confirma que los resultados generados, incluyendo resúmenes y recomendaciones, son precisos y cumplen con las expectativas. Esto valida la capacidad del modelo para automatizar la evaluación inicial de amenazas, optimizando recursos. La salida en formato JSON estandariza y facilita el procesamiento, para integración con herramientas de front-end.

## Descripción del Problema

Los operadores de ciberseguridad tienden a analizar diferentes indicadores de que la red haya podido haberse comprometido por actores maliciosos, estos indicadores normalmente se ven como alertas en herramientas de defensa. Uno de los puntos neurálgicos de la tarea de revisión, radica en la necesidad del operador de obtener información de diferentes fuentes abiertas, cómo resultado, requiere hacer un proceso continuo de llevar o copiar el indicador de red, y pegarlo en plataformas como VirusTotal, AbuseIPDB, Whois, etc., para poder obtener información relacionada con el artefacto que se está analizando, este proceso es desgastante y puede tomar mucho tiempo, además de poder obtener una idea rápida respecto a si el indicador representa un riesgo.

Otro de los retos que resultan de dicho proceso de operación de la ciberseguridad en las compañías, se relaciona con la interpretación, e incluso normalización de las características (ya que una misma herramienta puede devolver diferentes campos para diferentes indicadores). 

Así pues, se busca explotar las capacidades de los LLMs para procesar en segundos múltiples fuentes de información, y generar un reporte que evidencie las razones detrás de cada conclusión que el modelo extraiga de los datos, para que pueda servir como herramienta para que los operadores de ciberseguridad tengan acceso a la base de conocimientos que requieren para tomar decisiones, basado en un pseudo-análisis o resúmen de los datos que ya utilizan hoy en día, para llevar a cabo las investigaciones que tuvieran lugar, si se sospecha que la red fue comprometida. 

## Descripción del Modelo

El sistema emplea agentes basados en LLMs para el análisis de seguridad de IPs y dominios. Implementamos tres modelos independientes que operan en paralelo, permitiendo un análisis A/B testing concurrente para cada consulta. Esto no solo optimiza la obtención de resultados diversos, sino que también facilita la comparación y el refinamiento continuo.

La arquitectura subyacente se construye sobre LangChain y LangGraph, proporcionando un marco flexible para la orquestación de los agentes. Cada agente accede a herramientas externas como VirusTotal, WHOIS, AbuseIPDB y Shodan, asegurando una recolección de datos exhaustiva.

La coherencia y calidad de las respuestas se logran mediante un proceso iterativo de refinamiento de prompts. Este enfoque optimiza la interacción entre el LLM y las herramientas, asegurando que las salidas en formato JSON sean consistentemente pertinentes y bien estructuradas.

El flujo de trabajo de cada agente se define mediante una máquina de estados: el agente inicia, el asistente (LLM) procesa la solicitud, y si necesita más información, consulta las herramientas. Este ciclo se repite hasta que el asistente tiene suficiente información para generar la respuesta final.


## Evaluación del Modelo

La evaluación del modelo se centró en la calidad y utilidad de las respuestas generadas, dada la naturaleza cualitativa del análisis de seguridad y la intervención humana en la validación. En lugar de métricas cuantitativas tradicionales de clasificación (como precisión o recall), nos enfocamos en:

* Coherencia y Relevancia del Resumen: ¿El resumen captura los puntos clave del análisis de la IP/dominio? ¿Es conciso y fácil de entender? La evaluación humana confirmó que los resúmenes son altamente relevantes y coherentes, sintetizando eficazmente la información de múltiples fuentes.
* Claridad y Accionabilidad de la Recomendación: ¿Las recomendaciones son claras, específicas y útiles para la toma de decisiones de seguridad? Se encontró que las recomendaciones son directas y prácticas, ofreciendo pasos concretos basados en el análisis de riesgo.
* Confiabilidad del Score de Riesgo: ¿El "Score" asignado refleja adecuadamente el nivel de amenaza percibido, alineándose con la interpretación de los analistas humanos? La revisión validó que el score es un indicador fiable que se correlaciona con la complejidad y severidad de las señales detectadas.
* Completitud de la Información JSON: ¿El formato JSON incluye todos los campos esperados y la información es correctamente estructurada? Se verificó que la salida JSON es completa y cumple con el esquema predefinido, facilitando su integración por otros sistemas, para despliegue en el front, y almacenamiento en MongoDB.

En resumen, la evaluación cualitativa y la revisión humana confirmaron que el modelo produce resultados fiables y consistentes que se alinean con las expectativas de los operadores. La capacidad de integrar y sintetizar información de herramientas diversas en un formato útil y estandarizado es su principal fortaleza, validando su eficacia en un entorno de seguridad dinámico.


## Conclusiones y Recomendaciones

El modelo es una herramienta eficaz para el análisis de seguridad de IPs y dominios, validado por la revisión humana. Su principal fortaleza es la automatización de la recolección y síntesis de datos de diversas fuentes (VirusTotal, WHOIS, AbuseIPDB, Shodan), con posibilidad de extensión a más herramientas, entregando análisis accionables en JSON. Esto acelera la toma de decisiones y reduce el trabajo manual.

Sin embargo, el modelo depende de la disponibilidad y calidad de las APIs externas; fallos o cambios en estas pueden afectar su rendimiento. Aunque el refinamiento de prompts minimiza los riesgos, la naturaleza de los LLMs siempre deja un pequeño margen para respuestas inesperadas, riesgo que la revisión humana actual controla.

Aplicaciones Sugeridas
* Priorización: Evaluar rápidamente alertas de seguridad.
* Inteligencia de Amenazas: Enriquecer bases de datos de IOCs con contexto.
* Investigación Forense: Obtener puntos de partida rápidos.
* Automatización de SecOps: Integrar el análisis en flujos de trabajo de seguridad para respuestas más ágiles.

A futuro, recomendamos integrar más fuentes de datos y permitir la adaptación de recomendaciones a políticas de seguridad específicas. También, es clave el monitoreo continuo en ambientes productivos para mejorar el refinamiento de prompts y la utilidad del proyecto.


## Referencias

* https://github.com/amxn167/RiskScope
* https://langchain-ai.github.io/langgraph/agents/agents/
* https://medium.com/@umang91999/building-a-react-agent-with-langgraph-a-step-by-step-guide-812d02bafefa
* https://python.langchain.com/docs/how_to/output_parser_json/