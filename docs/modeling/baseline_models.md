## Reporte del Modelo Baseline

## Descripción del modelo
El projecto está enfocado en automatizar el análisis inicial de indicadores de compromiso (IoCs), como direcciones IP y dominios observados en entornos corporativos. El agente implementado utiliza la arquitectura ReAct para interactuar de manera lógica con APIs especializadas: VirusTotal, WHOIS, AbuseIPDB y Shodan. Cada API ofrece datos sobre reputación, dueño, historial de abusos y nivel de exposición de los artefactos consultados.

Los resultados de las consultas se integran mediante un template en LangChain, que permite procesar y estructurar la información para su interpretación por modelos tipo OpenAI API, DeepSeek API o ClaudeAPI. El flujo principal consiste en tomar el indicador, consultar fuentes, estructurar la información y entregar al usuario un resumen (Summary), una recomendación (Recommendation) y un puntaje de riesgo (Score).

### Mejoras propuestas con un modelo ajustado con fine-tuning (Opcional)

Para superar limitaciones del agente de IA, se propone realizar el entrenamiento de Fine-Tuning usando LoRa, con Gemma 2B, el proceso se aplicaría al encoder. Este ajuste fino se realiza utilizando un dataset etiquetado donde cada ejemplo se asocia a un nivel de riesgo categórico: riesgo bajo Score (de 0 a 25), medio Score (de 26 a 60), alto Score (de 61 a 75) o crítico Score (de 75 a 100). El modelo entrenado pretende mejorar la manera de analizar el riesgo de los IoCs, mejorando la coherencia, interpretabilidad y precisión del Score y permitiendo recomendaciones más ajustadas. Esta solución, al estar basada en un LLM propio, disminuye la dependencia de APIs externas para la evaluación de riesgo.

![Descripción de la imagen](docs\modeling\images\18e275db-1afb-499d-b99b-774880d81699 (1).png)

# Variables de entrada

* Indicador: IP o dominio bajo investigación.

* Fuente de la alerta: Herramienta de seguridad que disparó la alerta (VirusTotal, AbuseIPDB, WHOIS, Shodan).

* Resultados crudos de las APIs: Datos recogidos tal cual de las APIs respectivas.

* Prompt al LLM: template con la información de las variables para ser pasado el LLM.

### Observaciones del analista: Elementos contextuales que el usuario quiera agregar para enriquecer la investigación.

### Estructura de mensaje

La plantilla envida a los LLMs (OpenAI, DeepSeek, Claude y LLM Local con fine-tuning), es ajustada con un mensaje que incluye el IoC y posterior se pasan las respuestas de las APIs de (VirusTotal, AbuseIPDB, WHOIS, Shodan), esto forma un contexto y una pregunta que el LLM apoya para resolver.

## Mejora con el modelo ajustado (Opcional)

Con el modelo Gemma 2B ajustado, la estructura de mensaje también incluye la categoría de riesgo esperada (label) en los ejemplos de entrenamiento, de modo que el encoder del modelo pueda aprender a discriminar rangos de entrada y asociarlos efectivamente a los niveles de riesgo definidos.

## Variable objetivo

Summary: Un resumen integrado y conciso, resultado de la síntesis de información cruzada entre las fuentes API.

Recommendation: Consejos accionables, orientados a la mitigación, priorización o desestimación de la alerta.

Score: Puntuación de riesgo cuantitativa (0-100)

### Mejora técnica con el modelo ajustado (Opcional)

Al incorporar el fine-tuning de Gemma 2B, la variable objetivo Score puede enriquecerse: el modelo aprende a mapear descripciones complejas y señales de alerta heterogéneas a etiquetas estándar de riesgo, produciendo evaluaciones de riesgo inherentes sin depender únicamente de reglas heurísticas o scoring de terceros.

## Evaluación del modelo

### Métricas de evaluación

Relevancia del Summary: Se compara la capacidad de síntesis del modelo, validando que capture los aspectos clave del IoC.

Precisión y utilidad de la Recommendation: Se evalúa que las recomendaciones sean directas, concretas y alineadas con las mejores prácticas de ciberseguridad.

Consistencia del Score: Se contrasta el puntaje/arquetipo de riesgo asignado por el modelo con la opinión de analistas expertos y con los valores entregados por las APIs originales.

Calidad del mensaje JSON: Se verifica la presentación, completitud y estructura (Summary, Recommendation, Score).

### Con el modelo ajustado (Opcional)

#### Las métricas se amplían:

* Exactitud en la clasificación de riesgo: Se utiliza un set de validación de ejemplos etiquetados para medir precisión, recall y F1-score en la asignación de la categoría de riesgo con el modelo entrenado.

* Generalización y robustez: Se analiza el desempeño del modelo ante ejemplos nuevos o con información incompleta, asegurando que las predicciones sean robustas y confiables.

## Análisis de los resultados

***Fortalezas***:

* Reducción del tiempo y carga mental del analista al automatizar la búsqueda y consulta en múltiples fuentes clave.

* Resultados estructurados y reutilizables en flujos de trabajo de seguridad.

* Alta extensibilidad: el flujo puede complementarse fácilmente con nuevas fuentes o modelos.

***Debilidades***:

* El modelo baseline depende fuertemente de la disponibilidad, latencia y formato consistente de las APIs.

* La puntuación de riesgo puede ser limitada a la información bruta y heurísticas simples.

* Escaso aprendizaje de patrones contextuales o señales "débiles".

### Mejora con el modelo ajustado (Opcional)

* Un encoder ajustado con fine-tuning en Gemma 2B mejora la capacidad de aprendizaje sobre patrones complejos y correlaciones no obvias entre datos de diferentes APIs.

* El modelo puede identificar y clasificar amenazas emergentes incluso en escenarios de datos incompletos.

* Reducción de fijación en heurísticas externas, logrando mayor autonomía, adaptabilidad y precisión contextual en la evaluación de riesgo.

## Conclusiones

La solución baseline provee una automatización robusta para la agregación de inteligencia sobre IoCs, facilitando análisis rápidos y respuestas accionables para los equipos de ciberseguridad. Sin embargo, integrar un modelo Gemma 2B ajustado vía fine-tuning —basado en etiquetas de riesgo categóricas— permitiría que el sistema no solo recopile y resuma la información, sino que clasifique amenazas y proponga respuestas de manera proactiva y alineada con la experiencia humana. Técnicamente, esto se implementa mediante la reentrenación del encoder con ejemplos históricos etiquetados, mejorando la precisión, autonomía y adaptabilidad ante nuevas amenazas.

## Referencias
https://github.com/amxn167/RiskScope

https://langchain-ai.github.io/langgraph/agents/agents/

https://medium.com/@umang91999/building-a-react-agent-with-langgraph-a-step-by-step-guide-812d02bafefa

https://python.langchain.com/docs/how_to/output_parser_json/