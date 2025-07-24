# Informe de salida

## Resumen Ejecutivo

Este informe presenta los resultados alcanzados en el proyecto "Agentes de IA para Análisis de Indicadores de Compromiso" orientado a la gestión y análisis de indicadores de compromiso (IoCs), mediante inteligencia artificial y APIs de inteligencia abierta (OSINT). Durante el desarrollo se cumplió con el despliegue de la arquitectura contenerizada, integración de las fuentes de datos relevantes, la implementación del agente IA y la entrega de una interfaz web para su uso por profesionales en ciberseguridad. Se lograron los objetivos de automatización y enriquecimiento de información para la validación de riesgos asociados a IPs y dominios.

## Resultados del proyecto

### Entregables y logros:

* Versionamiento de proyecto y datos manejado en las fases del proyecto.

* Integración exitosa de APIs: VirusTotal, AbuseIPDB, Whois, Shodan y Maltrail.

* Desarrollo e implementación del agente IA con LangChain y LLM de OpenAI para consultas automáticas.

* Despliegue de sistema contenerizado con backend, frontend y base de datos MongoDB usando Docker Compose.

* Interfaz web para consulta y visualización de resultados accesible vía navegador.

### Evaluación del modelo:

* Validación del agente con al menos 5 IoCs reales, logrando categorización eficaz y respuestas pertinentes sobre riesgo potencial.

* Comparación con modelo base manual (validación humana), mostrando agilización y precisión aceptable para uso operativo.

### Relevancia para el negocio:

* Herramienta diseñada para facilitar la identificación y priorización de amenazas, apoyando equipos de SOC, cazadores de amenazas y profesionales de ciberseguridad.

## Lecciones aprendidas

* La integración de múltiples APIs presenta desafíos en la unificación y normalización de estructuras de datos variadas.

* La flexibilidad de MongoDB fue fundamental para manejar la heterogeneidad de los datos sin afectar la performance.

* El uso de LangChain simplificó la implementación del agente en alineación con modelos LLM, facilitando consultas contextuales.

* Importancia crítica del manejo seguro de credenciales y variables de entorno para proteger las llaves de servicios externos.

* Retos en el monitoreo del uso de recursos en despliegue contenerizado, especialmente en la gestión de espacio en disco debido a la variabilidad de datos.

## Impacto del proyecto

* El proyecto aporta una solución práctica para análisis automatizado y enriquecido de IoCs, mejorando los tiempos de respuesta a procesos clave en ciberseguridad.

* Se abre la oportunidad para futuras implementaciones incluyendo más tipos de indicadores y mejor integración con plataformas de monitoreo.

* Se identifica una optimización en gestión de datos y escalabilidad de la solución en entornos productivos.

## Conclusiones

* Se cumplieron los objetivos planteados inicialmente, entregando un sistema funcional y confiable para análisis de indicadores de compromiso basados en agentes IA.

* La combinación de tecnologías contenerizadas, bases de datos flexibles y modelos LLM genera un enfoque prometedor para proyectos similares.

* Se recomienda continuar con mantenimiento activo, actualización de componentes y evaluación continua del desempeño del agente.

## Agradecimientos

* Agradecemos especialmente al equipo de proyecto: Diego Valero, Jose Ávila y Nicolas Cubillos, cuyo esfuerzo y dedicación hicieron posible el éxito de esta iniciativa.

* Reconocimiento a los colaboradores externos y proveedores de servicios que permitieron el acceso a las APIs utilizadas en el proyecto.

* Gratitud a los patrocinadores y financiadores, en especial por el apoyo económico para el acceso al modelo de OpenAI y la infraestructura necesaria.
