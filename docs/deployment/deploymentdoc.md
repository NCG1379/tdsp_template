# Despliegue de modelos

## Infraestructura

- **Nombre del modelo:**: Agentes de IA para Análisis de Indicadores de Compromiso

- **Plataforma de despliegue:**: Despliegue mediante Docker

- **Requisitos técnicos:**:

* La versión de python usada se define dentro del ***Dockerfile*** con el cargue de la imagen `FROM python:3.12-slim-bullseye`.
* Todos los prerequisitos son instalados dentro de la imagen, implementando la instalación del ***full_requirements.txt***, el cual también está dentro del ***Dockerfile***.
* En hardware se requieren 6.1 GB para el despliegue y se debe tener en cuenta el consumo de la base de datos con cada consulta generada, al ser variable el tamaño de la data consultada en las fuentes de datos, el consumo en espacio en disco se debe monitorear.

    ![Texto alternativo](docs\deployment\images\size_consume_docker.png)

- **Requisitos de seguridad:**:

* En un despliegue en producción el único puerto expuesto a internet debe ser el puerto 3000.
* En esta entrega no se tiene la sanitización de los datos de entrada. Sin embargo, los frameworks usados y el uso de pydantic no permite que se pueda pasar cualquier tipo de información o ejecución de código malicioso.
* Al usar APIs de modelos públicos nos aseguramos de tener protección contra el OWASP Top 10 LLMs.
* Se recomienda el uso de un WAF/IDS/IPS para la protección de la aplicación de cara a internet.
* El uso de variables de entorno y evitar subir el .env a repositorios públicos protege los key de los servicios consumidos por API (agregar esto al .gitignore).

- **Diagrama de arquitectura:** (imagen que muestra la arquitectura del sistema que se utilizará para desplegar el modelo)

    ![Texto alternativo](docs\deployment\images\Arquitectura1.png)

## Código de despliegue

- **Archivos principales:**: 

    * **Docker Backend**: carga el app.py que expone todas las APIs que tiene el backend disponible.

    * **Docker Frontend**: carga la UI de usuario para interactuar con las APIs del Backend.

    * **Docker MongoDB**: crear la base de datos que almacena los datos de las fuentes consultadas.

    * **Docker MongoDB**: documento único que ejecuta todos los dockerfiles y crea los componentes antes mencionados.

- **Rutas de acceso a los archivos:**:

    * **Docker Backend**: `tdsp_template\Dockerfile`

    * **Docker Frontend**: `tdsp_template\src\nombre_paquete\frontend-mod6\Dockerfile`

    * **Docker MongoDB**: `tdsp_template\docker-compose.yml`

    * **Docker MongoDB**: `tdsp_template\docker-compose.yml`

- **Variables de entorno:**:

    * **Variables de entorno:**: Se debe tener las llaves de los servicios que se van a consumir para poder correr el projecto, se debe dejar en un archivo `.env` y llamar este archivo en los scripts que requieran cargar una variable de entorno.

        ~~~
        VT_API_KEY=""
        ABUSE_IP_DB_API_KEY=""
        SHODAN_API_KEY=""


        DRIVEID = ""

        HUGGINGFACE_TOKEN = ''

        DEEPSEEK_KEY=""
        OPENAI_KEY=""
        ANTHROPIC_KEY=""
        ~~~

## Documentación del despliegue

- **Instrucciones de instalación:** 

El despliegue del proyecto se realiza desde un docker compose [herramienta para el despliegue de multiples contenedores desde un solo comando](https://learn.microsoft.com/es-es/azure/ai-services/containers/docker-compose-recipe) usando el docker-compose.yml, los pasos de despliegue se describen a continuación:

1. Instalación de docker y docker compose [documentación del fabricante varía según sistema operativo](https://docs.docker.com/engine/install/).

2. Instalado los componentes de docker se procede a correr el siguiente comando, dentro del directorio principal del projecto:

    2.1. En linux: `sudo docker compose -f docker-compose.yml up --build`.

    Se debería observar lo siguiente al correr el comando dentro del directorio del proyecto como se muestra en la imagen:

    ![Texto alternativo]("D:\03_Development\03_MLOps_DL\Project\Branch_dev\tdsp_template\docs\deployment\images\docker_compose_command.png")

3. Se validan los servicios en ejecución:

    3.1. En un navegador pegar `http://localhost:3000` -> Debe cargar el frontend de la aplicación.

    3.2. En un navegador pegar `http://localhost:8000` -> Debe cargar el servicio de FastAPI.

    3.3. En un terminal de comando pegar `curl -X POST http://localhost:8000/api/v1/virustotal -H "Content-Type: application/json" -d '{"ioc": "example.com"}'` -> Debe devolder `{"response":{"message":"Unknown"}}`, esto implica que la base de datos está corriendo correctamente.


- **Instrucciones de uso:**

1. La página se puede visualizar al cargar el `http://localhost:3000`, se debe colocar la IP o Dominio que se desea consultar para poder validar la información y el resumen de los modelos usados:

    * El resultado de las consultas e información se presenta en la página web del frontend

    ![Texto alternativo](docs\deployment\images\WebPage_Complete.png)

- **Instrucciones de mantenimiento:**

* Las versiones de imagenes de los docker deben mantenerse actualizadas por seguridad y compatibilidad.
* Las librerías usadas están soportadas en python 3.12, la migración a otra versión requiere revisión de compatibilidad.
* El frontend en React se debe mantener actualizado para el uso de los componentes gráficos y funciones del framework.

**Nota: en el momento el mantenimiento se genera a nivel de software de la aplicación, los modelos LLMs a nivel de mantenimiento son soportados por el fabricante.

- **Costos asociados al proyecto:**

## Tabla de costos estimados: Infraestructura AWS y uso de modelos OpenAI, DeepSeek y Claude

| Elemento / Modelo                 | Recursos (vCPU / RAM GB) | Costo Mensual Estimado (USD)                 | Observaciones                                         |
|---------------------------------|:------------------------:|:--------------------------------------------:|------------------------------------------------------|
| **Backend (Docker Container)**   |    1 vCPU / 6 GB         | 49.02                                       | AWS Fargate 24/7                                     |
| **Frontend (Docker Container)**  |   0.5 vCPU / 2 GB        | 21.26                                       | AWS Fargate 24/7                                     |
| **MongoDB (Docker Container)**   |    1 vCPU / 6 GB         | 49.02                                       | AWS Fargate 24/7                                     |
| **OpenAI GPT-4 (o3)**            |          --              | $10 (entrada) / $40 (salida) por 1M tokens | Costos basados en API por millón de tokens           |
| **DeepSeek-R1**                  |          --              | $0.55 (entrada) / $2.19 (salida) por 1M tokens | API eficiente, útil para análisis estructurados   |
| **Claude 3.5 Sonnet**            |          --              | $3 (entrada) / $15 (salida) por 1M tokens   | Anthropic API, modelo intermedio                      |

### Detalles y consideraciones

- **Infraestructura AWS Fargate:** costos para ejecución continua 24/7 durante un mes, sin incluir almacenamiento o tráfico adicional.
- **Modelos IA/API:** costos únicamente de tokens procesados; el uso real puede variar según volumen de consultas.
- Precios de APIs OSINT (VirusTotal, AbuseIPDB, etc.) no considerados por ofrecer planes gratuitos con límites.
