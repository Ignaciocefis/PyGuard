
# SIEM PySpark

Este proyecto implementa un sistema de gestión de eventos e información de seguridad utilizando Apache Spark y PySpark, integrando dashboards para visualización de datos en tiempo real.

## Requisitos previos

Antes de ejecutar el proyecto, asegúrate de tener instalado lo siguiente:

- **Python 3.9 o superior**
- **Jupyter Notebook**
- **Streamlit**
- **Docker** (para Kafka y Zookeeper)
- **Zookeeper** (usado para la gestión de Kafka)
- **Kafka** (usado para la transmisión de eventos)

## Instalación

1. **Instalar dependencias del proyecto:**

   Ejecuta el siguiente comando para instalar los requisitos desde el archivo `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

2. **Instalar Jupyter Notebook:**

   Si no tienes Jupyter Notebook instalado, puedes hacerlo con:
   ```bash
   pip install notebook
   ```

3. **Instalar Docker:**

   Si no tienes Docker instalado, descárgalo e instálalo desde [docker.com](https://www.docker.com/get-started).

4. **Instalar Zookeeper y Kafka con Docker:**

   Si estás utilizando Docker para gestionar Kafka y Zookeeper, asegúrate de ejecutar los siguientes comandos para instalar y configurar ambos servicios:

   ```bash
   docker pull confluentinc/cp-kafka
   docker pull zookeeper
   docker run -d --name zookeeper -p 2181:2181 zookeeper
   docker run -d --name kafka -p 9093:9093 --link zookeeper:zookeeper -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9093 -e KAFKA_LISTENER_SECURITY_PROTOCOL=PLAINTEXT -e KAFKA_LISTENER_PORT=9093 -e KAFKA_LISTENER_NAME=PLAINTEXT confluentinc/cp-kafka
   docker ps
   ```

## Ejecución del proyecto

1. **Abrir Jupyter Notebook:**
   - Ejecuta Jupyter desde la terminal con:
     ```bash
     jupyter notebook
     ```
   - Navega a la carpeta donde se encuentra el repositorio clonado.

2. **Ejecutar `SIEM-SparkGenerator`:**
   - En el notebook `SIEM-SparkGenerator.ipynb`, ejecuta todas las celdas necesarias para generar los datos de eventos.

3. **Ejecutar `SIEM-SparkConsumer`:**
   - En el notebook `SIEM-SparkConsumer.ipynb`, ejecuta todas las celdas para consumir y procesar los datos generados por el paso anterior.

4. **Iniciar Streamlit:**
   - Abre la consola de comandos, navega hasta la carpeta del repositorio y ejecuta el siguiente comando para visualizar el dashboard:
     ```bash
     streamlit run dashboard.py
     ```

¡Listo! Ahora puedes ver los resultados en tiempo real a través del dashboard.

