from pyspark.sql import SparkSession
from pyspark.sql.functions import split, col, window, count
import os

# Crear sesión de Spark
spark = SparkSession.builder \
    .appName("SIEM-Spark") \
    .getOrCreate()

# Leer los datos desde Kafka
df = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "localhost:9093") \
    .option("subscribe", "logs_topic") \
    .option("startingOffsets", "latest") \
    .load()

# Parsear el mensaje
df_parsed = df.selectExpr("CAST(value AS STRING)") \
    .select(split(col("value"), ", ").alias("data")) \
    .select(
        col("data")[0].alias("source"),
        col("data")[1].alias("event"),
        col("data")[2].cast("int").alias("severity")
    )

# Crear carpeta de resultados si no existe
os.makedirs("results", exist_ok=True)

# Guardar logs detectados en archivo
query = df_parsed.writeStream \
    .outputMode("append") \
    .format("text") \
    .option("path", "results/") \
    .option("checkpointLocation", "results/checkpoint/") \
    .start()

query.awaitTermination()
