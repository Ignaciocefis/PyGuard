import streamlit as st
import os
import time
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, desc, hour, to_timestamp, window
import pandas as pd

st.set_page_config(page_title="SIEM Dashboard", layout="wide")

LOG_FILE = 'logs/kafka_logs.csv'
REFRESH_INTERVAL = 5  # segundos

# -------------------------------
# Funciones con Spark
# -------------------------------

@st.cache_resource
def get_spark_session():
    return (
        SparkSession.builder
        .appName("SIEM Dashboard")
        .config("spark.python.worker.reuse", "false")
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.python.profile", "false")
        .config("spark.executorEnv.PYTHONUNBUFFERED", "YES")
        .config("spark.network.timeout", "600s")
        .config("spark.executor.heartbeatInterval", "60s")
        .getOrCreate()
    )

def load_spark_data(_spark):
    if os.path.exists(LOG_FILE):
        df = _spark.read.option("header", True).csv(LOG_FILE)
        df = df.withColumn("timestamp", to_timestamp(col("timestamp")))
        return df
    return _spark.createDataFrame([], schema="timestamp timestamp, event_type string, user string, ip string, message string")

# -------------------------------
# Funciones de análisis SIEM
# -------------------------------

def count_unique_users(df):
    return df.select("user").distinct().count()

def detect_anomalous_users(df):
    return df.groupBy("user").count().filter(col("count") > 100)

def analyze_time_distribution(df):
    return df.withColumn("hour", hour("timestamp")) \
             .groupBy("hour").count().orderBy("hour")

def detect_suspicious_patterns(df):
    return df.filter(col("event_type") == "suspicious").groupBy("user").count()

def correlate_failed_logins_errors(df):
    return df.filter((col("event_type") == "failed_login") | (col("event_type") == "error")) \
             .groupBy("user").count().orderBy(desc("count"))

def detect_dangerous_ips(df):
    return df.filter(col("ip").startswith("192.168")).groupBy("ip").count().orderBy(desc("count"))

def analyze_ip_activity(df):
    return df.groupBy("ip").count().orderBy(desc("count"))

def detect_potential_attacks(df):
    return df.filter((col("event_type") == "failed_login") & (col("ip").isNotNull())) \
             .groupBy("ip", "user").count().filter(col("count") > 10)

# -------------------------------
# Interfaz Streamlit + Spark
# -------------------------------

st.title("🔍 SIEM Dashboard en Tiempo Real con Spark")

placeholder = st.empty()
spark = get_spark_session()

while True:
    with placeholder.container():
        df_spark = load_spark_data(spark)

        if df_spark.count() == 0:
            st.warning("⚠️ No hay datos disponibles.")
            time.sleep(REFRESH_INTERVAL)
            continue

        # Convertir a Pandas para visualización
        df_pd = df_spark.toPandas()

        # Estadísticas Generales
        st.subheader("📊 Estadísticas Generales")
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Total de eventos", len(df_pd))
            st.dataframe(df_pd.tail(10), use_container_width=True)

        with col2:
            event_counts = df_spark.groupBy("event_type").count().toPandas()
            event_counts = event_counts.set_index("event_type")
            st.bar_chart(event_counts)

        # Evolución temporal
        st.subheader("⏱️ Evolución temporal")
        df_time = (
            df_spark
            .groupBy(window("timestamp", "10 seconds"), "event_type")
            .count()
            .toPandas()
        )

        if not df_time.empty:
            df_time['timestamp'] = df_time['window'].apply(lambda w: w.start)
            df_pivot = df_time.pivot(index='timestamp', columns='event_type', values='count').fillna(0)
            st.line_chart(df_pivot)

        # Resultados del análisis SIEM
        st.subheader("🧐 Análisis SIEM")
        
        # Mostrar las métricas actualizadas cada vez que se recargue
        unique_users_result = count_unique_users(df_spark)
        st.metric("Usuarios únicos", unique_users_result)

        anomalous_users_result = detect_anomalous_users(df_spark)
        st.write("Usuarios anómalos:")
        st.dataframe(anomalous_users_result.toPandas(), use_container_width=True)

        time_distribution_result = analyze_time_distribution(df_spark)
        st.write("Distribución temporal de eventos:")
        st.dataframe(time_distribution_result.toPandas(), use_container_width=True)

        suspicious_patterns_result = detect_suspicious_patterns(df_spark)
        st.write("Patrones sospechosos de eventos:")
        st.dataframe(suspicious_patterns_result.toPandas(), use_container_width=True)

        failed_logins_errors_result = correlate_failed_logins_errors(df_spark)
        st.write("Errores de login fallidos:")
        st.dataframe(failed_logins_errors_result.toPandas(), use_container_width=True)

        dangerous_ips_result = detect_dangerous_ips(df_spark)
        st.write("IPs peligrosas:")
        st.dataframe(dangerous_ips_result.toPandas(), use_container_width=True)

        ip_activity_result = analyze_ip_activity(df_spark)
        st.write("Actividad por IP:")
        st.dataframe(ip_activity_result.toPandas(), use_container_width=True)

        potential_attacks_result = detect_potential_attacks(df_spark)
        st.write("Posibles ataques detectados:")
        st.dataframe(potential_attacks_result.toPandas(), use_container_width=True)

    time.sleep(REFRESH_INTERVAL)
