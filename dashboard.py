import streamlit as st
import os
import time
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, desc, hour, to_timestamp, window, countDistinct, when, avg, lag, unix_timestamp
from pyspark.sql.window import Window
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="SIEM Dashboard", layout="wide")

LOG_FILE = 'logs/kafka_logs.csv'
REFRESH_INTERVAL = 5  # segundos

# -------------------------------
# Inicialización de Spark
# -------------------------------

@st.cache_resource
# Crea e inicializa una sesión de Spark
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

# Carga los datos desde un archivo CSV si existe
# Convierte la columna timestamp a formato de fecha y hora

def load_spark_data(_spark):
    if os.path.exists(LOG_FILE):
        df = _spark.read.option("header", True).csv(LOG_FILE)
        df = df.withColumn("timestamp", to_timestamp(col("timestamp")))
        return df
    return _spark.createDataFrame([], schema="timestamp timestamp, event_type string, user string, ip string, message string")

# -------------------------------
# Funciones de análisis SIEM
# -------------------------------

# Cuenta el número de usuarios únicos

def count_unique_users(df):
    return df.select("user").distinct().count()

# Detecta usuarios con una cantidad de eventos inusualmente alta

def detect_anomalous_users(df):
    return df.groupBy("user").count().filter(col("count") > 100)

# Agrupa los eventos por hora y los cuenta

def analyze_time_distribution(df):
    return df.withColumn("hour", hour("timestamp")) \
             .groupBy("hour").count().orderBy("hour")

# Detecta patrones marcados como 'suspicious'

def detect_suspicious_patterns(df):
    return df.filter(col("event_type") == "suspicious").groupBy("user").count()

# Agrupa fallos de login y errores por usuario

def correlate_failed_logins_errors(df):
    return df.filter((col("event_type") == "failed_login") | (col("event_type") == "error")) \
             .groupBy("user").count().orderBy(desc("count"))

# Detecta IPs internas peligrosas por frecuencia

def detect_dangerous_ips(df):
    return df.filter(col("ip").startswith("192.168")).groupBy("ip").count().orderBy(desc("count"))

# Actividad general por IP

def analyze_ip_activity(df):
    return df.groupBy("ip").count().orderBy(desc("count"))

# Detecta combinaciones de IP y usuario con múltiples fallos de login

def detect_potential_attacks(df):
    return df.filter((col("event_type") == "failed_login") & (col("ip").isNotNull())) \
             .groupBy("ip", "user").count().filter(col("count") > 10)

# Detecta usuarios con aumentos de actividad inusuales por hora

def detect_user_behavior_change(df):
    return df.groupBy("user", hour("timestamp").alias("hour")).count() \
             .groupBy("user").agg(avg("count").alias("avg_events_per_hour")) \
             .filter(col("avg_events_per_hour") > 20)

# Detecta picos de eventos de un tipo en intervalos de 1 minuto

def detect_event_type_spikes(df):
    return df.groupBy(window("timestamp", "1 minute"), "event_type").count() \
             .filter(col("count") > 50).orderBy(desc("count"))

# IPs usadas por múltiples usuarios (posibles accesos compartidos o ataques)

def detect_unusual_ip_usage(df):
    return df.groupBy("user", "ip").count().filter(col("count") > 5) \
             .groupBy("ip").agg(countDistinct("user").alias("unique_users")) \
             .filter(col("unique_users") > 3).orderBy(desc("unique_users"))

# Tiempo promedio entre eventos por usuario (puede revelar automatización o bots)

def average_time_between_events(df):
    window_spec = Window.partitionBy("user").orderBy("timestamp")
    df_with_lag = df.withColumn("prev_timestamp", lag("timestamp").over(window_spec))
    df_with_diff = df_with_lag.withColumn("time_diff", 
        unix_timestamp("timestamp") - unix_timestamp("prev_timestamp"))
    return df_with_diff.groupBy("user").agg(avg("time_diff").alias("avg_seconds_between_events")) \
                       .filter(col("avg_seconds_between_events").isNotNull())

# Detecta usuarios con errores consecutivos sin actividad normal intermedia

def detect_consecutive_errors(df):
    window_spec = Window.partitionBy("user").orderBy("timestamp")
    df_filtered = df.filter(col("event_type") == "ERROR")
    df_with_lag = df_filtered.withColumn("prev_timestamp", lag("timestamp").over(window_spec))
    df_with_gap = df_with_lag.withColumn("time_gap", 
        unix_timestamp("timestamp") - unix_timestamp("prev_timestamp"))
    return df_with_gap.filter(col("time_gap") < 60).groupBy("user").count().filter(col("count") > 3)

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

        df_pd = df_spark.toPandas()

        # Estadísticas Generales
        st.subheader("📊 Estadísticas Generales")
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Total de eventos", len(df_pd))

        with col2:
            event_counts = df_spark.groupBy("event_type").count().toPandas()
            event_counts = event_counts.set_index("event_type")
            st.bar_chart(event_counts['count'], use_container_width=True)

        # Picos Anómalos de Eventos por Tipo
        st.subheader("🚨 Picos Anómalos de Eventos por Tipo")
        df_event_spikes = detect_event_type_spikes(df_spark).toPandas()
        if not df_event_spikes.empty:
            st.line_chart(df_event_spikes.set_index('event_type')['count'], use_container_width=True)
        else:
            st.warning("⚠️ No se detectaron picos anómalos de eventos.")

        # Usuarios con Cambios Inusuales en el Comportamiento
        st.subheader("👥 Usuarios con Cambios Inusuales en el Comportamiento")
        df_behavior_changes = detect_user_behavior_change(df_spark).toPandas()
        if not df_behavior_changes.empty:
            st.line_chart(df_behavior_changes.set_index('user')['avg_events_per_hour'], use_container_width=True)
        else:
            st.warning("⚠️ No se detectaron cambios inusuales en el comportamiento de los usuarios.")

        # Distribución Temporal de Eventos
        st.subheader("📅 Distribución Temporal de Eventos")
        df_time = (
            df_spark
            .groupBy(window("timestamp", "1 minute"), "event_type")
            .count()
            .toPandas()
        )

        if not df_time.empty:
            df_time['timestamp'] = df_time['window'].apply(lambda w: w.start)
            df_pivot = df_time.pivot(index='timestamp', columns='event_type', values='count').fillna(0)
            st.line_chart(df_pivot, use_container_width=True)
        else:
            st.warning("⚠️ No hay eventos para mostrar en la distribución temporal.")

        # Mostrar usuarios anómalos y errores de login fallidos en la misma fila
        st.subheader("🚨 Usuarios Anómalos y Errores de Login Fallidos")

        # Crear dos columnas para mostrar los gráficos juntos
        col1, col2 = st.columns(2)

        # Gráfico de Usuarios Anómalos
        with col1:
            anomalous_users = detect_anomalous_users(df_spark).toPandas()
            if not anomalous_users.empty:
                st.bar_chart(anomalous_users.set_index('user')['count'], use_container_width=True)
            else:
                st.warning("⚠️ No se detectaron usuarios anómalos.")

        # Gráfico de Errores de Login Fallidos
        with col2:
            failed_logins = correlate_failed_logins_errors(df_spark).toPandas()
            if not failed_logins.empty:
                st.bar_chart(failed_logins.set_index('user')['count'], use_container_width=True)
            else:
                st.warning("⚠️ No se detectaron fallos de login.")

        # IPs Peligrosas
        st.subheader("⚠️ IPs Peligrosas")
        dangerous_ips = detect_dangerous_ips(df_spark).toPandas()
        if not dangerous_ips.empty:
            st.bar_chart(dangerous_ips.set_index('ip')['count'], use_container_width=True)
        else:
            st.warning("⚠️ No se detectaron IPs peligrosas.")

        # Actividad por IP
        st.subheader("🌐 Actividad por IP")
        ip_activity = analyze_ip_activity(df_spark).toPandas()
        if not ip_activity.empty:
            st.bar_chart(ip_activity.set_index('ip')['count'], use_container_width=True)
        else:
            st.warning("⚠️ No se detectó actividad sospechosa por IP.")

        # Posibles Ataques Detectados
        st.subheader("🚨 Posibles Ataques Detectados")
        potential_attacks = detect_potential_attacks(df_spark).toPandas()
        if not potential_attacks.empty:
            st.bar_chart(potential_attacks.set_index('ip')['count'], use_container_width=True)
        else:
            st.warning("⚠️ No se detectaron posibles ataques.")

        # IPs Utilizadas por Múltiples Usuarios
        st.subheader("🔐 IPs Utilizadas por Múltiples Usuarios (Posibles Ataques)")
        unusual_ip_usage = detect_unusual_ip_usage(df_spark).toPandas()
        if not unusual_ip_usage.empty:
            st.bar_chart(unusual_ip_usage.set_index('ip')['unique_users'], use_container_width=True)
        else:
            st.warning("⚠️ No se detectaron IPs compartidas entre múltiples usuarios.")

        # Tiempo Promedio Entre Eventos por Usuario
        st.subheader("⏳ Tiempo Promedio Entre Eventos por Usuario")
        avg_time_events = average_time_between_events(df_spark).toPandas()
        if not avg_time_events.empty:
            st.bar_chart(avg_time_events.set_index('user')['avg_seconds_between_events'], use_container_width=True)
        else:
            st.warning("⚠️ No se detectaron anomalías en los tiempos entre eventos.")

        # Usuarios con Errores Consecutivos en Corto Periodo de Tiempo
        st.subheader("⏱️ Usuarios con Errores Consecutivos en Corto Periodo de Tiempo")
        consecutive_errors = detect_consecutive_errors(df_spark).toPandas()
        if not consecutive_errors.empty:
            st.bar_chart(consecutive_errors.set_index('user')['count'], use_container_width=True)
        else:
            st.warning("⚠️ No se detectaron errores consecutivos.")

    time.sleep(REFRESH_INTERVAL)


