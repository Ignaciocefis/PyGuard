import streamlit as st
import os
import time
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, countDistinct, hour, avg, desc, unix_timestamp, lag, window, count, collect_list, array_contains, to_timestamp
from pyspark.sql.window import Window

st.set_page_config(page_title="PyGuard - SIEM Dashboard", layout="wide")

LOG_FILE = 'logs/kafka_logs.csv'
REFRESH_INTERVAL = 5  # segundos

# -------------------------------
# Inicialización de Spark
# -------------------------------

# Crea e inicializa una sesión de Spark
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

# Carga los datos desde un archivo CSV si existe
def load_spark_data(_spark):
    if os.path.exists(LOG_FILE):
        df = _spark.read.option("header", True).csv(LOG_FILE)
        df = df.withColumn("timestamp", to_timestamp(col("timestamp")))
        return df
    return _spark.createDataFrame([], schema="timestamp timestamp, event_type string, user string, ip string, message string")

# -------------------------------
# Funciones de análisis SIEM
# -------------------------------

# 1. Número de usuarios únicos que han generado eventos
def count_unique_users(df):
    return df.select("user").distinct().count()

# 2. Distribución del número de eventos por hora del día
def analyze_time_distribution(df):
    return df.withColumn("hour", hour("timestamp")) \
             .groupBy("hour").count().orderBy("hour")

# 3. Detección de usuarios con una media elevada de eventos por hora (mayor a 20)
def detect_user_activity_anomalies(df):
    hourly = df.groupBy("user", hour("timestamp").alias("hour")).count()
    return hourly.groupBy("user").agg(avg("count").alias("avg_events_per_hour")) \
                 .filter(col("avg_events_per_hour") > 20)

# 4. Número total de errores y fallos de login por usuario
def correlate_failed_logins_errors(df):
    return df.filter(col("event_type").isin("ERROR", "LOGIN_FAILURE")) \
             .groupBy("user").count().orderBy(desc("count"))

# 5. Número total de errores y fallos de login por usuario
def analyze_ip_activity(df):
    return df.groupBy("ip").count().orderBy(desc("count"))

# 6. Detección de IPs con alta actividad o accedidas por múltiples usuarios
def detect_ip(df):
    return df.filter(col("ip").rlike("^(192\\.168|172\\.16)")) \
             .groupBy("ip").agg(count("*").alias("event_count"), countDistinct("user").alias("unique_users")) \
             .filter((col("event_count") > 50) | (col("unique_users") > 3))

# 7. Detección de combinaciones IP-usuario con múltiples intentos de acceso fallidos (más de 10)
def detect_potential_attacks(df):
    return df.filter((col("event_type") == "LOGIN_FAILURE") & (col("ip").isNotNull())) \
             .groupBy("ip", "user").count().filter(col("count") > 10)

# 8. Detección de picos de eventos por tipo en intervalos de 1 minuto (más de 50 eventos)
def detect_event_type_spikes(df):
    spikes = df.groupBy(window("timestamp", "1 minute"), "event_type").count().filter(col("count") > 50).orderBy(desc("count"))
    return spikes.select("event_type", "count", "window.start", "window.end")

# 9. Detección de IPs utilizadas por múltiples usuarios y usuarios que acceden desde muchas IPs distintas.
def detect_shared_or_suspicious_ips(df):
    ip_multiple_users = df.groupBy("ip").agg(countDistinct("user").alias("user_count")) \
             .filter(col("user_count") > 3)
    user_multiple_ips = df.groupBy("user").agg(countDistinct("ip").alias("ip_count")) \
             .filter(col("ip_count") > 5)
    return ip_multiple_users.join(user_multiple_ips, how="outer")

# 10. Tiempo promedio entre eventos por usuario
def average_time_between_events(df):
    window_spec = Window.partitionBy("user").orderBy("timestamp")
    df_with_lag = df.withColumn("prev_timestamp", lag("timestamp").over(window_spec))
    df_with_diff = df_with_lag.withColumn("time_diff", 
        unix_timestamp("timestamp") - unix_timestamp("prev_timestamp"))
    return df_with_diff.groupBy("user").agg(avg("time_diff").alias("avg_seconds_between_events")) \
                       .filter(col("avg_seconds_between_events").isNotNull())

# 11. Detección de posibles ataques de fuerza bruta desde IPs con más de 10 intentos de login fallido en 2 minutos
def detect_brute_force(df):
    failed_logins = df.filter(col("event_type") == "LOGIN_FAILURE")
    brute_force = failed_logins.groupBy(window("timestamp", "2 minutes"), col("ip")) \
             .count().filter(col("count") > 10).orderBy(desc("count"))
    return brute_force.select("ip", "count", "window.start", "window.end")

# 12. Detección de usuarios que acceden desde más de 5 IPs distintas en un intervalo de 1 minuto
def detect_network_scan(df):
    user_ip_window = window("timestamp", "1 minute")
    scan_df = df.groupBy("user", user_ip_window) \
             .agg(countDistinct("ip").alias("distinct_ips")) \
             .filter(col("distinct_ips") > 5) \
             .orderBy(desc("distinct_ips"))
    return scan_df.select("user", "distinct_ips", "window.start", "window.end")

# 13. Detección de usuarios con más de 5 eventos fuera del horario habitual (antes de las 6h o después de las 22h)
def detect_off_hours_activity(df):
    return df.withColumn("hour", hour("timestamp")) \
             .filter((col("hour") < 6) | (col("hour") >= 22)) \
             .groupBy("user").count().filter(col("count") > 5)

# 14. Número de tipos distintos de eventos generados por cada usuario (más de 4)
def detect_event_type_diversity(df):
    return df.groupBy("user").agg(countDistinct("event_type").alias("event_types")) \
             .filter(col("event_types") > 4)

# 15. Detección de usuarios con secuencias de eventos (ej. LOGIN → PERMISSION_CHANGE → FILE_DOWNLOAD)
def detect_suspicious_event_chains(df):
    sequence_df = df.filter(col("event_type").isin("LOGIN", "PERMISSION_CHANGE", "FILE_DOWNLOAD"))
    return sequence_df.groupBy("user").agg(collect_list("event_type").alias("events")) \
                      .filter(array_contains(col("events"), "LOGIN") & array_contains(col("events"), "FILE_DOWNLOAD"))

# 16. Detección de eventos repetidos por usuario y tipo con más de 10 ocurrencias
def detect_repetitive_behavior(df):
    return df.groupBy("user", "event_type", "timestamp").count() \
             .groupBy("user", "event_type").agg(count("*").alias("occurrences")) \
             .filter(col("occurrences") > 10)

# -------------------------------
# Interfaz Streamlit + Spark
# -------------------------------

st.title("SIEM Dashboard con Spark")

placeholder = st.empty()
spark = get_spark_session()

while True:
    with placeholder.container():
        df_spark = load_spark_data(spark)

        if df_spark.count() == 0:
            st.warning("No hay datos disponibles.")
            time.sleep(REFRESH_INTERVAL)
            continue

        df_pd = df_spark.toPandas()

        # Estadísticas Generales
        st.subheader("Estadísticas Generales")
        st.metric("Total de eventos", len(df_pd))
        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(df_pd.tail(10), use_container_width=True)
        with col2:
            event_counts = df_spark.groupBy("event_type").count().toPandas()
            event_counts = event_counts.set_index("event_type")
            st.bar_chart(event_counts)

        # Evolución temporal de eventos
        st.subheader("Evolución temporal")
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

        # Resultados del análisis
        st.subheader("Análisis SIEM")
        
        count_unique_users_result = count_unique_users(df_spark)
        st.metric("1. Número de usuarios únicos que han generado eventos:", count_unique_users_result)

        analyze_time_distribution_result = analyze_time_distribution(df_spark)
        st.write("2. Distribución del número de eventos por hora:")
        st.line_chart(analyze_time_distribution_result.toPandas().set_index("hour"))

        detect_user_activity_anomalies_result = detect_user_activity_anomalies(df_spark)
        st.write("3. Detección de usuarios con una media elevada de eventos por hora (mayor a 20):")
        st.bar_chart(detect_user_activity_anomalies_result.toPandas().set_index("user"))

        failed_logins_errors_result = correlate_failed_logins_errors(df_spark)
        st.write("4. Número total de errores y fallos de login por usuario:")
        st.bar_chart(failed_logins_errors_result.toPandas().set_index("user"))

        analyze_ip_activity_result = analyze_ip_activity(df_spark)
        st.write("5. Número total de errores y fallos de login por usuario:")
        st.bar_chart(analyze_ip_activity_result.toPandas().set_index("ip"))

        detect_ip_result = detect_ip(df_spark)
        st.write("6. Detección de IPs internas con alta actividad o accedidas por múltiples usuarios:")
        st.dataframe(detect_ip_result.toPandas(), use_container_width=True)

        detect_potential_attacks_result = detect_potential_attacks(df_spark)
        st.write("7. Detección de combinaciones IP-usuario con múltiples intentos de acceso fallidos (más de 10):")
        st.dataframe(detect_potential_attacks_result.toPandas(), use_container_width=True)

        detect_event_type_spikes_result = detect_event_type_spikes(df_spark)
        st.write("8. Detección de picos de eventos por tipo en intervalo de 1 minuto (más de 50 eventos):")  
        st.dataframe(detect_event_type_spikes_result.toPandas(), use_container_width=True)

        detect_shared_or_suspicious_ips_result = detect_shared_or_suspicious_ips(df_spark)
        st.write("9. Detección de IPs utilizadas por múltiples usuarios y usuarios que acceden desde muchas IPs distintas.:")
        st.dataframe(detect_shared_or_suspicious_ips_result.toPandas(), use_container_width=True)

        average_time_between_events_result = average_time_between_events(df_spark)
        st.write("10. Tiempo promedio entre eventos por usuario:")
        st.bar_chart(average_time_between_events_result.toPandas().set_index("user"))

        detect_brute_force_result = detect_brute_force(df_spark)
        st.write("11. Detección de posibles ataques de fuerza bruta desde IPs con más de 10 intentos de acceso fallido en 2 minutos:")
        st.dataframe(detect_brute_force_result.toPandas(), use_container_width=True)

        detect_network_scan_result = detect_network_scan(df_spark)
        st.write("12. Detección de usuarios que acceden desde más de 5 IPs distintas en un intervalo de 1 minuto:")
        st.dataframe(detect_network_scan_result.toPandas(), use_container_width=True)

        detect_off_hours_activity_result = detect_off_hours_activity(df_spark)
        st.write("13. Detección de usuarios con más de 5 eventos fuera del horario habitual (antes de las 6h o después de las 22h):")
        st.dataframe(detect_off_hours_activity_result.toPandas(), use_container_width=True)

        detect_event_type_diversity_result = detect_event_type_diversity(df_spark)
        st.write("14. Número de tipos distintos de eventos generados por cada usuario (más de 4):")
        st.bar_chart(detect_event_type_diversity_result.toPandas().set_index("user"))

        detect_suspicious_event_chains_result = detect_suspicious_event_chains(df_spark)
        st.write("15. Detección de usuarios con secuencias de eventos (LOGIN → PERMISSION_CHANGE → FILE_DOWNLOAD):")
        st.dataframe(detect_suspicious_event_chains_result.toPandas(), use_container_width=True)

        detect_repetitive_behavior_result = detect_repetitive_behavior(df_spark)
        st.write("16. Detección de eventos repetidos por usuario y tipo con más de 10 ocurrencias:")
        st.dataframe(detect_repetitive_behavior_result.toPandas(), use_container_width=True)

    time.sleep(REFRESH_INTERVAL)