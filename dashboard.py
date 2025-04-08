import streamlit as st
import pandas as pd
import os
import time

st.set_page_config(page_title="SIEM Dashboard", layout="wide")

LOG_FILE = 'logs/kafka_logs.csv'

st.title("🔍 SIEM Dashboard en Tiempo Real")

@st.cache_data(ttl=1)
def load_data():
    if os.path.exists(LOG_FILE):
        return pd.read_csv(LOG_FILE)
    return pd.DataFrame(columns=['timestamp', 'event_type', 'user', 'ip', 'message'])

# Auto refresco
REFRESH_INTERVAL = 5  # segundos
placeholder = st.empty()

while True:
    with placeholder.container():
        df = load_data()
        st.subheader("📊 Estadísticas Generales")
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Total de eventos", len(df))
            st.dataframe(df.tail(10), use_container_width=True)

        with col2:
            st.bar_chart(df['event_type'].value_counts())

        st.subheader("⏱️ Evolución temporal")
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df_time = df.groupby([pd.Grouper(key='timestamp', freq='10s'), 'event_type']).size().unstack().fillna(0)
            st.line_chart(df_time)

    time.sleep(REFRESH_INTERVAL)