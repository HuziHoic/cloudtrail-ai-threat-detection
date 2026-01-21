import streamlit as st
import pandas as pd
from charts import (
    anomalies_over_time,
    top_risky_principals
)

DATA_PATH = "data/detections/scored_windows.parquet"

st.set_page_config(
    page_title="CloudTrail Threat Detection Dashboard",
    layout="wide"
)

st.title("🚨 CloudTrail AI Threat Detection")

@st.cache_data
def load_data():
    df = pd.read_parquet(DATA_PATH)
    df["time_window"] = pd.to_datetime(df["time_window"])
    return df

df = load_data()

# KPIs
col1, col2, col3 = st.columns(3)

col1.metric("Total Windows", len(df))
col2.metric("High Severity Alerts", (df["severity"] == "HIGH").sum())
col3.metric("Unique Principals", df["user_arn"].nunique())

st.divider()

# Charts
st.subheader("Anomaly Score Over Time")
st.plotly_chart(anomalies_over_time(df), use_container_width=True)

st.subheader("Top Risky Principals")
st.plotly_chart(top_risky_principals(df), use_container_width=True)

st.subheader("Recent High-Risk Alerts")
st.dataframe(
    df[df["severity"] == "HIGH"]
      .sort_values("final_score", ascending=False)
      .head(10)[
          ["time_window", "user_arn", "final_score", "rule_reasons"]
      ]
)
