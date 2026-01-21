import plotly.express as px

def anomalies_over_time(df):
    grouped = (
        df.groupby("time_window")["final_score"]
        .mean()
        .reset_index()
    )

    fig = px.line(
        grouped,
        x="time_window",
        y="final_score",
        title="Average Anomaly Score Over Time"
    )

    fig.update_layout(yaxis_title="Anomaly Score")
    return fig


def top_risky_principals(df):
    risky = (
        df[df["severity"].isin(["HIGH", "MEDIUM"])]
        .groupby("user_arn")
        .size()
        .reset_index(name="alert_count")
        .sort_values("alert_count", ascending=False)
        .head(10)
    )

    fig = px.bar(
        risky,
        x="alert_count",
        y="user_arn",
        orientation="h",
        title="Top Risky Principals"
    )

    fig.update_layout(yaxis_title="Principal")
    return fig
