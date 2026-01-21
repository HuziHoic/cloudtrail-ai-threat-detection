import pandas as pd
from alert_schema import build_alert
from sns import send_sns_alert
from markdown import write_markdown_report

DATA_PATH = "data/detections/scored_windows.parquet"

def main():
    df = pd.read_parquet(DATA_PATH)

    alerts = df[df["severity"].isin(["HIGH", "MEDIUM"])]

    print(f"[+] Generating {len(alerts)} alerts")

    alert_payloads = []

    for _, row in alerts.iterrows():
        alert = build_alert(row.to_dict())
        alert_payloads.append(alert)
        send_sns_alert(alert)

    write_markdown_report(alert_payloads)

if __name__ == "__main__":
    main()
