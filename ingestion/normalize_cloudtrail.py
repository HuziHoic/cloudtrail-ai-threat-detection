import json
import gzip
import pandas as pd
from pathlib import Path
from datetime import datetime

RAW_FILE = "data/raw/sample_cloudtrail.json.gz"
OUTPUT_DIR = "data/processed/cloudtrail_parquet"

def extract_record(record: dict) -> dict:
    ui = record.get("userIdentity", {})
    session_ctx = ui.get("sessionContext", {})
    attrs = session_ctx.get("attributes", {})

    return {
        "event_time": record.get("eventTime"),
        "event_source": record.get("eventSource"),
        "event_name": record.get("eventName"),
        "aws_region": record.get("awsRegion"),
        "source_ip": record.get("sourceIPAddress"),
        "user_agent": record.get("userAgent"),
        "read_only": record.get("readOnly"),
        "event_type": record.get("eventType"),

        "user_type": ui.get("type"),
        "user_arn": ui.get("arn"),
        "account_id": ui.get("accountId"),

        "mfa_authenticated": attrs.get("mfaAuthenticated"),
        "session_creation": attrs.get("creationDate"),

        "error_code": record.get("errorCode"),
        "error_message": record.get("errorMessage"),
    }

def load_cloudtrail(file_path: str) -> pd.DataFrame:
    with gzip.open(file_path, "rt", encoding="utf-8") as f:
        payload = json.load(f)

    records = payload.get("Records", [])
    rows = [extract_record(r) for r in records]

    df = pd.DataFrame(rows)
    df["event_time"] = pd.to_datetime(df["event_time"], utc=True)

    # Partition columns
    df["year"] = df["event_time"].dt.year
    df["month"] = df["event_time"].dt.month
    df["day"] = df["event_time"].dt.day
    df["mfa_authenticated"] = df["mfa_authenticated"].map({"true": True, "false": False})
    df["is_aws_service_call"] = df["user_type"] == "AWSService"

    return df

def write_parquet(df: pd.DataFrame):
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    df.to_parquet(
        OUTPUT_DIR,
        engine="pyarrow",
        partition_cols=["year", "month", "day"],
        index=False
    )

if __name__ == "__main__":
    df = load_cloudtrail(RAW_FILE)
    write_parquet(df)

    print("Normalization complete")
    print(df.head())
