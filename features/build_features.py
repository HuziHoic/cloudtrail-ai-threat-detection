import pandas as pd

PARQUET_PATH = "data/processed/cloudtrail_parquet"
OUTPUT_PATH = "data/features/behavior_features.parquet"
WINDOW = "5min"

def load_data():
    df = pd.read_parquet(PARQUET_PATH)
    df["event_time"] = pd.to_datetime(df["event_time"], utc=True)

    # CREATE TIME WINDOW HERE (CRITICAL)
    df["time_window"] = df["event_time"].dt.floor(WINDOW)

    return df


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values("event_time")


    # Basic temporal features
    df["hour_of_day"] = df["event_time"].dt.hour
    df["is_weekend"] = df["event_time"].dt.weekday >= 5

    # Error flag
    df["is_failed"] = df["error_code"].notna()

    grouped = df.groupby(["user_arn", "time_window"])

    features = grouped.agg(
        api_call_count=("event_name", "count"),
        unique_api_count=("event_name", "nunique"),
        unique_service_count=("event_source", "nunique"),
        unique_region_count=("aws_region", "nunique"),
        error_count=("is_failed", "sum"),
        failed_call_ratio=("is_failed", "mean"),
        hour_of_day=("hour_of_day", "first"),
        is_weekend=("is_weekend", "first"),
    ).reset_index()

    return features

def detect_new_api_usage(df, features):
    features = features.sort_values("time_window")

    seen_apis = {}

    new_api_flags = []

    for _, row in features.iterrows():
        user = row["user_arn"]
        window = row["time_window"]

        window_apis = set(
            df[
                (df["user_arn"] == user) &
                (df["time_window"] == window)
            ]["event_name"]
        )

        historical = seen_apis.get(user, set())
        new_api_flags.append(len(window_apis - historical) > 0)

        # Update history AFTER evaluation
        seen_apis[user] = historical.union(window_apis)

    features["new_api_used"] = new_api_flags
    return features


if __name__ == "__main__":
    df = load_data()
    features = build_features(df)
    features = detect_new_api_usage(df, features)

    features.to_parquet(OUTPUT_PATH, index=False)
    print(features.head())
