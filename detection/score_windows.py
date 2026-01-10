import os
import joblib
import pandas as pd
import numpy as np

FEATURE_PATH = "data/features/behavior_features.parquet"
MODEL_PATH = "models/artifacts/isolation_forest.joblib"
OUTPUT_PATH = "data/detections/scored_windows.parquet"

def normalize_scores(scores):
    # Higher = more anomalous
    inverted = -scores
    min_s, max_s = inverted.min(), inverted.max()

    if min_s == max_s:
        return np.zeros(len(scores))

    return 100 * (inverted - min_s) / (max_s - min_s)

def assign_severity(score):
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"

def main():
    print("[+] Loading features...")
    df = pd.read_parquet(FEATURE_PATH)
    df = df.sort_values("time_window")

    print("[+] Loading model...")
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_cols = bundle["features"]

    X = df[feature_cols]

    print("[+] Scoring windows...")
    raw_scores = model.decision_function(X)

    df["anomaly_score_raw"] = raw_scores
    df["anomaly_score"] = normalize_scores(raw_scores)
    df["severity"] = df["anomaly_score"].apply(assign_severity)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df.to_parquet(OUTPUT_PATH, index=False)

    print("[+] Top suspicious windows:")
    print(
        df.sort_values("anomaly_score", ascending=False)
          .head(5)[
              ["user_arn", "time_window", "anomaly_score", "severity"]
          ]
    )

if __name__ == "__main__":
    main()
