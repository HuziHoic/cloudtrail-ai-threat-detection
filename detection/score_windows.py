import os
import joblib
import pandas as pd
import numpy as np

from hybrid_scoring import (
    compute_rule_risk,
    hybrid_score,
    severity_from_score
)

FEATURE_PATH = "data/features/behavior_features.parquet"
MODEL_PATH = "models/artifacts/isolation_forest.joblib"
OUTPUT_PATH = "data/detections/scored_windows.parquet"


def normalize_scores(scores):
    inverted = -scores
    min_s, max_s = inverted.min(), inverted.max()

    if min_s == max_s:
        return np.zeros(len(scores))

    return 100 * (inverted - min_s) / (max_s - min_s)


def build_rule_context(row: pd.Series) -> dict:
    """
    Build rule context from aggregated feature window
    """
    return {
        "apis": set(),  # placeholder (Phase 7 will use raw events)
        "identity_type": "AssumedRole" if "assumed-role" in row["user_arn"] else "IAMUser",
        "mfa_used": row.get("mfa_used", True),
        "readonly_only": row.get("failed_call_ratio", 0) == 0,
        "new_api_used": row.get("new_api_used", False),
    }


def main():
    print("[+] Loading features...")
    df = pd.read_parquet(FEATURE_PATH)
    df = df.sort_values("time_window")

    print("[+] Loading model...")
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_cols = bundle["features"]

    X = df[feature_cols]

    print("[+] Scoring windows (ML)...")
    raw_scores = model.decision_function(X)
    df["anomaly_score_raw"] = raw_scores
    df["anomaly_score"] = normalize_scores(raw_scores)

    print("[+] Applying rule-based risk scoring...")
    rule_scores = []
    hybrid_scores = []
    severities = []

    for _, row in df.iterrows():
        context = build_rule_context(row)
        rule_score = compute_rule_risk(context)

        final_score = hybrid_score(
            anomaly_score=row["anomaly_score"],
            rule_score=rule_score
        )

        rule_scores.append(rule_score)
        hybrid_scores.append(final_score)
        severities.append(severity_from_score(final_score))

    df["rule_score"] = rule_scores
    df["final_score"] = hybrid_scores
    df["severity"] = severities

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df.to_parquet(OUTPUT_PATH, index=False)

    print("[+] Top suspicious windows:")
    print(
        df.sort_values("final_score", ascending=False)
          .head(5)[
              ["user_arn", "time_window", "final_score", "severity"]
          ]
    )


if __name__ == "__main__":
    main()
