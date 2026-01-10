import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

DATA_PATH = "data/features/behavior_features.parquet"
MODEL_DIR = "models/artifacts"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")

# Columns to exclude from training
EXCLUDE_COLS = [
    "user_arn",
    "source_ip",
    "event_time"
]

def main():
    print("[+] Loading features...")
    df = pd.read_parquet(DATA_PATH)
    df = df.sort_values("time_window")

    split_idx = int(len(df) * 0.8)
    train_df = df.iloc[:split_idx]
    eval_df = df.iloc[split_idx:]

    def prepare_X(df):
        X = df.drop(columns=EXCLUDE_COLS, errors="ignore")
        return X.select_dtypes(include=["number", "bool"])

    X_train = prepare_X(train_df)
    X_eval = prepare_X(eval_df)

    feature_cols = X_train.columns.tolist()

    print(f"[+] Using {len(feature_cols)} features")

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=0.01,
        random_state=42,
        n_jobs=-1
    )

    print("[+] Training Isolation Forest...")
    model.fit(X_train)

    # Generate anomaly scores
    train_scores = model.decision_function(X_train)
    eval_scores = model.decision_function(X_eval)

    print("[+] Score summary:")
    print(f"    Train mean score: {train_scores.mean():.4f}")
    print(f"    Eval mean score:  {eval_scores.mean():.4f}")

    # Persist model
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "features": feature_cols
        },
        MODEL_PATH
    )

    print(f"[+] Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()  
