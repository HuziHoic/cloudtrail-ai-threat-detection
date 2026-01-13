import yaml
import pandas as pd
from pathlib import Path

RISK_CONFIG = Path(__file__).parent / "risk_weights.yaml"

with open(RISK_CONFIG, "r") as f:
    RISK_WEIGHTS = yaml.safe_load(f)

def extract_window_context(events: pd.DataFrame) -> dict:
    return {
        "apis": set(events["event_name"].dropna()),
        "identity_type": events["user_type"].mode().iloc[0],
        "mfa_used": events["mfa_authenticated"].any(),
        "readonly_only": events["read_only"].all(),
    }

def compute_rule_risk(context):
    score = 0
    reasons = []

    if context["high_risk_api_used"]:
        score += 30
        reasons.append("High-risk IAM API used")

    if context["admin_role"]:
        score += 20
        reasons.append("Privileged IAM role")

    return score, reasons


def hybrid_score(anomaly_score: float, rule_score: float) -> float:
    return (0.7 * anomaly_score) + (0.3 * rule_score * 20)

def severity_from_score(score: float) -> str:
    if score >= 80:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    elif score >= 30:
        return "LOW"
    return "INFO"
