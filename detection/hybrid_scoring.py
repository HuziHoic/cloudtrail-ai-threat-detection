import yaml
import pandas as pd
from pathlib import Path

RISK_CONFIG = Path(__file__).parent / "risk_weights.yaml"

HIGH_RISK_APIS = {
    "CreateAccessKey",
    "AttachRolePolicy",
    "PassRole"
}

with open(RISK_CONFIG, "r") as f:
    RISK_WEIGHTS = yaml.safe_load(f)

def extract_window_context(row):
    api_list = row.get("api_call_list", [])

    if isinstance(api_list, str):
        api_list = api_list.split(",")

    return {
        "user_arn": row["user_arn"],
        "api_calls": row.get("unique_api_calls", 0),
        "is_admin": row.get("is_admin_role", False),
        "high_risk_api_used": any(api in HIGH_RISK_APIS for api in api_list),
    }

def compute_rule_risk(context):
    """
    Returns:
      numeric_score (int)
      reasons (list[str])
    """
    score = 0
    reasons = []

    if context.get("high_risk_api_used", False):
        score += 3
        reasons.append("High-risk IAM API used")

    if context.get("is_admin", False):
        score += 2
        reasons.append("Admin or privileged role")

    return score, reasons


def hybrid_score(anomaly_score, rule_score):
    """
    anomaly_score: 0–100
    rule_score: small int (0–5)
    """
    return (0.7 * anomaly_score) + (0.3 * rule_score * 20)

def severity_from_score(score: float) -> str:
    if score >= 80:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    elif score >= 30:
        return "LOW"
    return "INFO"
