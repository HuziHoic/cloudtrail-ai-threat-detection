def build_alert(row: dict) -> dict:
    return {
        "who": {
            "user_arn": row["user_arn"],
            "account_id": row.get("account_id"),
        },
        "what": {
            "time_window": str(row["time_window"]),
            "severity": row["severity"],
            "final_score": round(row["final_score"], 2),
        },
        "why": {
            "anomalous_behavior": round(row["anomaly_score"], 2),
            "rule_risk": round(row.get("rule_score", 0), 2),
            "risk_factors": row.get("risk_reasons", []),
        },
        "confidence": severity_to_confidence(row["severity"]),
    }


def severity_to_confidence(severity: str) -> str:
    return {
        "HIGH": "High confidence malicious behavior",
        "MEDIUM": "Suspicious behavior requiring review",
        "LOW": "Unusual but likely benign behavior",
    }.get(severity, "Unknown")
