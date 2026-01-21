from pathlib import Path

OUTPUT = "data/reports/incidents.md"

def write_markdown_report(alerts: list):
    Path("data/reports").mkdir(parents=True, exist_ok=True)

    with open(OUTPUT, "w") as f:
        f.write("# CloudTrail Security Alerts\n\n")

        for a in alerts:
            f.write(f"## {a['what']['severity']} Alert\n")
            f.write(f"**Who:** `{a['who']['user_arn']}`\n\n")
            f.write(f"**When:** {a['what']['time_window']}\n\n")
            f.write(f"**Score:** {a['what']['final_score']}\n\n")
            f.write("**Why:**\n")
            for r in a["why"]["risk_factors"]:
                f.write(f"- {r}\n")
            f.write(f"\n**Confidence:** {a['confidence']}\n\n---\n\n")
