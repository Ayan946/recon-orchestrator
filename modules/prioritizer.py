SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def prioritize_findings(risk_findings, signal_findings):
    prioritized = []

    for f in risk_findings:
        prioritized.append({
            "score": SEVERITY_SCORE.get(f["severity"], 1),
            "category": "risk",
            "details": f
        })

    for f in signal_findings:
        prioritized.append({
            "score": 2,
            "category": "signal",
            "details": f
        })

    return sorted(prioritized, key=lambda x: x["score"], reverse=True)
