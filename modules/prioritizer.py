def prioritize_findings(risk_findings, signal_findings):
    prioritized = []

    severity_score = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    # ---- Add Risk Findings ----
    for finding in risk_findings:
        score = severity_score.get(finding["severity"], 0)

        prioritized.append({
            "category": "risk",
            "score": score,
            "details": finding
        })

    # ---- Add Signal Findings ----
    for finding in signal_findings:
        # Signals get medium baseline priority
        prioritized.append({
            "category": "signal",
            "score": 2,
            "details": finding
        })

    # ---- Sort by score descending ----
    prioritized.sort(key=lambda x: x["score"], reverse=True)

    return prioritized
