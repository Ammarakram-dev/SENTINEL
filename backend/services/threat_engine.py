from typing import List, Dict


def calculate_threat_score(
    indicators: List[Dict],
    base_score: int = 0
) -> dict:

    score = base_score

    severity_weights = {
        "low": 5,
        "medium": 15,
        "high": 25,
        "critical": 40
    }

    processed_indicators = []

    for indicator in indicators:

        severity = indicator.get("severity", "low").lower()

        weight = severity_weights.get(severity, 5)

        score += weight

        processed_indicators.append({
            "severity": severity,
            "weight": weight,
            "message": indicator.get(
                "message",
                "Security indicator detected."
            )
        })

    score = max(0, min(score, 100))

    if score >= 80:
        risk_level = "CRITICAL"
        recommendation = (
            "Immediate investigation recommended. "
            "The target contains multiple strong risk indicators."
        )

    elif score >= 60:
        risk_level = "HIGH"
        recommendation = (
            "Exercise extreme caution. "
            "Further investigation is recommended before interacting."
        )

    elif score >= 30:
        risk_level = "MEDIUM"
        recommendation = (
            "Some suspicious characteristics were detected. "
            "Additional verification is recommended."
        )

    else:
        risk_level = "LOW"
        recommendation = (
            "No major indicators were detected by the current "
            "analysis rules."
        )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "indicator_count": len(processed_indicators),
        "indicators": processed_indicators,
        "recommendation": recommendation
    }