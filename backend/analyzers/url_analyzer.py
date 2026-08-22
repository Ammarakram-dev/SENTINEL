from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "password",
    "bank",
    "signin",
    "confirm",
]


def analyze_url(url: str) -> dict:
    """
    Analyze a URL using basic security indicators.
    """

    parsed = urlparse(url)

    score = 0
    indicators = []

    # Check protocol
    if parsed.scheme != "https":
        score += 20
        indicators.append({
            "type": "warning",
            "message": "The URL does not use HTTPS."
        })

    # Check username/password embedded in URL
    if parsed.username or parsed.password:
        score += 30
        indicators.append({
            "type": "danger",
            "message": "The URL contains embedded authentication information."
        })

    # Check suspicious keywords
    url_lower = url.lower()

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    if matched_keywords:
        score += min(len(matched_keywords) * 10, 30)

        indicators.append({
            "type": "warning",
            "message": "Suspicious security-related keywords detected.",
            "keywords": matched_keywords
        })

    # Check excessive URL length
    if len(url) > 150:
        score += 10

        indicators.append({
            "type": "warning",
            "message": "The URL is unusually long."
        })

    # Check excessive subdomains
    hostname = parsed.hostname or ""

    if hostname.count(".") >= 4:
        score += 10

        indicators.append({
            "type": "warning",
            "message": "The domain contains an unusually high number of subdomains."
        })

    # Keep score between 0 and 100
    score = min(score, 100)

    # Determine risk level
    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "indicator_count": len(indicators),
    }