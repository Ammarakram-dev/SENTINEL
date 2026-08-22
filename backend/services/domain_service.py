import socket
import ipaddress
from urllib.parse import urlparse


def analyze_domain(target: str) -> dict:
    """
    Analyze basic domain and IP characteristics.
    """

    original_target = target.strip()

    # Allow both domains and URLs
    if "://" in original_target:
        parsed = urlparse(original_target)
        hostname = parsed.hostname
    else:
        hostname = original_target.split("/")[0].split(":")[0]

    if not hostname:
        return {
            "target": original_target,
            "status": "invalid",
            "message": "A valid domain or IP address is required."
        }

    result = {
        "target": original_target,
        "hostname": hostname,
        "type": "domain",
        "ip_addresses": [],
        "risk_indicators": []
    }

    # ------------------------------------------------
    # Check whether target is an IP address
    # ------------------------------------------------

    try:
        ip = ipaddress.ip_address(hostname)

        result["type"] = "ip"

        if ip.is_private:
            result["risk_indicators"].append(
                "The IP address belongs to a private network."
            )

        if ip.is_loopback:
            result["risk_indicators"].append(
                "The IP address is a local loopback address."
            )

        result["status"] = "analyzed"

        return result

    except ValueError:
        pass

    # ------------------------------------------------
    # Resolve domain
    # ------------------------------------------------

    try:
        addresses = socket.gethostbyname_ex(hostname)[2]

        result["ip_addresses"] = list(set(addresses))
        result["status"] = "resolved"

    except socket.gaierror:

        result["status"] = "unresolved"

        result["risk_indicators"].append(
            "The domain could not be resolved."
        )

    # ------------------------------------------------
    # Basic suspicious-domain checks
    # ------------------------------------------------

    if len(hostname) > 60:
        result["risk_indicators"].append(
            "The hostname is unusually long."
        )

    if hostname.count(".") >= 4:
        result["risk_indicators"].append(
            "The hostname contains many subdomains."
        )

    if "-" in hostname:
        result["risk_indicators"].append(
            "The hostname contains hyphens."
        )

    result["indicator_count"] = len(result["risk_indicators"])

    return result