from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import sqlite3
import socket
import ipaddress

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# =========================================================
# SENTINEL CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_FILE = BASE_DIR / "sentinel.db"


# =========================================================
# DATABASE
# =========================================================

def get_database():
    connection = sqlite3.connect(
        DATABASE_FILE,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    connection = get_database()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        connection.commit()

    finally:

        connection.close()


def save_scan(
    target,
    target_type,
    risk_score,
    risk_level,
    recommendation
):

    connection = get_database()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO scans (
                target,
                target_type,
                risk_score,
                risk_level,
                recommendation,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                target_type,
                risk_score,
                risk_level,
                recommendation,
                datetime.now().isoformat(
                    timespec="seconds"
                )
            )
        )

        connection.commit()

        return cursor.lastrowid

    finally:

        connection.close()


def get_all_scans():

    connection = get_database()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                target,
                target_type,
                risk_score,
                risk_level,
                recommendation,
                created_at
            FROM scans
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


def get_one_scan(scan_id):

    connection = get_database()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                target,
                target_type,
                risk_score,
                risk_level,
                recommendation,
                created_at
            FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:

        connection.close()


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

initialize_database()


# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="SENTINEL",
    description=(
        "Intelligent Digital Threat Monitoring "
        "and Security Analysis Platform"
    ),
    version="1.0.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8000",
        "http://localhost:8000"
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"]
)


# =========================================================
# REQUEST MODELS
# =========================================================

class URLRequest(BaseModel):

    url: str


class DomainRequest(BaseModel):

    target: str


class ThreatRequest(BaseModel):

    target: str

    target_type: str = "url"


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url: str):

    url = url.strip()

    if not url:

        return {
            "url": url,
            "risk_score": 0,
            "risk_level": "LOW",
            "indicator_count": 1,
            "indicators": [
                {
                    "severity": "high",
                    "message": "Empty URL provided."
                }
            ]
        }


    parsed = urlparse(url)

    score = 0

    indicators = []


    # -----------------------------------------------------
    # URL SCHEME
    # -----------------------------------------------------

    if parsed.scheme.lower() != "https":

        score += 20

        indicators.append(
            {
                "severity": "medium",
                "message": (
                    "The website does not use HTTPS."
                )
            }
        )


    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    suspicious_keywords = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "confirm",
        "bank",
        "wallet",
        "payment"

    ]


    found_keywords = []

    lower_url = url.lower()


    for keyword in suspicious_keywords:

        if keyword in lower_url:

            found_keywords.append(
                keyword
            )


    if found_keywords:

        keyword_score = min(
            len(found_keywords) * 8,
            40
        )

        score += keyword_score

        indicators.append(
            {
                "severity": "medium",
                "message": (
                    "Potentially sensitive "
                    "keywords were detected."
                ),
                "keywords": found_keywords
            }
        )


    # -----------------------------------------------------
    # URL LENGTH
    # -----------------------------------------------------

    if len(url) > 150:

        score += 10

        indicators.append(
            {
                "severity": "low",
                "message": (
                    "The URL is unusually long."
                )
            }
        )


    # -----------------------------------------------------
    # HOSTNAME
    # -----------------------------------------------------

    hostname = parsed.hostname or ""


    if hostname.count(".") >= 4:

        score += 10

        indicators.append(
            {
                "severity": "medium",
                "message": (
                    "The domain contains "
                    "many subdomains."
                )
            }
        )


    # -----------------------------------------------------
    # EMBEDDED CREDENTIALS
    # -----------------------------------------------------

    if parsed.username or parsed.password:

        score += 30

        indicators.append(
            {
                "severity": "high",
                "message": (
                    "Authentication information "
                    "is embedded in the URL."
                )
            }
        )


    # -----------------------------------------------------
    # IP ADDRESS IN URL
    # -----------------------------------------------------

    if hostname:

        try:

            ipaddress.ip_address(
                hostname
            )

            score += 15

            indicators.append(
                {
                    "severity": "medium",
                    "message": (
                        "The URL uses a direct "
                        "IP address instead of a domain."
                    )
                }
            )

        except ValueError:

            pass


    # -----------------------------------------------------
    # FINAL SCORE
    # -----------------------------------------------------

    score = min(
        max(score, 0),
        100
    )


    # -----------------------------------------------------
    # RISK LEVEL
    # -----------------------------------------------------

    if score >= 80:

        risk_level = "CRITICAL"

    elif score >= 60:

        risk_level = "HIGH"

    elif score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    return {

        "url": url,

        "risk_score": score,

        "risk_level": risk_level,

        "indicator_count": len(
            indicators
        ),

        "indicators": indicators

    }


# =========================================================
# DOMAIN / IP ANALYSIS
# =========================================================

def analyze_domain(target: str):

    target = target.strip()


    # -----------------------------------------------------
    # EXTRACT HOSTNAME
    # -----------------------------------------------------

    if "://" in target:

        hostname = urlparse(
            target
        ).hostname

    else:

        hostname = (
            target
            .split("/")[0]
            .split(":")[0]
        )


    # -----------------------------------------------------
    # INVALID TARGET
    # -----------------------------------------------------

    if not hostname:

        return {

            "target": target,

            "status": "invalid",

            "message": (
                "A valid domain or IP "
                "address is required."
            )

        }


    result = {

        "target": target,

        "hostname": hostname,

        "type": "domain",

        "ip_addresses": [],

        "risk_indicators": []

    }


    # -----------------------------------------------------
    # IP ANALYSIS
    # -----------------------------------------------------

    try:

        ip = ipaddress.ip_address(
            hostname
        )

        result["type"] = "ip"

        result["status"] = "analyzed"


        if ip.is_private:

            result["risk_indicators"].append(
                "The IP address belongs "
                "to a private network."
            )


        if ip.is_loopback:

            result["risk_indicators"].append(
                "The IP address is a "
                "local loopback address."
            )


        if ip.is_multicast:

            result["risk_indicators"].append(
                "The IP address is a "
                "multicast address."
            )


        result["indicator_count"] = len(
            result["risk_indicators"]
        )


        return result


    except ValueError:

        pass


    # -----------------------------------------------------
    # DNS RESOLUTION
    # -----------------------------------------------------

    try:

        addresses = socket.gethostbyname_ex(
            hostname
        )[2]

        result["ip_addresses"] = list(
            set(addresses)
        )

        result["status"] = "resolved"


    except (
        socket.gaierror,
        socket.timeout,
        OSError
    ):

        result["status"] = "unresolved"

        result["risk_indicators"].append(
            "The domain could not be resolved."
        )


    # -----------------------------------------------------
    # DOMAIN CHARACTERISTICS
    # -----------------------------------------------------

    if len(hostname) > 60:

        result["risk_indicators"].append(
            "The hostname is unusually long."
        )


    if hostname.count(".") >= 4:

        result["risk_indicators"].append(
            "The hostname contains "
            "many subdomains."
        )


    if "-" in hostname:

        result["risk_indicators"].append(
            "The hostname contains hyphens."
        )


    result["indicator_count"] = len(
        result["risk_indicators"]
    )


    return result


# =========================================================
# THREAT SCORING
# =========================================================

def calculate_threat_score(
    indicators,
    base_score=0
):

    score = base_score

    weights = {

        "low": 5,

        "medium": 15,

        "high": 25,

        "critical": 40

    }


    processed = []


    for indicator in indicators:

        severity = str(
            indicator.get(
                "severity",
                "low"
            )
        ).lower()


        weight = weights.get(
            severity,
            5
        )


        processed.append(
            {
                "severity": severity,

                "weight": weight,

                "message": indicator.get(
                    "message",
                    "Security indicator detected."
                )
            }
        )


    # -----------------------------------------------------
    # IMPORTANT
    # -----------------------------------------------------
    # URL analysis already calculated a score.
    # We therefore don't add the indicator weights
    # again when base_score is already present.
    #
    # For domain/IP analysis base_score is zero,
    # so indicator weights are calculated normally.
    # -----------------------------------------------------

    if base_score == 0:

        score = 0

        for item in processed:

            score += item["weight"]


    score = min(
        max(score, 0),
        100
    )


    # -----------------------------------------------------
    # FINAL RISK
    # -----------------------------------------------------

    if score >= 80:

        level = "CRITICAL"

        recommendation = (
            "Immediate investigation is "
            "recommended."
        )

    elif score >= 60:

        level = "HIGH"

        recommendation = (
            "Exercise extreme caution "
            "and investigate the target."
        )

    elif score >= 30:

        level = "MEDIUM"

        recommendation = (
            "Suspicious characteristics "
            "were detected. Further "
            "verification is recommended."
        )

    else:

        level = "LOW"

        recommendation = (
            "No major indicators were "
            "detected by the current rules."
        )


    return {

        "risk_score": score,

        "risk_level": level,

        "indicator_count": len(
            processed
        ),

        "indicators": processed,

        "recommendation": recommendation

    }


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {

        "name": "SENTINEL",

        "status": "online",

        "message": (
            "Threat monitoring system "
            "is running."
        )

    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    return {

        "status": "healthy",

        "database": "connected",

        "version": "1.0.0"

    }


# =========================================================
# URL ANALYSIS API
# =========================================================

@app.post("/analyze/url")
def analyze_url_api(
    request: URLRequest
):

    return analyze_url(
        request.url
    )


# =========================================================
# DOMAIN / IP API
# =========================================================

@app.post("/analyze/domain")
def analyze_domain_api(
    request: DomainRequest
):

    return analyze_domain(
        request.target
    )


# =========================================================
# FULL THREAT ASSESSMENT
# =========================================================

@app.post("/analyze/threat")
def analyze_threat_api(
    request: ThreatRequest
):

    target_type = (
        request.target_type
        .strip()
        .lower()
    )


    # -----------------------------------------------------
    # URL
    # -----------------------------------------------------

    if target_type == "url":

        analysis = analyze_url(
            request.target
        )

        indicators = analysis[
            "indicators"
        ]

        base_score = analysis[
            "risk_score"
        ]


    # -----------------------------------------------------
    # DOMAIN / IP
    # -----------------------------------------------------

    elif target_type in [
        "domain",
        "ip"
    ]:

        analysis = analyze_domain(
            request.target
        )

        indicators = []


        for message in analysis.get(
            "risk_indicators",
            []
        ):

            indicators.append(
                {
                    "severity": "medium",
                    "message": message
                }
            )


        base_score = 0


    # -----------------------------------------------------
    # INVALID TYPE
    # -----------------------------------------------------

    else:

        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid target_type. "
                "Use url, domain, or ip."
            )
        )


    # -----------------------------------------------------
    # THREAT ENGINE
    # -----------------------------------------------------

    threat = calculate_threat_score(
        indicators,
        base_score
    )


    # -----------------------------------------------------
    # SAVE SCAN
    # -----------------------------------------------------

    scan_id = save_scan(

        target=request.target,

        target_type=target_type,

        risk_score=threat[
            "risk_score"
        ],

        risk_level=threat[
            "risk_level"
        ],

        recommendation=threat[
            "recommendation"
        ]

    )


    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    return {

        "scan_id": scan_id,

        "target": request.target,

        "target_type": target_type,

        "analysis": analysis,

        "threat_assessment": threat

    }


# =========================================================
# SCAN HISTORY
# =========================================================

@app.get("/scans")
def scan_history():

    scans = get_all_scans()

    return {

        "count": len(scans),

        "scans": scans

    }


# =========================================================
# SINGLE SCAN
# =========================================================

@app.get("/scans/{scan_id}")
def single_scan(
    scan_id: int
):

    scan = get_one_scan(
        scan_id
    )


    if scan is None:

        raise HTTPException(
            status_code=404,
            detail="Scan not found."
        )


    return scan