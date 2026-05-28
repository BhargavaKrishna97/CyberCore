import requests
from config import Config

ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

def _headers():
    return {
        "Key":    Config.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }


def check_ip(ip_address: str, max_age_days: int = 90) -> dict:
    """
    Check an IP address against AbuseIPDB.
    Returns abuse confidence score and report data.
    """
    params = {
        "ipAddress":  ip_address,
        "maxAgeInDays": max_age_days,
        "verbose": True
    }
    try:
        resp = requests.get(
            f"{ABUSE_BASE}/check",
            headers=_headers(),
            params=params,
            timeout=10
        )
    except requests.RequestException as e:
        return {"error": str(e)}

    if resp.status_code != 200:
        return {"error": f"AbuseIPDB error {resp.status_code}"}

    data = resp.json().get("data", {})
    return {
        "ip":                 data.get("ipAddress"),
        "is_public":          data.get("isPublic"),
        "abuse_score":        data.get("abuseConfidenceScore"),
        "country":            data.get("countryCode"),
        "isp":                data.get("isp"),
        "domain":             data.get("domain"),
        "total_reports":      data.get("totalReports"),
        "last_reported":      data.get("lastReportedAt"),
        "is_tor":             data.get("isTor"),
        "is_whitelisted":     data.get("isWhitelisted"),
        "usage_type":         data.get("usageType"),
    }


def check_block(network: str) -> dict:
    """
    Check a CIDR block (e.g. '192.168.1.0/24') against AbuseIPDB.
    """
    params = {"network": network}
    try:
        resp = requests.get(
            f"{ABUSE_BASE}/check-block",
            headers=_headers(),
            params=params,
            timeout=10
        )
    except requests.RequestException as e:
        return {"error": str(e)}

    if resp.status_code != 200:
        return {"error": f"AbuseIPDB block check error {resp.status_code}"}

    return resp.json()
