import hashlib
import requests
from config import Config

VT_BASE = "https://www.virustotal.com/api/v3"

def _headers():
    return {"x-apikey": Config.VIRUSTOTAL_API_KEY}


def hash_file(file_bytes: bytes) -> str:
    """Return SHA256 hash of file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


def check_file_hash(sha256: str) -> dict:
    """
    Look up a file hash on VirusTotal.
    Returns detection stats and vendor results.
    """
    url = f"{VT_BASE}/files/{sha256}"
    try:
        resp = requests.get(url, headers=_headers(), timeout=15)

        print("VT STATUS:", resp.status_code)
        print("VT RESPONSE:", resp.text[:500])
    except requests.RequestException as e:
        return {"error": str(e)}

    if resp.status_code == 404:
        return {"status": "not_found", "sha256": sha256}

    if resp.status_code != 200:
        return {"error": f"VT API error {resp.status_code}", "details": resp.text}

    data  = resp.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "sha256":     sha256,
        "status":     "found",
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "total":      sum(stats.values()),
        "name":       attrs.get("meaningful_name", ""),
        "stats":      stats,
    }


def upload_and_scan(file_bytes: bytes, filename: str) -> dict:
    """
    Upload a file to VirusTotal for scanning.
    Use for files not already in VT database.
    """
    url = f"{VT_BASE}/files"
    files = {"file": (filename, file_bytes)}
    try:
        resp = requests.post(url, headers=_headers(), files=files, timeout=30)
    except requests.RequestException as e:
        return {"error": str(e)}

    if resp.status_code not in (200, 202):
        return {"error": f"Upload failed {resp.status_code}"}

    analysis_id = resp.json().get("data", {}).get("id", "")
    return {"status": "submitted", "analysis_id": analysis_id}

def get_analysis_result(analysis_id):
    url = f"{VT_BASE}/analyses/{analysis_id}"

    resp = requests.get(
        url,
        headers=_headers(),
        timeout=15
    )

    if resp.status_code != 200:
        return {
            "error": f"VT API error {resp.status_code}"
        }

    data = resp.json()

    stats = (
        data.get("data", {})
            .get("attributes", {})
            .get("stats", {})
    )
    status = (
        data.get("data", {})
            .get("attributes", {})
            .get("status", "")
    )

    return {
        "status": status,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values())
    }
