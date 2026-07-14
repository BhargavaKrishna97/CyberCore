import os 
import shutil
from flask import Blueprint, request, jsonify
from services.virustotal_service import ( check_file_hash, upload_and_scan, hash_file, get_analysis_result )
from extensions import db
from models.threat import Threat
from models.alert import Alert

vt_bp = Blueprint("virustotal", __name__)


@vt_bp.route("/check-hash", methods=["POST"])
def check_hash():
    """
    POST /api/virustotal/check-hash
    Body: { "sha256": "abc123..." }
    """
    data   = request.get_json()
    print("DEBUG DATA:", data)
    sha256 = data.get("sha256", "").strip()

    if not sha256:
        return jsonify({"error": "sha256 is required"}), 400

    result = check_file_hash(sha256)
    malicious = result.get("malicious", 0 )
    if malicious >= 15:
        severity = "critical"
    elif malicious >= 8:
        severity = "high"
    elif malicious >= 1:
        severity = "medium"
    else:
        severity = "info"
    # save alert
    alert = Alert(
        alert_type="virustotal_hash",
        severity=severity,
        message=f"VT Hash Lookup: {malicious} engines detected",
        file_path=sha256
    )
    db.session.add(alert)

    # Save threat if malicious
    if malicious > 0:
        threat = Threat(
            threat_type = "malware",
            severity    = severity,
            description = f"VT: {result['malicious']}/{result['total']} engines detected malware",
            source      = "virustotal",
            raw_data    = result,
        )
        db.session.add(threat)
    db.session.commit()
    return jsonify(result), 200


@vt_bp.route("/upload", methods=["POST"])
def upload_file():
    """
    POST /api/virustotal/upload
    Multipart: file field named 'file'
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded   = request.files["file"]
    file_bytes = uploaded.read()

    # First try hash lookup
    sha256 = hash_file(file_bytes)
    cached = check_file_hash(sha256)
    if cached.get("status") == "found":
        malicious = cached.get("malicious",0)
        if malicious >= 15:
            severity = "critical"
        elif malicious >= 8:
            severity = "high"
        elif malicious >= 1:
            severity = "medium"
        else:
            severity = "info"
        alert = Alert(
            alert_type="virustotal_scan",
            severity=severity,
            message=f"VT Scan: {malicious} engines detected",
            file_path=uploaded.filename
        )
        db.session.add(alert)
        print("Saving Alert:", severity, malicious)
        if cached.get("malicious",0) > 0:
            threat = Threat(
                threat_type="malware",
                severity=severity,
                description=f"VT: {cached.get('malicious',0)}/{cached.get('total',0)} engines detected malware",
                source="virustotal",
                raw_data=cached
            )
            db.session.add(threat)
        db.session.commit()

        return jsonify(cached), 200

    # Upload if not found
    result = upload_and_scan(file_bytes, uploaded.filename)
    import time
    analysis_id = result.get("analysis_id")
    if analysis_id:
        for _ in range(12):
            time.sleep(5)
            analysis = get_analysis_result(analysis_id)
            if analysis.get("status") == "completed":
                result = analysis
                break
    malicious = result.get("malicious",0)
    if malicious >= 15:
        severity = "critical"
    elif malicious >= 8:
        severity = "high"
    elif malicious >= 1:
        severity = "medium"
    else:
        severity = "info"
    alert = Alert(
        alert_type="virustotal_upload",
        severity=severity,
        message=f"VirusTotal Scan: {malicious} engines detected",
        file_path=uploaded.filename
    )
    db.session.add(alert)
    #store threat if malicious
    if result.get("malicious", 0) > 0:
        threat = Threat(
            threat_type="malware",
            severity=severity,
            description=f"VT: {result.get('malicious',0)}/{result.get('total',0)} engines detected malware",
            source="virustotal",
            raw_data=result
        )
        db.session.add(threat)
    db.session.commit()

    result["sha256"] = sha256
    return jsonify(result), 202

@vt_bp.route("/analysis/<analysis_id>")
def analysis_result(analysis_id):
    result = get_analysis_result(
        analysis_id
    )
    return jsonify(result)
