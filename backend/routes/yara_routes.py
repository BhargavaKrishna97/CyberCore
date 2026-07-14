import os
import tempfile
from flask import Blueprint, request, jsonify
from services.yara_service import scan_file, scan_bytes
from extensions import db
from models.scan_result import ScanResult
from models.alert import Alert

yara_bp = Blueprint("yara", __name__)


@yara_bp.route("/scan-file", methods=["POST"])
def scan_filepath():
    """
    POST /api/yara/scan-file
    Body: { "file_path": "/path/to/file" }
    """
    data      = request.get_json()
    file_path = data.get("file_path", "").strip()

    if not file_path:
        return jsonify({"error": "file_path is required"}), 400

    result = scan_file(file_path)

    # Save scan + alert if infected
    record = ScanResult(
        target    = file_path,
        scan_type = "yara",
        status    = result.get("status", "unknown"),
        raw_output= result,
    )
    db.session.add(record)

    if result.get("status") == "INFECTED":
        alert = Alert(
            alert_type = "malware_detected",
            severity   = "critical",
            message    = f"YARA match on {file_path}: {result.get('matches')}",
            file_path  = file_path,
        )
        db.session.add(alert)

    db.session.commit()
    return jsonify(result), 200


@yara_bp.route("/scan-upload", methods=["POST"])
def scan_upload():
    """
    POST /api/yara/scan-upload
    Multipart: file field named 'file'
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded = request.files["file"]
    file_bytes = uploaded.read()

    result = scan_bytes(file_bytes)
    result["filename"] = uploaded.filename

    # --------------------------
    # Save Scan Result to DB
    # --------------------------
    record = ScanResult(
        target=uploaded.filename,
        scan_type="yara",
        status=result.get("status", "unknown"),
        raw_output=result
    )
    db.session.add(record)

    # --------------------------
    # Create Alert if INFECTED
    # --------------------------
    if result.get("status") == "INFECTED":
        alert = Alert(
            alert_type="malware_detected",
            severity="critical",
            message=f"Upload infected: {uploaded.filename}",
            file_path=uploaded.filename
        )
        db.session.add(alert)

    db.session.commit()

    return jsonify(result), 200
#Scan History API
@yara_bp.route("/history", methods=["GET"])
def scan_history():
    scans = ScanResult.query.all()

    return jsonify([
        {
            "id": s.id,
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "raw_output": s.raw_output
        }
        for s in scans
    ]), 200
#Alerts API
@yara_bp.route("/alerts", methods=["GET"])
def get_alerts():
    alerts = Alert.query.all()

    return jsonify([
        {
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity,
            "message": a.message,
            "file": a.file_path
        }
        for a in alerts
    ]), 200
