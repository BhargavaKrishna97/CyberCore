from flask import Blueprint, request, jsonify
from services.virustotal_service import check_file_hash, upload_and_scan, hash_file
from extensions import db
from models.threat import Threat

vt_bp = Blueprint("virustotal", __name__)


@vt_bp.route("/check-hash", methods=["POST"])
def check_hash():
    """
    POST /api/virustotal/check-hash
    Body: { "sha256": "abc123..." }
    """
    data   = request.get_json()
    sha256 = data.get("sha256", "").strip()

    if not sha256:
        return jsonify({"error": "sha256 is required"}), 400

    result = check_file_hash(sha256)

    # Store threat if malicious
    if result.get("malicious", 0) > 0:
        threat = Threat(
            threat_type = "malware",
            severity    = "critical" if result["malicious"] > 5 else "high",
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
        return jsonify(cached), 200

    # Upload if not found
    result = upload_and_scan(file_bytes, uploaded.filename)
    result["sha256"] = sha256
    return jsonify(result), 202
