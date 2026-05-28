from flask import Blueprint, request, jsonify
from services.abuseipdb_service import check_ip, check_block
from extensions import db
from models.threat import Threat

abuse_bp = Blueprint("abuseipdb", __name__)


@abuse_bp.route("/check-ip", methods=["POST"])
def check_single_ip():
    """
    POST /api/abuseipdb/check-ip
    Body: { "ip": "8.8.8.8" }
    """
    data = request.get_json()
    ip   = data.get("ip", "").strip()

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    result = check_ip(ip)

    # Store if score is high (suspicious IP)
    score = result.get("abuse_score", 0)
    if score and score > 50:
        severity = "critical" if score > 85 else "high"
        threat = Threat(
            ip_address  = ip,
            threat_type = "malicious_ip",
            severity    = severity,
            description = f"AbuseIPDB score {score}% for {ip}",
            source      = "abuseipdb",
            raw_data    = result,
        )
        db.session.add(threat)
        db.session.commit()

    return jsonify(result), 200


@abuse_bp.route("/check-block", methods=["POST"])
def check_cidr():
    """
    POST /api/abuseipdb/check-block
    Body: { "network": "192.168.1.0/24" }
    """
    data    = request.get_json()
    network = data.get("network", "").strip()

    if not network:
        return jsonify({"error": "network is required"}), 400

    result = check_block(network)
    return jsonify(result), 200


@abuse_bp.route("/threats", methods=["GET"])
def list_threats():
    """GET /api/abuseipdb/threats — list stored IP threats"""
    threats = Threat.query.filter_by(source="abuseipdb")\
                          .order_by(Threat.detected_at.desc())\
                          .limit(50).all()
    return jsonify([t.to_dict() for t in threats]), 200
