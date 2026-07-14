from flask import Blueprint, request, jsonify
from services.nmap_service import run_nmap_scan
from extensions import db
from models.scan_result import ScanResult

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/", methods=["POST"])
def port_scan():
    """
    POST /api/scan/
    Body: { "target": "192.168.1.1", "ports": "1-1024" }
    """
    data   = request.get_json()
    target = data.get("target", "").strip()
    ports  = data.get("ports", "1-6000")

    if not target:
        return jsonify({"error": "target is required"}), 400

    result = run_nmap_scan(target, ports)

    # Save to DB
    record = ScanResult(
        target     = target,
        scan_type  = "nmap",
        status     = "complete",
        open_ports = result,
        raw_output = result,
    )
    db.session.add(record)
    db.session.commit()

    return jsonify(result), 200


@scan_bp.route("/history", methods=["GET"])
def scan_history():
    """GET /api/scan/history — last 50 scans"""
    records = ScanResult.query.filter_by(scan_type="nmap")\
                              .order_by(ScanResult.scanned_at.desc())\
                              .limit(50).all()
    return jsonify([r.to_dict() for r in records]), 200
