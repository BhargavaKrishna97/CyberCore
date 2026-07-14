from flask import Blueprint, request, jsonify
from extensions import db
from models.alert import Alert
from models.threat import Threat
import threading
import os

monitor_bp = Blueprint("monitor", __name__)

# Keep monitor thread reference
_monitor_thread = None
_monitor_running = False


def _start_monitor(path: str):
    """Run watchdog in a background thread."""
    from monitoring.file_monitor import start_monitoring
    start_monitoring(path)


@monitor_bp.route("/start", methods=["POST"])
def start():
    """
    POST /api/monitor/start
    Body: { "path": "/home/kali/test_folder" }
    """
    global _monitor_thread, _monitor_running

    data = request.get_json()
    path = data.get("path", "").strip()

    if not path:
        return jsonify({"error": "path is required"}), 400

    if _monitor_running:
        return jsonify({"status": "already_running"}), 200

    _monitor_running = True
    _monitor_thread = threading.Thread(
        target=_start_monitor, args=(path,), daemon=True
    )
    _monitor_thread.start()

    return jsonify({"status": "monitoring_started", "path": path}), 200


@monitor_bp.route("/stop", methods=["POST"])
def stop():
    """POST /api/monitor/stop"""
    global _monitor_running
    _monitor_running = False

    from monitoring.file_monitor import stop_monitoring
    stop_monitoring()

    return jsonify({"status": "monitoring_stopped"}), 200


@monitor_bp.route("/alerts", methods=["GET"])
def get_alerts():
    """GET /api/monitor/alerts — list all ransomware alerts"""
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(100).all()
    return jsonify([a.to_dict() for a in alerts]), 200


@monitor_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id):
    """POST /api/monitor/alerts/<id>/resolve"""
    alert = Alert.query.get_or_404(alert_id)
    alert.resolved = True
    db.session.commit()
    return jsonify({"status": "resolved", "id": alert_id}), 200

@monitor_bp.route("/quarantine", methods=["GET"])
def list_quarantine():
    """GET /api/monitor/quarantine"""
    quarantine_dir = "quarantine"
    if not os.path.exists(quarantine_dir):
        return jsonify({
            "count": 0,
            "files": []
        }), 200
    files = os.listdir(quarantine_dir)
    return jsonify({
        "count": len(files),
        "files": files
    }), 200

@monitor_bp.route("/dashboard", methods=["GET"])
def dashboard():
    """ GET /api/monitor/dashboard """
    alerts = Alert.query.order_by(
        Alert.created_at.desc()
    ).limit(20).all()
    threats = Threat.query.order_by(
        Threat.id.desc()
    ).limit(20).all()
    critical = Alert.query.filter_by(
        severity="critical"
    ).count()
    high = Alert.query.filter_by(
        severity="high"
    ).count()
    medium = Alert.query.filter_by(
        severity="medium"
    ).count()
    info = Alert.query.filter_by(
        severity="info"
    ).count()
    quarantine_dir = "quarantine"
    files = []
    if os.path.exists(quarantine_dir):
        files = os.listdir(quarantine_dir)
    threat_count = Threat.query.count()
    return jsonify({
        "alerts": [a.to_dict() for a in alerts],
        "threat_count": threat_count,
        "threats": [ 
            t.to_dict()
            for t in threats
        ],
        "counts": {
            "critical":critical,
            "high": high,
            "medium": medium,
            "info": info
        },
        "quarantine": {
            "count": len(files),
            "files": files
        }
    }), 200
@monitor_bp.route("/reset", methods=["POST"])
def reset_dashboard():
    """Reset dashboard data"""

    Alert.query.delete()
    Threat.query.delete()
    db.session.commit()

    quarantine_dir = "quarantine"

    if os.path.exists(quarantine_dir):
        for file in os.listdir(quarantine_dir):
            os.remove(os.path.join(quarantine_dir, file))

    return jsonify({
        "status": "Dashboard reset successfully"
    }), 200
