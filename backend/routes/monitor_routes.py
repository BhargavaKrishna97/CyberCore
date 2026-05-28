from flask import Blueprint, request, jsonify
from extensions import db
from models.alert import Alert
import threading

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
