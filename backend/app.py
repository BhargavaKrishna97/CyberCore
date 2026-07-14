import threading
from flask import Flask, jsonify
from flask_cors import CORS
from extensions import db, jwt
from monitoring.file_monitor import start_monitoring

def create_app():
    app = Flask(__name__)
    from config import Config
    app.config.from_object(Config)

    CORS(app)
    db.init_app(app)
    jwt.init_app(app)

    from routes.scan_routes       import scan_bp
    from routes.yara_routes       import yara_bp
    from routes.virustotal_routes import vt_bp
    from routes.abuseipdb_routes  import abuse_bp
    from routes.monitor_routes    import monitor_bp

    app.register_blueprint(scan_bp,    url_prefix="/api/scan")
    app.register_blueprint(yara_bp,    url_prefix="/api/yara")
    app.register_blueprint(vt_bp,      url_prefix="/api/virustotal")
    app.register_blueprint(abuse_bp,   url_prefix="/api/abuseipdb")
    app.register_blueprint(monitor_bp, url_prefix="/api/monitor")

    @app.route("/")
    def health():
        return jsonify({"status": "ok", "message": "CyberCore Backend Running"})

    with app.app_context():
        db.create_all()

    return app

app = create_app()

if __name__ == "__main__":
    monitor_thread = threading.Thread(
        target=start_monitoring,
        args=("uploads",),
        daemon=True
    )
    monitor_thread.start()
    app.run(debug=True, host="0.0.0.0", port=5000)
