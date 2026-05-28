from extensions import db
from datetime import datetime

class Alert(db.Model):
    __tablename__ = "alerts"

    id          = db.Column(db.Integer, primary_key=True)
    alert_type  = db.Column(db.String(100))  # ransomware / port_scan / malware
    severity    = db.Column(db.String(20))
    message     = db.Column(db.Text)
    file_path   = db.Column(db.String(500))
    resolved    = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":         self.id,
            "alert_type": self.alert_type,
            "severity":   self.severity,
            "message":    self.message,
            "file_path":  self.file_path,
            "resolved":   self.resolved,
            "created_at": self.created_at.isoformat(),
        }
