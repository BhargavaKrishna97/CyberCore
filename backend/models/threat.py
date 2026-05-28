from app import db
from datetime import datetime

class Threat(db.Model):
    __tablename__ = "threats"

    id          = db.Column(db.Integer, primary_key=True)
    ip_address  = db.Column(db.String(45))
    threat_type = db.Column(db.String(100))
    severity    = db.Column(db.String(20))   # low / medium / high / critical
    description = db.Column(db.Text)
    source      = db.Column(db.String(50))   # abuseipdb / virustotal / yara / nmap
    raw_data    = db.Column(db.JSON)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":          self.id,
            "ip_address":  self.ip_address,
            "threat_type": self.threat_type,
            "severity":    self.severity,
            "description": self.description,
            "source":      self.source,
            "detected_at": self.detected_at.isoformat(),
        }
