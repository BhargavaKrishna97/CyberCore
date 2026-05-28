from app import db
from datetime import datetime

class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id         = db.Column(db.Integer, primary_key=True)
    target     = db.Column(db.String(200))
    scan_type  = db.Column(db.String(50))   # nmap / yara / virustotal
    status     = db.Column(db.String(20))   # clean / infected / suspicious
    open_ports = db.Column(db.JSON)
    raw_output = db.Column(db.JSON)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":         self.id,
            "target":     self.target,
            "scan_type":  self.scan_type,
            "status":     self.status,
            "open_ports": self.open_ports,
            "raw_output": self.raw_output,
            "scanned_at": self.scanned_at.isoformat(),
        }
