"""
Real-time file system monitor using watchdog.
Detects ransomware-like behaviour:
  - Mass file renames / extensions changed to known ransomware extensions
  - Rapid file modifications
  - Creation of ransom note files
"""

import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Known ransomware extensions
RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypto", ".enc", ".crypt",
    ".locky", ".cerber", ".wannacry", ".wnry", ".wncry",
    ".zepto", ".thor", ".aesir", ".odin", ".xyz", ".lol",
}

RANSOM_NOTE_NAMES = {
    "readme.txt", "how_to_decrypt.txt", "decrypt_files.html",
    "ransom.txt", "your_files_are_encrypted.txt", "!!!_readme_!!!"
}

_observer = None


def _is_ransomware_extension(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    return ext in RANSOMWARE_EXTENSIONS


def _is_ransom_note(path: str) -> bool:
    basename = os.path.basename(path).lower()
    return basename in RANSOM_NOTE_NAMES


def _save_alert(alert_type: str, severity: str, message: str, file_path: str):
    """Save alert to DB (import inside function to avoid circular imports)."""
    try:
        from app import db
        from flask import current_app
        from models.alert import Alert
        with current_app.app_context():
            alert = Alert(
                alert_type = alert_type,
                severity   = severity,
                message    = message,
                file_path  = file_path,
            )
            db.session.add(alert)
            db.session.commit()
    except Exception as e:
        print(f"[Monitor] DB save failed: {e}")


class RansomwareHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self._event_count = 0
        self._start_time  = time.time()

    def _check_burst(self):
        """Alert if more than 30 events in 5 seconds (mass encryption sign)."""
        self._event_count += 1
        elapsed = time.time() - self._start_time

        if elapsed > 5:
            self._event_count = 0
            self._start_time  = time.time()
        elif self._event_count > 30:
            print("[ALERT] Burst of file events — possible ransomware!")
            _save_alert(
                alert_type = "ransomware_burst",
                severity   = "critical",
                message    = f"{self._event_count} file events in {elapsed:.1f}s — possible ransomware",
                file_path  = "",
            )
            self._event_count = 0
            self._start_time  = time.time()

    def on_created(self, event):
        if event.is_directory:
            return
        self._check_burst()
        path = event.src_path

        if _is_ransom_note(path):
            print(f"[CRITICAL] Ransom note created: {path}")
            _save_alert("ransom_note", "critical",
                        f"Ransom note detected: {path}", path)

        if _is_ransomware_extension(path):
            print(f"[CRITICAL] Ransomware file created: {path}")
            _save_alert("ransomware_file", "critical",
                        f"File with ransomware extension created: {path}", path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._check_burst()

    def on_moved(self, event):
        if event.is_directory:
            return
        self._check_burst()
        dest = event.dest_path

        if _is_ransomware_extension(dest):
            print(f"[CRITICAL] File renamed to ransomware extension: {dest}")
            _save_alert("ransomware_rename", "critical",
                        f"File renamed to {dest}", dest)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._check_burst()


def start_monitoring(path: str):
    """Start watchdog observer on the given path."""
    global _observer

    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

    print(f"[Monitor] Watching: {path}")
    event_handler = RansomwareHandler()
    _observer = Observer()
    _observer.schedule(event_handler, path, recursive=True)
    _observer.start()

    try:
        while _observer.is_alive():
            time.sleep(1)
    except Exception:
        pass
    finally:
        _observer.stop()
        _observer.join()


def stop_monitoring():
    """Stop the running observer."""
    global _observer
    if _observer and _observer.is_alive():
        _observer.stop()
        _observer = None
        print("[Monitor] Stopped.")
