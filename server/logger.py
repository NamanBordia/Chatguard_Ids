"""Simple file logger for IDS events."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from threading import Lock

_LOG_LOCK = Lock()
LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "logs.txt"


def log_event(username: str, message: str, threat_type: str, action_taken: str, severity: str = "none") -> None:
    """Append a structured IDS event record to logs/logs.txt."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_message = message.replace("\n", " ").strip()
    row = f"{timestamp} | {username} | {clean_message} | {threat_type} | {severity} | {action_taken}\n"

    with _LOG_LOCK:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(row)
