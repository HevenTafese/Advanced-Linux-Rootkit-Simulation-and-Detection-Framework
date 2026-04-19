import json
import time
import uuid
import logging
from pathlib import Path

log = logging.getLogger(__name__)

ALERT_FILE = Path(__file__).parent / "alerts.json"


def write_alert(check, status, confidence, findings, technique_id=None):
    alert = {
        "id":           str(uuid.uuid4())[:8],
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%S"),
        "check":        check,
        "status":       status,
        "confidence":   confidence,
        "technique_id": technique_id,
        "findings":     findings,
    }
    ALERT_FILE.parent.mkdir(exist_ok=True)
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    return alert


def load_alerts():
    if not ALERT_FILE.exists():
        return []
    alerts = []
    for line in ALERT_FILE.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                alerts.append(json.loads(line))
            except Exception:
                continue
    return alerts


def clear_alerts():
    if ALERT_FILE.exists():
        ALERT_FILE.write_text("")
