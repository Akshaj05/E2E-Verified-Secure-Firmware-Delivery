import json
import datetime
import requests
import threading
from .config import DASHBOARD_URL

# ---------------------------------------------------------
# SECURITY RATIONALE:
# A robust, structured logging engine is vital for 
# cybersecurity monitoring. Raw text is hard to parse for SIEMs.
# This logger wraps events in JSON, appending timestamps,
# and asynchronously forwards critical telemetry to the dashboard
# so that fleet managers are immediately alerted to MITM attacks.
# ---------------------------------------------------------

class SecurityLogger:
    def __init__(self, component_name):
        self.component = component_name

    def log(self, level, message, event_type=None, device_id=None):
        payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": level,
            "logger": self.component,
            "message": message
        }
        if event_type:
            payload["event_type"] = event_type
        if device_id:
            payload["device_id"] = device_id

        # Local output
        print(json.dumps(payload))

        # Asynchronous forward to dashboard to prevent blocking safety-critical threads
        def _forward():
            try:
                requests.post(f"{DASHBOARD_URL}/ingest", json=payload, timeout=2)
            except Exception:
                pass # Fail silently if dashboard is down, local log is preserved

        threading.Thread(target=_forward, daemon=True).start()

    def info(self, msg, **kwargs):
        self.log("INFO", msg, **kwargs)

    def warning(self, msg, **kwargs):
        self.log("WARNING", msg, **kwargs)

    def error(self, msg, **kwargs):
        self.log("ERROR", msg, **kwargs)

    def critical(self, msg, **kwargs):
        self.log("CRITICAL", msg, **kwargs)
