import json
import datetime
import requests
import threading
from .config import DASHBOARD_URL

# Structured JSON logging for SIEM integration with timestamps and async alerting for security events.

class SecurityLogger:
    def __init__(self, component_name):
        self.component = component_name

    def log(self, level, message, event_type=None, device_id=None, **kwargs):
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
        
        # Append any extra telemetry metrics like chunk_id
        payload.update(kwargs)

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
