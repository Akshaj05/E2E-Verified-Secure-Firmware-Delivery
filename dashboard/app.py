from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from collections import defaultdict
import os
import sys
import subprocess
import json
from pydantic import BaseModel

app = FastAPI(title="Fleet Management Dashboard")

logs = []
AUDIT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "audit")
AUDIT_FILE = os.path.join(AUDIT_DIR, "audit_log.json")

# Ensure audit file exists
os.makedirs(AUDIT_DIR, exist_ok=True)
if not os.path.exists(AUDIT_FILE):
    with open(AUDIT_FILE, "w") as f:
        json.dump([], f)

@app.get("/")
def get_dashboard():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(index_path, headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    })

@app.post("/ingest")
async def ingest_log(request: Request):
    data = await request.json()
    logs.append(data)
    
    # Persistently append to the central audit log JSON array
    try:
        with open(AUDIT_FILE, "r") as f:
            disk_logs = json.load(f)
    except:
        disk_logs = []
        
    if not disk_logs or data.get("event_type") == "ota_start":
        # Create a new session block
        disk_logs.append({
            "update_session_timestamp": data.get("timestamp", ""),
            "events": [data]
        })
    else:
        # Append to latest session block
        disk_logs[-1]["events"].append(data)
    
    with open(AUDIT_FILE, "w") as f:
        json.dump(disk_logs, f, indent=2)
        
    return {"status": "ok"}

@app.get("/metrics")
def get_metrics():
    events = defaultdict(int)
    for log in logs:
        evt = log.get("event_type")
        if evt:
            events[evt] += 1
            
    return {
        "total_logs": len(logs),
        "metrics": dict(events)
    }

@app.get("/logs")
def get_logs():
    return logs

@app.delete("/logs/clear")
def clear_logs():
    logs.clear()
    return {"status": "ok"}

class DemoRequest(BaseModel):
    script_name: str

@app.post("/run-demo")
def run_demo(req: DemoRequest):
    root_dir = os.path.dirname(os.path.dirname(__file__))
    script_path = os.path.join(root_dir, "scripts", req.script_name)
    if os.path.exists(script_path) and script_path.endswith(".py"):
        subprocess.Popen([sys.executable, script_path], cwd=root_dir)
        return {"status": "ok", "script": req.script_name}
    return {"status": "error", "message": "Script not found"}
