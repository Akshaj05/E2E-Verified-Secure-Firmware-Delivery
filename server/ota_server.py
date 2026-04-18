from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import base64
from common.logger import SecurityLogger

# ---------------------------------------------------------
# SECURITY RATIONALE:
# The OTA Server is considered untrusted infrastructure (cloud).
# It simply serves static artifacts (manifests, chunks).
# We MUST NOT offload security decisions to this server.
# The `attack_state` hooks allow the simulation to replicate 
# MITM tampering directly on the wire without needing heavy
# external network interception tools for the demo.
# ---------------------------------------------------------

app = FastAPI(title="Secure OTA Distribution Server")
logger = SecurityLogger("ota_server")

# In-memory storage for demonstration
RELEASE_STORE = {
    "manifest": None,
    "chunks": []
}

class ReleaseUpload(BaseModel):
    manifest: dict
    chunks_base64: List[str]

@app.post("/upload")
def upload_release(data: ReleaseUpload):
    RELEASE_STORE["manifest"] = data.manifest
    RELEASE_STORE["chunks"] = [base64.b64decode(c) for c in data.chunks_base64]
    return {"status": "success", "message": f"Version {data.manifest['version']} uploaded."}

@app.get("/manifest")
def get_manifest():
    if not RELEASE_STORE["manifest"]:
        raise HTTPException(status_code=404, detail="No release available")
    return RELEASE_STORE["manifest"]

@app.get("/chunk/{chunk_id}")
def get_chunk(chunk_id: int):
    if not RELEASE_STORE["chunks"] or chunk_id >= len(RELEASE_STORE["chunks"]) or chunk_id < 0:
        raise HTTPException(status_code=404, detail="Chunk not found")
        
    logger.info(f"Serving chunk request {chunk_id}", event_type="server_serving_chunk")
    chunk_data = RELEASE_STORE["chunks"][chunk_id]
    return base64.b64encode(chunk_data).decode('utf-8')
