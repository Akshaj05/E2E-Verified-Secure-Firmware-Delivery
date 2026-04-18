from pydantic import BaseModel
from typing import List, Optional

# ---------------------------------------------------------
# SECURITY RATIONALE:
# Pydantic is used for strict runtime type enforcement.
# This prevents trivial injection attacks or crashes due
# to malformed JSON payloads over the OTA HTTP boundaries.
# ---------------------------------------------------------

class Manifest(BaseModel):
    version: str
    merkle_root: str
    total_chunks: int
    sbom_hash: str
    metadata_signature: str

class UpdateRequest(BaseModel):
    device_id: str
    current_version: str
    battery_level: float
    engine_state: str
    gear_state: str

class SecurityEvent(BaseModel):
    timestamp: str
    level: str
    logger: str
    message: str
    device_id: Optional[str] = None
    event_type: Optional[str] = None
