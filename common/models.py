from pydantic import BaseModel, ConfigDict
from typing import List, Optional

# Pydantic is used for strict runtime type enforcement.
# This file is the single source of truth for all data models across the system, 
# ensuring consistency and security in data handling.

# Manifest defines the structure of the firmware manifest that the OTA server will use to verify and manage firmware updates.
class Manifest(BaseModel):
    version: str
    merkle_root: str
    total_chunks: int
    sbom_hash: str
    metadata_signature: str

# UpdateRequest defines the structure of the OTA update request sent by the vehicle to the server
class UpdateRequest(BaseModel):
    device_id: str
    current_version: str
    battery_level: float
    engine_state: str
    gear_state: str

# SecurityEvent defines the structure of the logs that will be emitted by the SecurityLogger.
# extra="allow" because SecurityLogger.log() attaches free-form telemetry kwargs
# (chunk_id, perf_data, cve_meta, ...) on top of the core fields below.
class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: str
    level: str
    logger: str
    message: str
    device_id: Optional[str] = None
    event_type: Optional[str] = None
