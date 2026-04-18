from common.logger import SecurityLogger
import random

# ---------------------------------------------------------
# SECURITY RATIONALE:
# The MITM attacker simulates diverse signal degrading vectors
# (random truncation, bitflips) and active payload substitution.
# The Chunk Manager's HMAC checks must deterministically filter 
# these out, while the retransmission engine fetches cleanly.
# ---------------------------------------------------------

class MITMAttacker:
    def __init__(self, target="chunk", corruption_type="bitflip"):
        self.logger = SecurityLogger("mitm_attacker")
        self.target = target
        self.corruption_type = corruption_type

    def intercept_chunk(self, index: int, original_data: bytes, retry_count: int = 0) -> bytes:
        if self.target == "chunk" and index == 1:
            # Simulate attacker abandoning interference after 1 retry so the system can demonstrate recovery
            if retry_count > 0:
                self.logger.info(f"MITM Attack abated for chunk {index} on retry.", event_type="attack_abated")
                return original_data
                
            self.logger.warning(f"MITM Attack: Corrupting chunk {index} via {self.corruption_type}", event_type="attack_active")
            
            if self.corruption_type == "truncate":
                return original_data[:-2] if len(original_data) > 2 else b""
            elif self.corruption_type == "bitflip":
                mutable = bytearray(original_data)
                if len(mutable) > 0:
                    mutable[0] = mutable[0] ^ 0xFF
                return bytes(mutable)
            elif self.corruption_type == "replace":
                return b"\xDE\xAD\xBE\xEF" * (len(original_data) // 4 + 1)
                
        return original_data

    def intercept_manifest(self, original_manifest: dict) -> dict:
        if self.target == "manifest":
            self.logger.warning("MITM Attack: Swapping Manifest Merkle Root to force installation of old vulnerable firmware!", event_type="attack_active")
            original_manifest["version"] = "v99.9.9" # Spoof version to bypass downgrade checks
        return original_manifest
