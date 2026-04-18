import base64
from key_management.hsm import SimulatedHSM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------
# SECURITY RATIONALE:
# The Signing Authority bonds the Merkle Root, the SBOM hash,
# and the version string together.
# If an attacker tries to swap the manifest from v1 to v2, 
# or swaps the SBOM, the Ed25519 signature will fail validation 
# on the ECU. This guarantees Non-Repudiation and Tamper-Evidence.
# ---------------------------------------------------------

class SigningAuthority:
    def __init__(self, hsm: SimulatedHSM):
        self.hsm = hsm

    def construct_payload(self, version: str, merkle_root: str, sbom_hash: str) -> bytes:
        """Creates the canonical string payload that is securely signed."""
        return f"{version}||{merkle_root}||{sbom_hash}".encode('utf-8')

    def generate_manifest_signature(self, version: str, merkle_root: str, sbom_hash: str) -> str:
        """Constructs the canonical payload and signs it using the secured HSM."""
        payload = self.construct_payload(version, merkle_root, sbom_hash)
        signature_bytes = self.hsm.sign(payload)
        return base64.b64encode(signature_bytes).decode('utf-8')

    @staticmethod
    def verify_manifest_signature(public_key_bytes: bytes, version: str, merkle_root: str, sbom_hash: str, signature_b64: str) -> bool:
        """Static method used by ECU to verify a manifest signature standalone."""
        payload = f"{version}||{merkle_root}||{sbom_hash}".encode('utf-8')
        signature = base64.b64decode(signature_b64)
        
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, payload)
            return True
        except InvalidSignature:
            return False
