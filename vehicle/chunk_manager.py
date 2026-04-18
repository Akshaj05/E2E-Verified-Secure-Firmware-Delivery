import requests
import base64
import time
from common.logger import SecurityLogger
from merkle.tree import MerkleTreeBuilder
from typing import List

# ---------------------------------------------------------
# SECURITY RATIONALE:
# Chunk Management must be resilient to active denial of service 
# or randomized bit flips over the air. We categorize chunks into
# concrete states so we never install UNVERIFIED bytes.
# Selective retransmission prevents bandwidth exhaustion.
# ---------------------------------------------------------

class ChunkState:
    PENDING = "pending"
    DOWNLOADED = "downloaded"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"

class ChunkManager:
    def __init__(self, server_url: str, hmac_secret: bytes, logger: SecurityLogger):
        self.server = server_url
        self.secret = hmac_secret
        self.logger = logger
        
        # State tracking (allows resume if persisted to disk in real implementations)
        self.chunk_states = {}   # int -> str (ChunkState)
        self.chunk_data = {}     # int -> bytes
        self.retry_counts = {}   # int -> int
        
        self.MAX_RETRIES = 3

    def fetch_and_verify(self, total_chunks: int, leaf_hashes: List[str], mitm_actor=None) -> bool:
        self.logger.info("Initializing robust Chunk Management Zone.", event_type="chunk_download_started")
        tree = MerkleTreeBuilder(self.secret)
        
        # Initialise state for all chunks if not resuming
        for i in range(total_chunks):
            if i not in self.chunk_states or self.chunk_states[i] != ChunkState.VERIFIED:
                self.chunk_states[i] = ChunkState.PENDING
                self.retry_counts[i] = 0

        pending_chunks = [i for i, state in self.chunk_states.items() if state != ChunkState.VERIFIED]

        while pending_chunks:
            for i in pending_chunks:
                if self.retry_counts[i] >= self.MAX_RETRIES:
                    self.logger.critical(f"Chunk {i} exceeded max retries. Aborting update.", event_type="chunk_retry_exceeded")
                    return False

                # Backoff logic
                if self.retry_counts[i] > 0:
                    backoff = 2 ** (self.retry_counts[i] - 1)
                    self.logger.info(f"Applying backoff of {backoff}s before retry for chunk {i}")
                    time.sleep(backoff)

                is_retry = self.retry_counts[i] > 0
                if is_retry:
                    self.logger.warning(f"Requesting targeted retransmission for chunk {i}", event_type="chunk_retransmission_requested")

                try:
                    res = requests.get(f"{self.server}/chunk/{i}")
                    if res.status_code != 200:
                        raise Exception(f"Server returned {res.status_code}")
                        
                    data = base64.b64decode(res.json())
                    self.chunk_states[i] = ChunkState.DOWNLOADED
                    if is_retry:
                        self.logger.info(f"Retransmission success for chunk {i}", event_type="chunk_retransmission_success")
                    else:
                        self.logger.info(f"Downloaded chunk {i}", event_type="chunk_downloaded")

                except Exception as e:
                    self.logger.error(f"Network error on chunk {i}: {e}")
                    self.retry_counts[i] += 1
                    continue

                # Attacker corruption layer
                if mitm_actor:
                    data = mitm_actor.intercept_chunk(i, data, retry_count=self.retry_counts[i])

                # HMAC Validation
                if not tree.verify_chunk(data, leaf_hashes[i]):
                    self.logger.error(f"Integrity failure on chunk {i}", event_type="chunk_corrupted")
                    self.chunk_states[i] = ChunkState.CORRUPTED
                    self.retry_counts[i] += 1
                    continue

                # Success
                self.chunk_states[i] = ChunkState.VERIFIED
                self.chunk_data[i] = data
                self.logger.info(f"Chunk {i} verified securely.", event_type="chunk_verified")

            # Update pending status for the next sweep
            pending_chunks = [i for i, state in self.chunk_states.items() if state != ChunkState.VERIFIED]

        return True
    
    def assemble_binary(self, total_chunks: int) -> bytes:
        """Assembles only fully verified chunks from the state store."""
        return b"".join(self.chunk_data[i] for i in range(total_chunks))
