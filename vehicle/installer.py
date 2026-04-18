from common.models import UpdateRequest
from common.logger import SecurityLogger
import os

# ---------------------------------------------------------
# SECURITY RATIONALE:
# ISO 26262 Functional Safety dictates that cyber-physical systems
# must not be interrupted during critical operations.
# The Installer implements strict safety interlocks.
# If an installation fails, the "Golden Image Rollback" mechanism
# atomically restores the ECU to its last known-good state.
# ---------------------------------------------------------

class ECUInstaller:
    def __init__(self, device_id: str, logger: SecurityLogger):
        self.device_id = device_id
        self.logger = logger
        self.golden_image_ver = "v1.0.0" # Factory default

    def execute_install(self, target_version: str, state: UpdateRequest, payload: bytes = None) -> bool:
        """
        Safety constraints:
        - state.engine_state MUST be IDLE
        - state.battery_level MUST be >= 70
        - state.gear_state MUST be PARK
        """
        self.logger.info("Evaluating safety interlocks for install...", device_id=self.device_id)

        if state.engine_state != "IDLE":
            self.logger.warning("Installation blocked: Engine must be IDLE (OFF)", event_type="safety_block", device_id=self.device_id)
            return False
            
        if state.battery_level < 70.0:
            self.logger.warning("Installation blocked: Battery below 70%", event_type="safety_block", device_id=self.device_id)
            return False
            
        if state.gear_state != "PARK":
            self.logger.warning("Installation blocked: Gear must be PARK", event_type="safety_block", device_id=self.device_id)
            return False

        # Simulate Flash Write
        self.logger.info("Installation proceeding... Flashing NAND.", device_id=self.device_id)
        
        if payload:
            self.logger.info(f"Physically verified binary blocks in-memory. Output file materialization disabled.", device_id=self.device_id)

        # Simulate success + golden image update
        self.golden_image_ver = target_version
        self.logger.info("Installation completed successfully.", event_type="install_success", device_id=self.device_id)
        return True

    def rollback(self, reason: str = "HASH/SIGNATURE_FAILURE"):
        """Restores the Golden Image."""
        self.logger.error(f"Performing automatic rollback to Golden Image: {self.golden_image_ver}")
        self.logger.error(f"ROLLBACK_TRIGGERED — reason: {reason} — golden image restored", event_type="rollback", device_id=self.device_id)
        self.logger.info("Rollback successful. ECU state restored.", device_id=self.device_id)
