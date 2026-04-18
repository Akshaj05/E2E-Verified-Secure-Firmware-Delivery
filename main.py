import argparse
import sys
import subprocess
import os
import requests
import base64
import time

# Ensure imports work dynamically
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.config import OTA_SERVER_PORT, OTA_SERVER_HOST, ATTACK_ENABLED, ATTACK_TARGET
from common.models import UpdateRequest
from build_pipeline.builder import build_firmware_release
from key_management.hsm import SimulatedHSM
from vehicle.gateway_ecu import GatewayECU
from attacker.mitm import MITMAttacker

# ---------------------------------------------------------
# SECURITY RATIONALE (ORCHESTRATOR):
# This main.py script serves as the isolated bootstrapping 
# boundary for either the Cloud (OTA Server) or the Cyber-Physical 
# system (Vehicle). 
# Note: HMAC Keys and Server Certificates would be strictly provisioned
# securely in the factory out-of-band in reality.
# ---------------------------------------------------------

# Global simulated factory secrets for demo
FACTORY_HMAC_SECRET = b"super_secret_hmac_key_for_all_ecu"
FACTORY_HSM = SimulatedHSM(seed=b"deterministic_demo_hsm_seed_for_multi_proc") 
PINNED_SERVER_PUB_CERT = FACTORY_HSM.get_public_key_bytes()

def run_server_node():
    print(f"[*] Starting OTA Server & Dashboard on {OTA_SERVER_HOST}...")
    env = os.environ.copy()
    
    # Actually run Uvicorn manually here or rely on the pipeline.
    # The requirement said to isolate components.
    ota_cmd = [sys.executable, "-m", "uvicorn", "server.ota_server:app", "--host", OTA_SERVER_HOST, "--port", str(OTA_SERVER_PORT)]
    dash_cmd = [sys.executable, "-m", "uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8001"]
    
    ota_p = subprocess.Popen(ota_cmd, env=env)
    dash_p = subprocess.Popen(dash_cmd, env=env)

    try:
        time.sleep(3)
        print("\n[+] Build Pipeline: Compiling and Signing Firmware...")
        firmware_data = b"\x01\x02\x03\x04\x05" * 100 
        manifest, chunks = build_firmware_release(firmware_data, "v2.0.0", FACTORY_HSM, FACTORY_HMAC_SECRET)
        print(f"    - Merkle Root (HMAC): {manifest.merkle_root}")
        print(f"    - Ed25519 Verify Key: {FACTORY_HSM.get_public_key_fingerprint()}")

        print("\n[+] Publishing Firmware to Distribution Server...")
        chunks_b64 = [base64.b64encode(c).decode("utf-8") for c in chunks]
        requests.post(f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}/upload", json={
            "manifest": manifest.model_dump(),
            "chunks_base64": chunks_b64
        })
        
        print("\n[!] Servers are live. Run vehicular node in another terminal via --vehicle.")
        print("[!] Press CTRL+C to terminate the Cloud Node.")
        ota_p.wait()
    except KeyboardInterrupt:
        ota_p.terminate()
        dash_p.terminate()


def run_vehicle_node():
    print(f"[*] Booting Vehicle Gateway ECU (Target URL: http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT})...")
    ecu = GatewayECU("VEH-1", f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}", PINNED_SERVER_PUB_CERT, FACTORY_HMAC_SECRET)

    if ATTACK_ENABLED:
        print("[!] ATTACKER MODULE ENABLED: Routing OTA through Kali MITM Pipeline")
        ecu.mitm_actor = MITMAttacker(target=ATTACK_TARGET)

    # Example 1: Battery constraints block installation
    print("\n[+] ECU executing OTA Request (Battery low)...")
    req_bad = UpdateRequest(device_id="VEH-1", current_version="v1.0.0", battery_level=55.0, engine_state="IDLE", gear_state="PARK")
    ecu.execute_ota_workflow("v2.0.0", req_bad)
    time.sleep(2)

    # Example 2: Normal safe state
    print("\n[+] ECU executing OTA Request (Safe to flash)...")
    req_ok = UpdateRequest(device_id="VEH-1", current_version="v1.0.0", battery_level=100.0, engine_state="IDLE", gear_state="PARK")
    ecu.execute_ota_workflow("v2.0.0", req_ok)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure OTA Demonstrator")
    parser.add_argument("--server", action="store_true", help="Launch the Cloud OTA and Dashboard pipelines")
    parser.add_argument("--vehicle", action="store_true", help="Launch a Vehicle ECU endpoint to download from Cloud")
    args = parser.parse_args()

    if args.server:
        run_server_node()
    elif args.vehicle:
        run_vehicle_node()
    else:
        print("Please specify --server or --vehicle. Examples in instructions.")
