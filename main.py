import argparse
import sys
import subprocess
import os
import requests
import base64
import time

# Ensure imports work dynamically
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.config import OTA_SERVER_PORT, OTA_SERVER_HOST, DASHBOARD_HOST, DASHBOARD_PORT, ATTACK_ENABLED, ATTACK_TARGET
from common.models import UpdateRequest
from build_pipeline.builder import build_firmware_release
from key_management.hsm import SimulatedHSM
from vehicle.gateway_ecu import GatewayECU
from attacker.mitm import MITMAttacker

# main.py is the Orchestrator entry point for OTA server or vehicle runtime.
# In production, HMAC Keys and Server Certificates are securely provisioned out-of-band.

# Global simulated factory secrets for demo
FACTORY_HMAC_SECRET = b"super_secret_hmac_key_for_all_ecu"
FACTORY_HSM = SimulatedHSM(seed=b"deterministic_hsm_seed_for_multi_proc") 
PINNED_SERVER_PUB_CERT = FACTORY_HSM.get_public_key_bytes()

def run_server_node():
    print(f"[*] Starting OTA Server & Dashboard on {OTA_SERVER_HOST}...")
    env = os.environ.copy()
    
    # Kill any zombie processes holding ports from previous runs (Windows Errno 10048 fix)
    for port in [OTA_SERVER_PORT, DASHBOARD_PORT]:
        try:
            subprocess.run(
                ["powershell", "-Command", 
                 f"(Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue).OwningProcess | ForEach-Object {{ Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }}"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
    time.sleep(1)
    
    #run via uvicorn or pipeline
    #we do this to ensure the server and dashboard run in the same environment with the same secrets but in separate processes for isolation
    ota_cmd = [sys.executable, "-m", "uvicorn", "server.ota_server:app", "--host", OTA_SERVER_HOST, "--port", str(OTA_SERVER_PORT), "--loop", "asyncio"]
    dash_cmd = [sys.executable, "-m", "uvicorn", "dashboard.app:app", "--host", DASHBOARD_HOST, "--port", str(DASHBOARD_PORT), "--loop", "asyncio"]
    
    ota_p = subprocess.Popen(ota_cmd, env=env)
    dash_p = subprocess.Popen(dash_cmd, env=env)

    try:
        time.sleep(3)
        print("\n[+] Build Pipeline: Compiling and Signing Firmware...")
        
        # Scenario 3: 10-chunk firmware OTA requirement
        # 128 bytes per chunk * 10 chunks = 1280 bytes
        firmware_data = b"\xef\xbe\xad\xde" * 320 
        
        manifest, chunks = build_firmware_release(firmware_data, "v2.0.0", FACTORY_HSM, FACTORY_HMAC_SECRET)
        print(f"    - Merkle Root (HMAC): {manifest.merkle_root}")
        print(f"    - Ed25519 Verify Key: {FACTORY_HSM.get_public_key_fingerprint()}")

        print("\n[+] Publishing Firmware to Distribution Server...")
        #chunks_b64 is responsible for encoding binary chunks into base64 strings so that they can be safely transmitted in JSON format over HTTP
        #we convert the binary data into a text representation that can be included in the JSON payload sent to the OTA server.
        chunks_b64 = [base64.b64encode(c).decode("utf-8") for c in chunks]
        requests.post(f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}/upload", json={
            "manifest": manifest.model_dump(),
            "chunks_base64": chunks_b64
        })
        
        print("\n[!] Servers are live. Run vehicular node in another terminal via --vehicle.")
        ota_p.wait()
    except KeyboardInterrupt:
        ota_p.terminate()
        dash_p.terminate()


def run_vehicle_node():
    print(f"[*] Booting Vehicle Gateway ECU (Target URL: http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT})...")
    FORCE_INTERRUPT_AT = int(os.environ.get("FORCE_INTERRUPT_AT", "-1"))
    ROGUE_HSM = os.environ.get("ROGUE_HSM", "false").lower() == "true"
    FORCE_CVE = os.environ.get("FORCE_CVE", "false").lower() == "true"
    
    pinned_key = PINNED_SERVER_PUB_CERT
    if ROGUE_HSM:
        pinned_key = SimulatedHSM().get_public_key_bytes() # Random rogue key
        
    ecu = GatewayECU("VEH-1", f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}", pinned_key, FACTORY_HMAC_SECRET)

    if ATTACK_ENABLED:
        print("[!] ATTACKER MODULE ENABLED: Routing OTA through Kali MITM Pipeline")
        ecu.mitm_actor = MITMAttacker(target=ATTACK_TARGET)
        ecu.mitm_actor.abate_on_retry = os.environ.get("ABATE_ON_RETRY", "true").lower() == "true"

    if FORCE_CVE:
        # We simulate the server providing an SBOM flagged config
        # The ECU checks the payload dynamically, but for mock purposes we pass it to ECU state here
        # Actually our SBOM generator uses an env var or we can pass it
        os.environ["FORCE_CVE"] = "true" 

    #Battery constraints block installation
    if os.environ.get("SKIP_BAD_BATTERY", "false").lower() != "true":
        print("\n[+] ECU executing OTA Request (Battery low)...")
        req_bad = UpdateRequest(device_id="VEH-1", current_version="v1.0.0", battery_level=45.0, engine_state="IDLE", gear_state="PARK")
        ecu.execute_ota_workflow("v2.0.0", req_bad)
        time.sleep(2)

    #Normal safe state
    if not ROGUE_HSM and not FORCE_CVE and FORCE_INTERRUPT_AT == -1:
        print("\n[+] ECU executing OTA Request (Safe to flash)...")
    req_ok = UpdateRequest(device_id="VEH-1", current_version="v1.0.0", battery_level=100.0, engine_state="IDLE", gear_state="PARK")
    ecu.execute_ota_workflow("v2.0.0", req_ok, force_interrupt_at=FORCE_INTERRUPT_AT)
    
    # Allow background log forwarding daemon threads to flush
    time.sleep(1)


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
