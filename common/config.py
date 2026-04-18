import os

# ---------------------------------------------------------
# SECURITY RATIONALE:
# Hardcoding secrets/URLs in source code is an anti-pattern.
# This config module consolidates all environment-driven 
# parameters, ensuring secrets can be injected securely via 
# orchestrated environment variables (e.g., K8s secrets) 
# and never checked into version control.
# ---------------------------------------------------------

OTA_SERVER_HOST = os.getenv("OTA_SERVER_HOST", "127.0.0.1")
OTA_SERVER_PORT = int(os.getenv("OTA_SERVER_PORT", "8000"))
OTA_SERVER_URL = f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}"

DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://127.0.0.1:8001")

# Default sizes
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "256"))

# Security modes
ATTACK_ENABLED = os.getenv("ATTACK_ENABLED", "false").lower() == "true"
ATTACK_TARGET = os.getenv("ATTACK_TARGET", "chunk") # can be 'chunk', 'manifest', 'replay'

# HSM config for pinning
FACTORY_PROVISIONED_PIN = os.getenv("FACTORY_PROVISIONED_PIN", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
