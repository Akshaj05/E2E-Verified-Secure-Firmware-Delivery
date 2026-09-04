# Secure Distributed OTA Update System

A secure and distributed Over-The-Air (OTA) firmware update system for automotive ECUs, built on an **HSM-based, two-role Trust-Anchor architecture** (a simplified Uptane-style Director/Image key split). It demonstrates real-world cybersecurity scenarios including MITM attacks, supply chain validation, cryptographic verification, rollback/freeze-attack protection, and safe-state rollback mechanisms.

Built with Python, FastAPI, and a real-time fleet management dashboard.

#### This project will run locally always, to reduce possible vulnerabilities, and even in a practical scenario, the project will never be deployed openly. This was made as a Hackathon project for the MAHE mobility challenge hosted by MITM, MAHE, Bangalore. Winning 2nd place in the Cybersescurity track.

> **`security-hardening` branch note:** this branch is a security-audit-driven evolution of the submitted hackathon build (kept intact on `main`). See `AUDIT_FINDINGS.md` for the full audit and the phased plan this branch implements — several bugs found during that audit (a dashboard RCE/XSS, an unenforced merkle root, missing rollback protection, a MITM flag that was silently ignored) are fixed here, and the Director/Image signing split below is new.
---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Running the Dashboard](#running-the-dashboard)
  - [Running Demos via CLI](#running-demos-via-cli)
- [Demo Scenarios](#demo-scenarios)
- [Security Design](#security-design)
- [Tech Stack](#tech-stack)

---

## Features

- **Director/Image Two-Role Signing** — a stolen or compromised OTA server (Director) key alone cannot authorize new firmware content; that requires the separately-held, offline Image key too
- **Ed25519 Signing, Two Independent Keys** — HSM-backed signatures for both the Director's per-device install instructions and the Image role's firmware content
- **HMAC-SHA256 Leaf Digests, Bound to the Signed Root** — per-chunk integrity verification prevents hash substitution attacks; the ECU recomputes and checks the root against what was actually signed, not just what a server hands it
- **Rollback / Freeze-Attack Protection** — a monotonic build counter, checked against installed history, rejects a replayed old-but-validly-signed manifest
- **SBOM Auditing** — real-time dependency scanning against a CVE database blocks vulnerable firmware
- **Selective Retransmission** — corrupted chunks are individually re-fetched with exponential backoff
- **Secure Resume** — interrupted downloads persist verified chunk state to disk and resume seamlessly
- **Golden Image Rollback** — failed installations atomically revert to the last known-good firmware
- **MITM Attack Simulation** — transparent proxy simulates bitflip, truncation, payload replacement, manifest replay, and compromised-Director attacks
- **Real-Time Dashboard** — fleet management UI with live telemetry, chunk validation grid, and security alerts

---

## Architecture

![Architecture Diagram](images/Architecture_Diagram.png)

---

## Project Structure

```
MAHE-Mobility-Final-Project/
│
├── main.py                      # Orchestrator — boots server or vehicle node
├── requirements.txt             # Python dependencies
├── readme.md                    # This file
│
├── common/                      # Shared infrastructure
│   ├── config.py                # Environment-driven configuration (ports, flags)
│   ├── logger.py                # Structured JSON logger with async dashboard forwarding
│   ├── models.py                # Pydantic models (Manifest, DirectorInstruction, UpdateRequest, SecurityEvent)
│   └── proc.py                  # Process-tree spawn/cleanup helpers (Windows-safe)
│
├── key_management/              # Cryptographic key store
│   └── hsm.py                   # Simulated Hardware Security Module (Ed25519)
│
├── signing/                     # Image + Director signature authorities
│   └── authority.py             # Signs/verifies both roles; compute_image_digest()
│
├── merkle/                      # Firmware integrity engine
│   └── tree.py                  # HMAC-SHA256 ordered leaf digest (build, verify, reconstruct)
│
├── sbom/                        # Software Bill of Materials
│   ├── generator.py             # Generates SBOM; injects vulnerable deps when FORCE_CVE=true
│   └── cve_database.json        # Local CVE threat feed for dependency scanning
│
├── build_pipeline/              # Offline build pipeline (holds the Image key)
│   └── builder.py               # SBOM → leaf digests → Image-key signing → Manifest assembly
│
├── server/                      # Cloud OTA distribution (plays the Director role)
│   └── ota_server.py            # FastAPI server (upload, manifest+director instruction, chunk endpoints)
│
├── vehicle/                     # ECU cyber-physical system
│   ├── gateway_ecu.py           # Main OTA workflow (Director+Image verify → rollback check → SBOM → chunks → install)
│   ├── chunk_manager.py         # Chunk download with retry, resume, and HMAC verification
│   └── installer.py             # Safety interlocks, persisted install-build history, golden image rollback
│
├── attacker/                    # MITM attack simulation
│   └── mitm.py                  # Bitflip/truncation/replace, manifest replay, compromised-Director forgery
│
├── dashboard/                   # Fleet management UI
│   ├── app.py                   # FastAPI backend (log ingestion, metrics, allowlisted demo runner)
│   └── index.html               # Single-page dashboard with real-time telemetry
│
├── scripts/                     # Pre-configured demo scenarios
│   ├── demo_1_normal.py         # Successful OTA update
│   ├── demo_2_tampered.py       # Persistent payload tampering attack
│   ├── demo_3_retransmit.py     # Chunk corruption with selective retransmission
│   ├── demo_4_resume.py         # Network interruption with secure resume
│   ├── demo_5_rogue_hsm.py      # Rogue/untrusted Image key — signature verification failure
│   ├── demo_6_sbom_cve.py       # SBOM CVE detection and force-patch
│   ├── demo_7_rollback.py       # Rollback/freeze attack — old-but-validly-signed manifest replay
│   └── demo_8_compromised_director.py  # Stolen Director key alone is not enough
│
└── audit/                       # Persistent audit trail
    └── audit_log.json           # Auto-generated structured audit log (gitignored)
```

---

## Prerequisites

- **Python** 3.9+
- **pip** (Python package manager)
- **Git**

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Akshaj05/MAHE-Mobility-Final-Project.git
cd MAHE-Mobility-Final-Project
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate    # macOS/Linux
# venv\Scripts\activate     # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```
#### note: you can do -g as well, or if you have them installed, this step can be skipped
---

## Usage

### Running the Dashboard

The recommended way to run demos is through the **web dashboard**, which provides real-time visualization of all security events.

**Step 1:** Start the server node:

```bash
python main.py --server
```

This boots:
- **OTA Server** on `http://127.0.0.1:7000` — serves firmware manifests and chunks
- **Dashboard** on `http://127.0.0.1:7001` — fleet management UI

**Step 2:** Open `http://127.0.0.1:7001` in your browser.

**Step 3:** Select a demo scenario from the modal dialog and click **Run**.

The dashboard will display:
- **Metric Cards** — Updates, retransmissions, successes, corruptions, aborts
- **Payload Validation Grid** — 10-chunk visual state tracker (green/yellow/red/purple)
- **SBOM Alert Panel** — CVE detection and force-patch progression (Demo 6 only)
- **Telemetry Terminal** — Real-time structured log stream with color-coded severity

### Running Demos via CLI

Each demo can also be run standalone without the dashboard:

```bash
# Normal OTA update
python scripts/demo_1_normal.py

# Payload tampering attack
python scripts/demo_2_tampered.py

# Chunk corruption + retransmission
python scripts/demo_3_retransmit.py

# Network interruption + resume
python scripts/demo_4_resume.py

# Rogue HSM signature injection
python scripts/demo_5_rogue_hsm.py

# SBOM CVE detection + force-patch
python scripts/demo_6_sbom_cve.py

# Rollback / freeze attack (old-but-validly-signed manifest replay)
python scripts/demo_7_rollback.py

# Compromised Director role (stolen fleet-server key alone isn't enough)
python scripts/demo_8_compromised_director.py
```

Or manually with separate terminals:

```bash
# Terminal 1: Start server
python main.py --server

# Terminal 2: Run vehicle
python main.py --vehicle
```

---

## Demo Scenarios

### Demo 1 — Normal OTA Update
A clean firmware update with all 10 chunks downloaded, HMAC-verified, and installed successfully. No attacks, no failures.

### Demo 2 — Payload Tampering Attack
A persistent MITM attacker corrupts chunk 0 via bitflip on every attempt. The chunk manager detects the HMAC mismatch, exhausts retries, and aborts the update.

### Demo 3 — Chunk Loss & Retransmission
The MITM attacker corrupts chunk 4 on the first attempt but abates on retry. The chunk manager detects corruption, requests retransmission, and successfully completes the update.

### Demo 4 — Interrupted OTA with Secure Resume
The network drops at chunk 6. Verified chunk states are persisted to disk. On reconnection, the ECU resumes from chunk 6 without re-downloading chunks 0–5.

### Demo 5 — Rogue HSM Injection
The vehicle ECU boots pinned to a randomly generated Image key that doesn't match the real build pipeline's key. The Director instruction verifies fine (that key wasn't touched), but Image signature verification fails, and the update is rejected — the whole trust chain the ECU was provisioned with is wrong, not just one role.

### Demo 6 — SBOM CVE Detection
The CI/CD pipeline is compromised and injects a vulnerable version of `libcurl` (7.88.1, matching CVE-2023-38545). The ECU detects the version mismatch, logs the CVE, forcefully patches the version, and continues the update.

### Demo 7 — Rollback / Freeze Attack
The vehicle first installs the current release (v2.0.0) legitimately. An attacker then replays an OLD manifest+director bundle (v1.0.0) that is still **validly signed** by both roles — no key compromise involved, just replay of an authentic artifact the vehicle has already moved past. Both signature checks pass; the ECU rejects it anyway, using its own persisted installed-build history to detect the downgrade. Distinct from Demo 5 (wrong keys) and Demo 8 (right Director key, wrong Image key).

### Demo 8 — Compromised Director
An attacker has stolen the **online** Director key (the OTA server's own signing key) but not the **offline** Image key held only by the build pipeline. They issue a validly-signed Director instruction pointing at firmware they fabricated. The Director check passes — but the ECU independently verifies the Image signature too, which fails, proving that compromising the network-facing role alone is not enough to install arbitrary code. This is the actual payoff of splitting signing authority across two roles instead of one.

---

## Security Design

| Layer | Mechanism | Threat Mitigated |
|-------|-----------|-----------------|
| **Authorization** | Director-role Ed25519 signature, per device_id | Misdirected or forged fleet instructions |
| **Content Provenance** | Image-role Ed25519 signature, independent key | A compromised Director alone pushing arbitrary firmware (Demo 8) |
| **Binding** | Director.image_digest == hash(Image metadata) | Valid Director signature paired with mismatched image content |
| **Freshness** | Monotonic build_number vs. persisted install history | Rollback/freeze attacks — replaying an old, validly-signed manifest (Demo 7) |
| **Integrity** | HMAC-SHA256 leaf digests, reconstructed root checked against the signed root | Bitflip attacks, payload substitution, and a leaf-hash list that doesn't match what was actually signed |
| **Supply Chain** | SBOM dependency audit against CVE database | Vulnerable third-party components |
| **Resilience** | Selective retransmission with exponential backoff | Network corruption, packet loss |
| **Continuity** | Disk-persisted chunk state for resume | Network interruption, power loss |
| **Safety** | Battery / engine-state / gear-state interlocks | Mid-flash power failure, flashing while driving |
| **Recovery** | Golden image rollback | Any unrecoverable failure |

Transport-layer encryption (TLS) is **not implemented** — the "ECDH session established" log line is illustrative only and does not correspond to a real handshake in this codebase. Everything above is enforced at the application layer regardless of transport; adding real TLS would be a reasonable next step but isn't required for any of the properties this table claims.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.9+, FastAPI, Uvicorn |
| Cryptography | Ed25519 (Director + Image signing, two independent keys), HMAC-SHA256 (chunk/leaf integrity), SHA-256 (image_digest binding) |
| Data Models | Pydantic v2 |
| HTTP Client | Requests, HTTPX |
| Frontend | Vanilla HTML/CSS/JS |
| Logging | Structured JSON with async HTTP forwarding |

---

## License

This project was developed as part of the MAHE Mobility Hackathon Final Project.
