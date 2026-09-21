"""Attack 1: a rogue OTA server (or MITM that fully replaces the response)
signs a malicious firmware payload with ITS OWN key and offers it to a
vehicle as if it were a real update. Because the vehicle only trusts the
ONE public key pinned at manufacture time, verification fails regardless
of how convincing the fake package otherwise looks.

Usage:
    python attack_simulator/rogue_key_attack.py
"""
import base64
import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fleet_sim.vehicle_client import VehicleClient
from ota_server import crypto

BASE_URL = "http://127.0.0.1:8100"
TARGET_VIN = "KMHL14JA1RA000001"


def main():
    public_key_pem = httpx.get(f"{BASE_URL}/admin/public-key").json()["public_key_pem"]
    vehicle = VehicleClient(TARGET_VIN, "Ioniq5", "US-West", BASE_URL, public_key_pem)
    vehicle.register()

    print(f"[attacker] generating our own signing keypair (we don't have the manufacturer's)...")
    attacker_private, _ = crypto.generate_keypair()

    malicious_payload = b"MALICIOUS_FIRMWARE_PAYLOAD" * 10
    malicious_signature = crypto.sign(attacker_private, malicious_payload)

    fake_offer = {
        "update_available": True,
        "version": "9.9.9",
        "sha256": crypto.sha256_hex(malicious_payload),
        "signature": malicious_signature,
        "firmware_b64": base64.b64encode(malicious_payload).decode(),
    }

    print(f"[attacker] offering fake v9.9.9 signed with OUR key to vehicle {TARGET_VIN}...")
    result = vehicle.check_and_apply_update(override_offer=fake_offer)
    print(f"[vehicle] result: {result}")
    if result == "rejected:invalid_signature":
        print("[attacker] FAILED: vehicle only trusts the manufacturer's pinned public key.")
    else:
        print("[attacker] uh oh, the attack succeeded -- this would be a critical bug.")


if __name__ == "__main__":
    main()
