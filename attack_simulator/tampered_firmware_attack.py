"""Attack 2: a MITM on the download channel tampers with an otherwise
LEGITIMATE, correctly-signed firmware package in transit (flips one byte).
The signature was computed over the original bytes, so any tampering --
even a single bit -- makes verification fail. This is why integrity must
be checked cryptographically, not just via a plain checksum an attacker
could also recompute and replace.

Requires a real published campaign the target vehicle can see, e.g.:
    python scripts/publish_firmware.py --version 2.0.0 --model Ioniq5 --regions US-West

Usage:
    python attack_simulator/tampered_firmware_attack.py
"""
import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fleet_sim.vehicle_client import VehicleClient

BASE_URL = "http://127.0.0.1:8100"
TARGET_VIN = "KMHL14JA1RA000002"


def main():
    public_key_pem = httpx.get(f"{BASE_URL}/admin/public-key").json()["public_key_pem"]
    vehicle = VehicleClient(TARGET_VIN, "Ioniq5", "US-West", BASE_URL, public_key_pem)
    vehicle.register()

    print(f"[attacker] intercepting {TARGET_VIN}'s download and flipping one byte of an "
          f"otherwise legitimate, correctly-signed package...")
    result = vehicle.check_and_apply_update(tamper_download=True)
    print(f"[vehicle] result: {result}")
    if result.startswith("rejected"):
        print("[attacker] FAILED: signature verification catches any tampering, however small.")
    elif result == "up_to_date":
        print("[attacker] no campaign is currently targeting this vehicle -- publish one first "
              "(see this script's docstring).")
    else:
        print("[attacker] uh oh, tampered firmware was accepted -- this would be a critical bug.")


if __name__ == "__main__":
    main()
