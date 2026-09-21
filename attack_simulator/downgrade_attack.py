"""Attack 3: a forced-downgrade attack. The attacker replays an OLD
firmware version that is GENUINELY, correctly signed by the manufacturer
(perhaps pulled from a public mirror or a vehicle that hasn't updated
yet) to try to roll a vehicle back onto a known-vulnerable build. Every
cryptographic check passes -- this is real, authentic manufacturer-signed
code. The only thing wrong with it is that it's old, so the defense has to
be a monotonic-version check, not just signature verification.

Requires two published versions the target has already moved past the
first of, e.g.:
    python scripts/publish_firmware.py --version 1.0.0 --model Ioniq5 --regions US-West
    python fleet_sim/run_fleet.py                 # vehicle installs 1.0.0
    python scripts/publish_firmware.py --version 2.0.0 --model Ioniq5 --regions US-West
    python fleet_sim/run_fleet.py                 # vehicle installs 2.0.0

Usage:
    python attack_simulator/downgrade_attack.py --old-version 1.0.0
"""
import argparse
import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fleet_sim.vehicle_client import VehicleClient

BASE_URL = "http://127.0.0.1:8100"
TARGET_VIN = "KMHL14JA1RA000003"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-version", default="1.0.0")
    args = parser.parse_args()

    public_key_pem = httpx.get(f"{BASE_URL}/admin/public-key").json()["public_key_pem"]
    vehicle = VehicleClient(TARGET_VIN, "Ioniq5", "US-West", BASE_URL, public_key_pem)
    vehicle.register()

    print(f"[attacker] fetching the GENUINE signed metadata for old version {args.old_version}...")
    meta = httpx.get(f"{BASE_URL}/ota/firmware-meta/{args.old_version}").json()
    if "version" not in meta:
        print(f"[attacker] version {args.old_version} was never published -- publish it first.")
        return

    forced_offer = {
        "update_available": True,
        "version": meta["version"],
        "sha256": meta["sha256"],
        "signature": meta["signature"],
        "download_url": f"/ota/firmware/{meta['version']}",
    }

    print(f"[attacker] replaying authentic v{args.old_version} to {TARGET_VIN} "
          f"(currently on v{vehicle.current_version})...")
    result = vehicle.check_and_apply_update(override_offer=forced_offer)
    print(f"[vehicle] result: {result}")
    if result == "rejected:downgrade_attempt":
        print("[attacker] FAILED: a valid signature was not enough -- the version was not newer.")
    else:
        print("[attacker] uh oh, the downgrade succeeded -- this would be a critical bug.")


if __name__ == "__main__":
    main()
