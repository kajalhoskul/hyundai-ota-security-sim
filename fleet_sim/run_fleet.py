"""Registers a simulated fleet (idempotent) and has every vehicle poll the
OTA server once, applying any available update.

Usage:
    python fleet_sim/run_fleet.py                      # normal poll, low failure rate
    python fleet_sim/run_fleet.py --fail-rate 0.4       # simulate a bad build's real-world impact
"""
import argparse
import os
import sys

import httpx

sys.path.insert(0, os.path.dirname(__file__))
from vehicle_client import VehicleClient

FLEET = [
    ("KMHL14JA1RA000001", "Ioniq5", "US-West"),
    ("KMHL14JA1RA000002", "Ioniq5", "US-West"),
    ("KMHL14JA1RA000003", "Ioniq5", "US-West"),
    ("KMHL14JA1RA000004", "Ioniq5", "US-West"),
    ("KMHL14JA1RA000005", "Ioniq5", "US-East"),
    ("KMHL14JA1RA000006", "Ioniq5", "US-East"),
    ("KMHL14JA1RA000007", "Ioniq5", "US-East"),
    ("KMHL14JA1RA000008", "Ioniq5", "EU-DE"),
    ("KMHL14JA1RA000009", "Ioniq5", "EU-DE"),
    ("KMHL14JA1RA000010", "Ioniq5", "EU-FR"),
    ("KMHL14JA1RA000011", "Tucson", "US-West"),
    ("KMHL14JA1RA000012", "Tucson", "US-East"),
    ("KMHL14JA1RA000013", "Tucson", "EU-DE"),
    ("KMHL14JA1RA000014", "Ioniq5", "US-West"),
    ("KMHL14JA1RA000015", "Ioniq5", "US-East"),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8100")
    parser.add_argument("--fail-rate", type=float, default=0.03)
    args = parser.parse_args()

    public_key_pem = httpx.get(f"{args.base_url}/admin/public-key").json()["public_key_pem"]

    for vin, model, region in FLEET:
        vehicle = VehicleClient(vin, model, region, args.base_url, public_key_pem)
        vehicle.register()
        result = vehicle.check_and_apply_update(health_check_fail_rate=args.fail_rate)
        print(f"  [{vin}] {model}/{region} -> {result} (now on {vehicle.current_version})")

    print("Fleet poll complete.")


if __name__ == "__main__":
    main()
