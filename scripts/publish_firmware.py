"""Legitimate manufacturer publish flow: build a firmware payload, and have
the server sign + start a campaign for it. This models the ONLY correct way
a new version should ever reach vehicles.

Usage:
    python scripts/publish_firmware.py --version 2.0.0 --model Ioniq5 --regions US-West,US-East
    python scripts/publish_firmware.py --version 2.1.0 --model Ioniq5 --regions US-West,US-East --buggy
"""
import argparse
import base64
import hashlib

import httpx


def fake_firmware_payload(version: str) -> bytes:
    # Deterministic per-version "binary" so re-running produces the same
    # bytes; a real payload would be an actual signed ECU image.
    seed = hashlib.sha256(version.encode()).digest()
    return seed * 64  # 2KB


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8100")
    parser.add_argument("--version", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--regions", default="")
    parser.add_argument("--buggy", action="store_true")
    args = parser.parse_args()

    payload = fake_firmware_payload(args.version)
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    r = httpx.post(f"{args.base_url}/admin/publish", json={
        "version": args.version,
        "model": args.model,
        "regions": regions,
        "is_buggy": args.buggy,
        "firmware_b64": base64.b64encode(payload).decode(),
    })
    print(f"Published {args.version} for {args.model} {regions or '(all regions)'}: {r.json()}")


if __name__ == "__main__":
    main()
