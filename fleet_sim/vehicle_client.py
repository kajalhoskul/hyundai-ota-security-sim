"""Simulates a single vehicle's OTA client. Every defense in this file is a
real UNECE R156 (Software Update Management System) expectation:
  - verify integrity (SHA-256) and authenticity (signature) before install
  - reject any offered version that isn't strictly newer (anti-rollback)
  - be able to revert to the previous known-good version if an install
    turns out to be bad (this is the *legitimate* rollback path, distinct
    from an attacker forcing a downgrade)

The vehicle's public key is "pinned" once at construction time (modeling a
key burned in at manufacture) and never changes based on anything the
network tells it afterwards.
"""
import base64
import os
import random
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ota_server import crypto
from ota_server.versioning import is_newer


class VehicleClient:
    def __init__(self, vin: str, model: str, region: str, base_url: str, pinned_public_key_pem: str, initial_version="1.0.0"):
        self.vin = vin
        self.model = model
        self.region = region
        self.base_url = base_url
        self.current_version = initial_version
        self.public_key = crypto.load_public_key_from_pem_str(pinned_public_key_pem)
        self.client = httpx.Client(base_url=base_url, timeout=5.0)

    def register(self):
        # Idempotent server-side: if this VIN already exists, the response
        # reflects its REAL current version, so a freshly-started script
        # picks up wherever the fleet actually is instead of assuming
        # every vehicle is still on its factory baseline.
        resp = self.client.post("/admin/vehicles/register", json={
            "vin": self.vin, "model": self.model, "region": self.region,
            "current_version": self.current_version,
        }).json()
        self.current_version = resp["current_version"]

    def _report(self, version, status, reason=""):
        self.client.post("/ota/report", json={
            "vin": self.vin, "version": version, "status": status, "reason": reason,
        })

    def check_and_apply_update(self, override_offer=None, tamper_download=False, health_check_fail_rate=None):
        """Returns a short status string describing what happened.

        override_offer: used ONLY by the attack simulators to model a
        rogue/MITM channel handing the vehicle a malicious "update offer"
        instead of the real server's response.
        tamper_download: flips a byte in the downloaded firmware after
        fetching it from the (real, legitimate) server, modeling an
        in-transit tampering attack on an otherwise genuine update.
        """
        offer = override_offer or self.client.get("/ota/check-in", params={"vin": self.vin}).json()
        if not offer.get("update_available"):
            return "up_to_date"

        version = offer["version"]

        if not is_newer(version, self.current_version):
            self._report(version, "rejected", "downgrade_attempt")
            return "rejected:downgrade_attempt"

        if override_offer and "firmware_b64" in override_offer:
            firmware_bytes = base64.b64decode(override_offer["firmware_b64"])
        else:
            firmware_bytes = self.client.get(offer["download_url"]).content

        if tamper_download:
            firmware_bytes = bytearray(firmware_bytes)
            firmware_bytes[0] ^= 0xFF
            firmware_bytes = bytes(firmware_bytes)

        if crypto.sha256_hex(firmware_bytes) != offer["sha256"]:
            self._report(version, "rejected", "checksum_mismatch")
            return "rejected:checksum_mismatch"

        if not crypto.verify(self.public_key, firmware_bytes, offer["signature"]):
            self._report(version, "rejected", "invalid_signature")
            return "rejected:invalid_signature"

        # All checks passed -- install, then run a post-install health
        # check the way a real ECU would before committing to the new
        # version.
        previous_version = self.current_version
        self.current_version = version

        fail_rate = health_check_fail_rate if health_check_fail_rate is not None else 0.03
        if random.random() < fail_rate:
            self.current_version = previous_version
            self._report(previous_version, "rolled_back", "post_install_health_check_failed")
            return "rolled_back"

        self._report(version, "installed")
        return "installed"
