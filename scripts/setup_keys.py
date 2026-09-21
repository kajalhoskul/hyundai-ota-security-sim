"""Generates the manufacturer's Ed25519 signing keypair.

Run once before starting the server:
    python scripts/setup_keys.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ota_server import crypto

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")


def main():
    os.makedirs(KEYS_DIR, exist_ok=True)
    private_path = os.path.join(KEYS_DIR, "manufacturer_private.pem")
    public_path = os.path.join(KEYS_DIR, "manufacturer_public.pem")

    if os.path.exists(private_path):
        print(f"Keypair already exists at {KEYS_DIR}, leaving it in place.")
        return

    private_key, public_key = crypto.generate_keypair()
    crypto.save_private_key(private_key, private_path)
    crypto.save_public_key(public_key, public_path)
    print(f"Generated manufacturer keypair:\n  private: {private_path} (keep secret, gitignored)\n  public:  {public_path} (pinned into every vehicle)")


if __name__ == "__main__":
    main()
