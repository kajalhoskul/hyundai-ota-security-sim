"""Ed25519 signing/verification for firmware packages, plus SHA-256 integrity
hashing. This models the cryptographic core of a UNECE R156 Software Update
Management System: every firmware package must be signed by the
manufacturer before distribution, and every vehicle verifies that signature
against a public key pinned at manufacture time before installing anything.
"""
import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair():
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign(private_key: Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(private_key.sign(data)).decode()


def verify(public_key: Ed25519PublicKey, data: bytes, signature_b64: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def save_private_key(private_key: Ed25519PrivateKey, path: str):
    with open(path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def save_public_key(public_key: Ed25519PublicKey, path: str):
    with open(path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_public_key_from_pem_str(pem_str: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem_str.encode())
