from __future__ import annotations
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .model import canonical


class Signer:
    algorithm = "ed25519"

    def __init__(self, key: bytes, key_id: str = "local-v1"):
        if len(key) != 32:
            raise ValueError("Ed25519 private seed must be exactly 32 bytes")
        self._key = Ed25519PrivateKey.from_private_bytes(key)
        self.key_id = key_id

    @property
    def public_key(self) -> str:
        return b64encode(
            self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

    def sign_bytes(self, value: bytes) -> bytes:
        return self._key.sign(value)

    def sign(self, value: dict) -> str:
        return b64encode(self.sign_bytes(canonical(value))).decode()

    def verify(self, value: dict, signature: str) -> bool:
        try:
            self._key.public_key().verify(
                __import__("base64").b64decode(signature, validate=True),
                canonical(value),
            )
            return True
        except (ValueError, TypeError):
            return False
