from __future__ import annotations
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

class KeyPair:
    def __init__(self, private: Ed25519PrivateKey):
        self.private = private
        self.public = private.public_key()

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @property
    def private_key_b64(self) -> str:
        return b64(self.private.private_bytes_raw())

    @property
    def public_key_b64(self) -> str:
        return b64(self.public.public_bytes_raw())

    @classmethod
    def from_private_b64(cls, value: str) -> "KeyPair":
        return cls(Ed25519PrivateKey.from_private_bytes(unb64(value)))

    @staticmethod
    def verify_signature(public_key_b64: str, message: bytes, signature_b64: str) -> None:
        Ed25519PublicKey.from_public_bytes(unb64(public_key_b64)).verify(unb64(signature_b64), message)

    @staticmethod
    def validate_public(public_key_b64: str) -> None:
        """Raise if the value is not a well-formed Ed25519 public key."""
        try:
            Ed25519PublicKey.from_public_bytes(unb64(public_key_b64))
        except Exception:
            raise ValueError("invalid_public_key") from None
