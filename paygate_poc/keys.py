"""Ed25519 signing helpers.

The deterministic demo keys are for repeatable PoC runs only. Production
integrations MUST use managed KMS/HSM-backed keys and key rotation.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from .canonical import canonical_bytes


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


def _preimage(context: str, obj: Any) -> bytes:
    if not context or "\x00" in context:
        raise ValueError("context must be a non-empty label without NUL")
    return context.encode("utf-8") + b"\x00" + canonical_bytes(obj)


@dataclass(frozen=True)
class KeyPair:
    kid: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_key_b64u(self) -> str:
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return b64u(raw)

    def private_key_b64u(self) -> str:
        raw = self.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return b64u(raw)

    def public_jwkish(self) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519", "kid": self.kid, "x": self.public_key_b64u()}

    def sign(self, context: str, obj: Any) -> dict[str, str]:
        sig = self.private_key.sign(_preimage(context, obj))
        return {"alg": "Ed25519", "kid": self.kid, "context": context, "value": b64u(sig)}


def deterministic_demo_key(label: str) -> KeyPair:
    seed = hashlib.sha256(("PAYGATE-REF-DEMO-KEY:" + label).encode("utf-8")).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    kid = "kid:demo:" + hashlib.sha256(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()[:16]
    return KeyPair(kid=kid, private_key=private)


def public_key_from_b64u(raw: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64u_decode(raw))


def verify_signature(public_key: Ed25519PublicKey, context: str, obj: Any, signature: dict[str, str]) -> bool:
    if not isinstance(signature, dict):
        return False
    if signature.get("alg") != "Ed25519":
        return False
    if signature.get("context") != context:
        return False
    try:
        public_key.verify(b64u_decode(signature["value"]), _preimage(context, obj))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False
