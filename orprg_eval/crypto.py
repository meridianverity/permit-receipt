"""Synthetic Ed25519 signing helpers. Deterministic keys are for test vectors only."""
from __future__ import annotations
import base64
import hashlib
from collections import OrderedDict
from typing import Any, Dict, Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .canonicalization import canonicalize, sha256_hex

_PUB_CACHE: Dict[str, Any] = {}
_SIG_CACHE: "OrderedDict[str, bool]" = OrderedDict()
_SIG_CACHE_MAX = 8192

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

def deterministic_private_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(("ORPRG-Eval-v3.2 deterministic key:" + label).encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)

def public_key_b64(priv: Ed25519PrivateKey) -> str:
    return b64(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

def sign_object(priv: Ed25519PrivateKey, obj: Mapping[str, Any]) -> str:
    return b64(priv.sign(canonicalize(obj)))

def verify_signature(public_b64: str, sig_b64: str, obj: Mapping[str, Any]) -> bool:
    try:
        obj_bytes = canonicalize(obj)
        cache_key = sha256_hex(public_b64.encode() + b"|" + sig_b64.encode() + b"|" + obj_bytes)
        if cache_key in _SIG_CACHE:
            _SIG_CACHE.move_to_end(cache_key)
            return _SIG_CACHE[cache_key]
        pub = _PUB_CACHE.get(public_b64)
        if pub is None:
            pub = Ed25519PublicKey.from_public_bytes(unb64(public_b64))
            _PUB_CACHE[public_b64] = pub
        pub.verify(unb64(sig_b64), obj_bytes)
        _SIG_CACHE[cache_key] = True
        _SIG_CACHE.move_to_end(cache_key)
        while len(_SIG_CACHE) > _SIG_CACHE_MAX:
            _SIG_CACHE.popitem(last=False)
        return True
    except Exception:
        return False

def sign_envelope(priv: Ed25519PrivateKey, body: Mapping[str, Any], issuer_id: str, sig_field: str = "signature") -> Dict[str, Any]:
    return {"body": dict(body), "authenticity": {"issuer_id": issuer_id, sig_field: sign_object(priv, body)}}
