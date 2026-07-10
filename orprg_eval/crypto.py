"""Synthetic Ed25519 helpers. Deterministic keys are for test vectors only."""
from __future__ import annotations

import base64
import binascii
import hashlib
import threading
from collections import OrderedDict
from typing import Any, Dict, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canonicalization import canonicalize, sha256_hex

_PUB_CACHE: "OrderedDict[str, Ed25519PublicKey]" = OrderedDict()
_SIG_CACHE: "OrderedDict[str, bool]" = OrderedDict()
_PUB_CACHE_MAX = 1024
_SIG_CACHE_MAX = 8192
_CACHE_LOCK = threading.RLock()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    if not isinstance(data, str) or not data:
        raise ValueError("base64 value must be a nonempty string")
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("invalid canonical base64") from exc


def deterministic_private_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(("ORPRG-Eval-v3.2 deterministic key:" + label).encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_b64(priv: Ed25519PrivateKey) -> str:
    return b64(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def sign_object(priv: Ed25519PrivateKey, obj: Mapping[str, Any]) -> str:
    return b64(priv.sign(canonicalize(obj)))


def _cached_public_key(public_b64: str) -> Ed25519PublicKey:
    with _CACHE_LOCK:
        cached = _PUB_CACHE.get(public_b64)
        if cached is not None:
            _PUB_CACHE.move_to_end(public_b64)
            return cached
    raw = unb64(public_b64)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    parsed = Ed25519PublicKey.from_public_bytes(raw)
    with _CACHE_LOCK:
        _PUB_CACHE[public_b64] = parsed
        _PUB_CACHE.move_to_end(public_b64)
        while len(_PUB_CACHE) > _PUB_CACHE_MAX:
            _PUB_CACHE.popitem(last=False)
    return parsed


def verify_signature(public_b64: str, sig_b64: str, obj: Mapping[str, Any]) -> bool:
    try:
        obj_bytes = canonicalize(obj)
        if not isinstance(public_b64, str) or not isinstance(sig_b64, str):
            return False
        cache_key = sha256_hex(public_b64.encode("ascii") + b"|" + sig_b64.encode("ascii") + b"|" + obj_bytes)
        with _CACHE_LOCK:
            if cache_key in _SIG_CACHE:
                _SIG_CACHE.move_to_end(cache_key)
                return _SIG_CACHE[cache_key]
        signature = unb64(sig_b64)
        if len(signature) != 64:
            return False
        _cached_public_key(public_b64).verify(signature, obj_bytes)
        with _CACHE_LOCK:
            _SIG_CACHE[cache_key] = True
            _SIG_CACHE.move_to_end(cache_key)
            while len(_SIG_CACHE) > _SIG_CACHE_MAX:
                _SIG_CACHE.popitem(last=False)
        return True
    except Exception:
        return False


def sign_envelope(priv, body: Mapping[str, Any], issuer_id: str, sig_field: str = "signature") -> Dict[str, Any]:
    return {"body": dict(body), "authenticity": {"issuer_id": issuer_id, sig_field: sign_object(priv, body)}}
