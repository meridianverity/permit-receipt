"""Deterministic canonicalization for synthetic ORPRG requests and artifacts."""
from __future__ import annotations
import hashlib
import json
import unicodedata
from typing import Any, Mapping

SUPPORTED_PROFILE = "CP-JSON-2"

class CanonicalizationError(ValueError):
    pass

def _normalize(x: Any) -> Any:
    if x is None or isinstance(x, (bool, int)):
        return x
    if isinstance(x, float):
        # Floats are intentionally rejected to avoid implementation-defined
        # formatting, NaN/Inf ambiguity, and precision drift.
        raise CanonicalizationError("CP-JSON-2 rejects floating point inputs")
    if isinstance(x, str):
        return unicodedata.normalize("NFC", x)
    if isinstance(x, list):
        return [_normalize(v) for v in x]
    if isinstance(x, tuple):
        return [_normalize(v) for v in x]
    if isinstance(x, Mapping):
        normalized = {}
        for k, v in x.items():
            nk = unicodedata.normalize("NFC", str(k))
            if nk in normalized:
                raise CanonicalizationError(f"duplicate normalized key: {nk}")
            normalized[nk] = _normalize(v)
        return {k: normalized[k] for k in sorted(normalized)}
    raise CanonicalizationError(f"unsupported canonicalization type: {type(x)!r}")

def canonicalize(obj: Mapping[str, Any], canonicalization_profile: str = SUPPORTED_PROFILE) -> bytes:
    if canonicalization_profile != SUPPORTED_PROFILE:
        raise CanonicalizationError(f"unsupported canonicalization profile {canonicalization_profile}")
    if not isinstance(obj, Mapping):
        raise CanonicalizationError("canonicalize expects a mapping")
    return json.dumps(_normalize(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def digest_obj(obj: Mapping[str, Any], canonicalization_profile: str = SUPPORTED_PROFILE) -> str:
    return sha256_hex(canonicalize(obj, canonicalization_profile))

def canonicalize_request(request: Mapping[str, Any], canonicalization_profile: str = SUPPORTED_PROFILE) -> bytes:
    return canonicalize(request, canonicalization_profile)

def compute_action_digest(canonical_request: bytes) -> str:
    return sha256_hex(canonical_request)
