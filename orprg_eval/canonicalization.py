"""Deterministic, bounded canonicalization for synthetic ORPRG artifacts."""
from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

SUPPORTED_PROFILE = "CP-JSON-2"
MAX_CANONICAL_DEPTH = 32
MAX_CONTAINER_ITEMS = 10_000
MAX_TOTAL_NODES = 50_000
MAX_STRING_UTF8_BYTES = 65_536
MAX_CANONICAL_BYTES = 1_048_576
MIN_PROFILE_INTEGER = -(2**63)
MAX_PROFILE_INTEGER = 2**63 - 1


class CanonicalizationError(ValueError):
    pass


@dataclass
class _Budget:
    nodes: int = 0

    def consume(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_TOTAL_NODES:
            raise CanonicalizationError("CP-JSON-2 node limit exceeded")


def _normalize_text(value: str) -> str:
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise CanonicalizationError("CP-JSON-2 rejects lone UTF-16 surrogate code points")
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized.encode("utf-8")) > MAX_STRING_UTF8_BYTES:
        raise CanonicalizationError("CP-JSON-2 string length limit exceeded")
    return normalized


def _normalize(value: Any, *, depth: int, budget: _Budget) -> Any:
    budget.consume()
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalizationError("CP-JSON-2 nesting limit exceeded")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value < MIN_PROFILE_INTEGER or value > MAX_PROFILE_INTEGER:
            raise CanonicalizationError("CP-JSON-2 integer outside signed 64-bit profile")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("CP-JSON-2 rejects floating point inputs")
    if isinstance(value, str):
        return _normalize_text(value)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise CanonicalizationError("CP-JSON-2 array item limit exceeded")
        return [_normalize(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, Mapping):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise CanonicalizationError("CP-JSON-2 object member limit exceeded")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("CP-JSON-2 object member names must be strings")
            normalized_key = _normalize_text(key)
            if normalized_key in normalized:
                raise CanonicalizationError(f"duplicate normalized key: {normalized_key}")
            normalized[normalized_key] = _normalize(item, depth=depth + 1, budget=budget)
        return {key: normalized[key] for key in sorted(normalized)}
    raise CanonicalizationError(f"unsupported canonicalization type: {type(value)!r}")


def normalize_json_value(value: Any) -> Any:
    """Validate and normalize a JSON-compatible value under CP-JSON-2 limits."""

    return _normalize(value, depth=0, budget=_Budget())


def canonicalize(obj: Mapping[str, Any], canonicalization_profile: str = SUPPORTED_PROFILE) -> bytes:
    if canonicalization_profile != SUPPORTED_PROFILE:
        raise CanonicalizationError(f"unsupported canonicalization profile {canonicalization_profile}")
    if not isinstance(obj, Mapping):
        raise CanonicalizationError("canonicalize expects a mapping")
    try:
        encoded = json.dumps(
            normalize_json_value(obj),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise CanonicalizationError("CP-JSON-2 serialization failed") from exc
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise CanonicalizationError("CP-JSON-2 canonical byte limit exceeded")
    return encoded


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_obj(obj: Mapping[str, Any], canonicalization_profile: str = SUPPORTED_PROFILE) -> str:
    return sha256_hex(canonicalize(obj, canonicalization_profile))


def canonicalize_request(request: Mapping[str, Any], canonicalization_profile: str = SUPPORTED_PROFILE) -> bytes:
    return canonicalize(request, canonicalization_profile)


def compute_action_digest(canonical_request: bytes) -> str:
    return sha256_hex(canonical_request)
