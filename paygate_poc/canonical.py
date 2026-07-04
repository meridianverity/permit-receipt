"""Deterministic JSON canonicalization utilities for the PayGate PoC.

This is a small JCS-like profile: UTF-8 JSON, sorted object keys, no
insignificant whitespace, integers for money, and no floating point values.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when an object cannot be safely canonicalized."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError(f"timestamp must be RFC3339 UTC with Z suffix: {ts!r}")
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _reject_unsafe(value: Any, path: str = "$" ) -> None:
    if isinstance(value, float):
        raise CanonicalizationError(f"floating point value forbidden at {path}; use integer minor units")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string object key at {path}: {key!r}")
            _reject_unsafe(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            _reject_unsafe(child, f"{path}[{i}]")


def canonical_bytes(value: Any) -> bytes:
    _reject_unsafe(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_json(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    return "sha256:" + sha256_hex_bytes(canonical_bytes(value))


def digest_bytes(data: bytes) -> str:
    return "sha256:" + sha256_hex_bytes(data)


def without_signature(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if k != "signature"}


def require_fields(obj: dict[str, Any], required: list[str], where: str) -> list[str]:
    return [f"MISSING_FIELD:{where}.{name}" for name in required if name not in obj]
