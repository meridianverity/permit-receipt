"""Strict JSON ingress helpers with duplicate-key and resource-limit rejection."""
from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any, Iterable, Tuple

from .canonicalization import (
    MAX_CANONICAL_BYTES,
    MAX_PROFILE_INTEGER,
    MIN_PROFILE_INTEGER,
    CanonicalizationError,
    normalize_json_value,
)

DEFAULT_MAX_JSON_BYTES = MAX_CANONICAL_BYTES


class StrictJSONError(ValueError):
    pass


class DuplicateJSONKeyError(StrictJSONError):
    pass


def _pairs_no_duplicates(pairs: Iterable[Tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    normalized_seen: set[str] = set()
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON member name: {key}")
        normalized = unicodedata.normalize("NFC", key)
        if normalized in normalized_seen:
            raise DuplicateJSONKeyError(f"duplicate NFC-normalized JSON member name: {normalized}")
        normalized_seen.add(normalized)
        result[key] = value
    return result


def _parse_int(text: str) -> int:
    value = int(text, 10)
    if value < MIN_PROFILE_INTEGER or value > MAX_PROFILE_INTEGER:
        raise StrictJSONError("JSON integer outside signed 64-bit public profile")
    return value


def _reject_float(text: str) -> Any:
    raise StrictJSONError(f"floating point JSON numbers are not accepted: {text}")


def _reject_constant(text: str) -> Any:
    raise StrictJSONError(f"non-finite JSON number is not accepted: {text}")


def loads_strict_json(data: str | bytes, *, max_bytes: int = DEFAULT_MAX_JSON_BYTES) -> Any:
    if isinstance(data, bytes):
        if len(data) > max_bytes:
            raise StrictJSONError("JSON body exceeds maximum size")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("JSON body is not valid UTF-8") from exc
    elif isinstance(data, str):
        if len(data.encode("utf-8")) > max_bytes:
            raise StrictJSONError("JSON body exceeds maximum size")
        text = data
    else:
        raise StrictJSONError("JSON input must be text or bytes")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        normalize_json_value(value)
        return value
    except (json.JSONDecodeError, CanonicalizationError, UnicodeError, TypeError, ValueError) as exc:
        if isinstance(exc, StrictJSONError):
            raise
        raise StrictJSONError("JSON input is outside the strict public profile") from exc


def load_strict_json(path: str | Path, *, max_bytes: int = DEFAULT_MAX_JSON_BYTES) -> Any:
    file_path = Path(path)
    raw = file_path.read_bytes()
    return loads_strict_json(raw, max_bytes=max_bytes)
