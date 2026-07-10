"""Bounded, duplicate-key-safe JSON helpers for local evaluation HTTP adapters."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from typing import Any, Mapping

from .canonicalization import MAX_CANONICAL_BYTES
from .jsonio import DuplicateJSONKeyError, StrictJSONError, loads_strict_json
from .models import DRC

MAX_HTTP_BODY_BYTES = MAX_CANONICAL_BYTES


class HTTPIngressError(ValueError):
    def __init__(self, denial_reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.denial_reason_code = denial_reason_code


def read_strict_json_body(
    handler: BaseHTTPRequestHandler,
    *,
    max_bytes: int = MAX_HTTP_BODY_BYTES,
) -> Any:
    """Read one bounded application/json body without ambiguous framing."""

    if handler.headers.get("transfer-encoding"):
        raise HTTPIngressError(DRC["SCHEMA_VALIDATION_FAILURE"], "transfer encoding unsupported")
    content_type = handler.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPIngressError(DRC["SCHEMA_VALIDATION_FAILURE"], "content type must be application/json")
    get_all = getattr(handler.headers, "get_all", None)
    if callable(get_all):
        lengths = get_all("content-length") or []
        if len(lengths) != 1:
            raise HTTPIngressError(DRC["SCHEMA_VALIDATION_FAILURE"], "content length must occur exactly once")
        text_length = lengths[0]
    else:
        text_length = handler.headers.get("content-length")
    if (
        not isinstance(text_length, str)
        or not text_length.isascii()
        or not text_length.isdigit()
    ):
        raise HTTPIngressError(DRC["SCHEMA_VALIDATION_FAILURE"], "invalid content length")
    length = int(text_length, 10)
    if length <= 0:
        raise HTTPIngressError(DRC["SCHEMA_VALIDATION_FAILURE"], "empty JSON body")
    if length > max_bytes:
        raise HTTPIngressError(DRC["RESOURCE_LIMIT_EXCEEDED"], "JSON body exceeds limit")
    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise HTTPIngressError(DRC["SCHEMA_VALIDATION_FAILURE"], "truncated JSON body")
    try:
        return loads_strict_json(raw, max_bytes=max_bytes)
    except DuplicateJSONKeyError as exc:
        raise HTTPIngressError(DRC["DUPLICATE_JSON_KEY"], "duplicate JSON member") from exc
    except StrictJSONError as exc:
        raise HTTPIngressError(DRC["SCHEMA_VALIDATION_FAILURE"], "invalid strict JSON") from exc


def send_json(
    handler: BaseHTTPRequestHandler,
    status: int,
    payload: Mapping[str, Any],
) -> None:
    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("content-length", str(len(body)))
    handler.send_header("cache-control", "no-store")
    handler.send_header("x-content-type-options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)
