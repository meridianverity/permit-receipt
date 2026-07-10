"""Strict, host-timezone-independent time helpers for the public evaluation profile."""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

# The selected public-evaluation profile deliberately chooses one small RFC 3339
# surface: uppercase ``T``; seconds required; at most microsecond precision; and
# an explicit ``Z`` or numeric UTC offset.  Naive local time is never accepted.
_RFC3339_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d{1,6})?"
    r"(?P<zone>Z|[+-]\d{2}:\d{2})$"
)

MAX_TIME_TEXT_LENGTH = 40


class TimeFormatError(ValueError):
    """Raised when an input is outside the selected RFC 3339 profile."""


def parse_rfc3339(value: Any) -> datetime:
    """Parse an explicit-zone RFC 3339 timestamp and return UTC.

    The function is intentionally strict and deterministic across hosts.  It
    rejects booleans, numbers, naive timestamps, space separators, lowercase
    timezone markers, leap seconds, the RFC 3339 unknown-offset sentinel
    ``-00:00``, and offsets not accepted by ``datetime``.
    """

    if not isinstance(value, str) or not value or len(value) > MAX_TIME_TEXT_LENGTH:
        raise TimeFormatError("timestamp must be a bounded nonempty string")
    if _RFC3339_RE.fullmatch(value) is None:
        raise TimeFormatError("timestamp is outside the selected RFC 3339 profile")
    # RFC 3339 uses ``-00:00`` to mean that the local offset is unknown.  An
    # authorization validity check requires a known instant, so the selected
    # profile rejects that sentinel rather than silently treating it as UTC.
    if value.endswith("-00:00"):
        raise TimeFormatError("unknown local offset is forbidden")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise TimeFormatError("timestamp is not a valid calendar instant") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TimeFormatError("timezone-naive timestamps are forbidden")
    # RFC 3339 numeric offsets are bounded to 23:59 by the grammar, while the
    # Python parser applies its own stricter calendar/offset validation.
    return parsed.astimezone(timezone.utc)


def is_strict_int(value: Any) -> bool:
    """Return True only for integers, excluding bool's int subclass behavior."""

    return isinstance(value, int) and not isinstance(value, bool)
