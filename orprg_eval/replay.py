"""Thread-safe transactional replay cache for nonce/single-use tests.

A verifier may need to validate multiple one-time objects before it can commit an
ALLOW decision.  ``reserve`` prevents concurrent reuse without consuming a
nonce when a later mandatory check fails; callers then ``commit`` all
reservations together or ``release`` them on denial.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import threading
from typing import MutableSequence, Optional, Set, Tuple


@dataclass
class ReplayReservation:
    """A single replay-cache reservation.

    Reservation methods are idempotent.  A reservation that is garbage
    collected without an explicit commit is released as a defensive convenience
    for this evaluation implementation; authorization code should still use an
    explicit ``try/finally`` transaction boundary.
    """

    _cache: "ReplayCache" = field(repr=False)
    domain: str
    nonce: str
    token: str = field(repr=False)
    _active: bool = field(default=True, init=False, repr=False)
    _committed: bool = field(default=False, init=False, repr=False)

    @property
    def active(self) -> bool:
        return self._active

    @property
    def committed(self) -> bool:
        return self._committed

    def commit(self) -> bool:
        if not self._active:
            return self._committed
        ok = self._cache._commit(self.domain, self.nonce, self.token)
        self._active = False
        self._committed = ok
        return ok

    def release(self) -> None:
        if self._active:
            self._cache._release(self.domain, self.nonce, self.token)
            self._active = False

    def __enter__(self) -> "ReplayReservation":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.release()

    def __del__(self) -> None:  # pragma: no cover - best-effort defensive path
        try:
            self.release()
        except Exception:
            pass


class ReplayCache:
    """In-memory replay cache with atomic reserve/commit/release semantics."""

    def __init__(self) -> None:
        self._seen: Set[Tuple[str, str]] = set()
        self._reserved: dict[Tuple[str, str], str] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate(domain: str, nonce: str) -> tuple[str, str]:
        if not isinstance(domain, str) or not domain or len(domain) > 512:
            raise ValueError("replay domain must be a bounded nonempty string")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
            raise ValueError("replay nonce must be a bounded nonempty string")
        return domain, nonce

    def reserve(self, domain: str, nonce: str) -> Optional[ReplayReservation]:
        """Reserve a fresh nonce, or return ``None`` when already used/reserved."""

        key = self._validate(domain, nonce)
        token = secrets.token_hex(16)
        with self._lock:
            if key in self._seen or key in self._reserved:
                return None
            self._reserved[key] = token
        return ReplayReservation(self, key[0], key[1], token)

    def _commit(self, domain: str, nonce: str, token: str) -> bool:
        key = (domain, nonce)
        with self._lock:
            if self._reserved.get(key) != token:
                return key in self._seen
            del self._reserved[key]
            self._seen.add(key)
            return True

    def _release(self, domain: str, nonce: str, token: str) -> None:
        key = (domain, nonce)
        with self._lock:
            if self._reserved.get(key) == token:
                del self._reserved[key]

    def check_and_mark(self, domain: str, nonce: str) -> bool:
        """Compatibility helper: atomically reserve and immediately commit."""

        reservation = self.reserve(domain, nonce)
        return reservation is not None and reservation.commit()

    def contains(self, domain: str, nonce: str) -> bool:
        key = self._validate(domain, nonce)
        with self._lock:
            return key in self._seen or key in self._reserved

    def count(self) -> int:
        with self._lock:
            return len(self._seen)


@dataclass
class MutableNonceListReservation:
    """Reservation backed by a mutable nonce list used by JSON test contexts.

    This compatibility adapter lets the public vector format carry replay state
    without serializing a cache object.  The standard ``ReplayCache`` remains the
    preferred concurrent implementation because it preserves the full scoped
    domain in storage.
    """

    _cache: "MutableNonceListReplayCache" = field(repr=False)
    domain: str
    nonce: str
    token: str = field(repr=False)
    _active: bool = field(default=True, init=False, repr=False)
    _committed: bool = field(default=False, init=False, repr=False)

    @property
    def active(self) -> bool:
        return self._active

    @property
    def committed(self) -> bool:
        return self._committed

    def commit(self) -> bool:
        if not self._active:
            return self._committed
        ok = self._cache._commit(self.domain, self.nonce, self.token)
        self._active = False
        self._committed = ok
        return ok

    def release(self) -> None:
        if self._active:
            self._cache._release(self.domain, self.nonce, self.token)
            self._active = False

    def __del__(self) -> None:  # pragma: no cover - best-effort defensive path
        try:
            self.release()
        except Exception:
            pass


class MutableNonceListReplayCache:
    """Transactional adapter for JSON-serializable ``used_nonces`` lists.

    The list stores raw nonce strings for backward-compatible public vectors. A
    process-wide lock and reservation registry make repeated verifier calls using
    the same list fail closed, including concurrent preflight calls in this
    evaluation process.  Production-like callers should use ``ReplayCache`` or
    ``SQLiteReplayCache`` so the scoped replay domain is durably retained.
    """

    _global_lock = threading.RLock()
    _reserved: dict[tuple[int, str], str] = {}

    def __init__(self, values: MutableSequence[str]) -> None:
        if not isinstance(values, list):
            raise TypeError("mutable replay state must be a list")
        self._values = values

    @staticmethod
    def _validate(domain: str, nonce: str) -> tuple[str, str]:
        if not isinstance(domain, str) or not domain or len(domain) > 512:
            raise ValueError("replay domain must be a bounded nonempty string")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
            raise ValueError("replay nonce must be a bounded nonempty string")
        return domain, nonce

    def reserve(self, domain: str, nonce: str) -> Optional[MutableNonceListReservation]:
        domain, nonce = self._validate(domain, nonce)
        key = (id(self._values), nonce)
        token = secrets.token_hex(16)
        with self._global_lock:
            if nonce in self._values or key in self._reserved:
                return None
            self._reserved[key] = token
        return MutableNonceListReservation(self, domain, nonce, token)

    def _commit(self, domain: str, nonce: str, token: str) -> bool:
        self._validate(domain, nonce)
        key = (id(self._values), nonce)
        with self._global_lock:
            if self._reserved.get(key) != token:
                return nonce in self._values
            del self._reserved[key]
            if nonce in self._values:
                return False
            self._values.append(nonce)
            return True

    def _release(self, domain: str, nonce: str, token: str) -> None:
        self._validate(domain, nonce)
        key = (id(self._values), nonce)
        with self._global_lock:
            if self._reserved.get(key) == token:
                del self._reserved[key]

    def check_and_mark(self, domain: str, nonce: str) -> bool:
        reservation = self.reserve(domain, nonce)
        return reservation is not None and reservation.commit()

    def contains(self, domain: str, nonce: str) -> bool:
        self._validate(domain, nonce)
        key = (id(self._values), nonce)
        with self._global_lock:
            return nonce in self._values or key in self._reserved

    def count(self) -> int:
        with self._global_lock:
            return len(self._values)
