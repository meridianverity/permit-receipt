"""Thread-safe replay cache for nonce/single-use tests."""
from __future__ import annotations
import threading
from typing import Set, Tuple

class ReplayCache:
    def __init__(self) -> None:
        self._seen: Set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

    def check_and_mark(self, domain: str, nonce: str) -> bool:
        """Return True if nonce is fresh and atomically mark it used."""
        key = (domain, nonce)
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            return True

    def contains(self, domain: str, nonce: str) -> bool:
        with self._lock:
            return (domain, nonce) in self._seen
