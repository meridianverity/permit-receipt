"""Persistent SQLite replay cache for synthetic ORPRG tests.

This cache uses a UNIQUE(domain, nonce) constraint to model single-use receipt
or capability nonces across process restarts. It is intentionally small and
not a production replay-cache design.
"""
from __future__ import annotations
import sqlite3
import threading
from pathlib import Path

class SQLiteReplayCache:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.path, timeout=30) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS used_nonces (domain TEXT NOT NULL, nonce TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(domain, nonce))")
            db.commit()

    def check_and_mark(self, domain: str, nonce: str) -> bool:
        with self._lock:
            try:
                with sqlite3.connect(self.path, timeout=30, isolation_level="IMMEDIATE") as db:
                    db.execute("INSERT INTO used_nonces(domain, nonce) VALUES (?, ?)", (domain, nonce))
                    db.commit()
                    return True
            except sqlite3.IntegrityError:
                return False

    def count(self) -> int:
        with sqlite3.connect(self.path, timeout=30) as db:
            row = db.execute("SELECT COUNT(*) FROM used_nonces").fetchone()
            return int(row[0])
