"""Persistent SQLite replay cache for synthetic ORPRG evaluation.

The schema upgrades the v2.2.5 ``used_nonces`` table in place.  Existing rows
are treated as committed.  New callers may reserve, commit, or release a nonce
transactionally.  Every connection is explicitly closed, including error
paths, so warnings-as-errors remains clean.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import secrets
import sqlite3
import threading
from typing import Optional


@dataclass
class SQLiteReplayReservation:
    _cache: "SQLiteReplayCache" = field(repr=False)
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

    def __del__(self) -> None:  # pragma: no cover - best effort only
        try:
            self.release()
        except Exception:
            pass


class SQLiteReplayCache:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._init()

    @staticmethod
    def _validate(domain: str, nonce: str) -> tuple[str, str]:
        if not isinstance(domain, str) or not domain or len(domain) > 512:
            raise ValueError("replay domain must be a bounded nonempty string")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
            raise ValueError("replay nonce must be a bounded nonempty string")
        return domain, nonce

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def _init(self) -> None:
        with self._lock:
            db = self._connect()
            try:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS used_nonces ("
                    "domain TEXT NOT NULL, nonce TEXT NOT NULL, "
                    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
                    "PRIMARY KEY(domain, nonce))"
                )
                columns = {row[1] for row in db.execute("PRAGMA table_info(used_nonces)")}
                if "reservation_id" not in columns:
                    db.execute("ALTER TABLE used_nonces ADD COLUMN reservation_id TEXT")
                if "committed" not in columns:
                    db.execute("ALTER TABLE used_nonces ADD COLUMN committed INTEGER NOT NULL DEFAULT 1")
                db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_used_nonces_state "
                    "ON used_nonces(committed, created_at)"
                )
            finally:
                db.close()

    def reserve(self, domain: str, nonce: str) -> Optional[SQLiteReplayReservation]:
        domain, nonce = self._validate(domain, nonce)
        token = secrets.token_hex(16)
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        "INSERT INTO used_nonces(domain, nonce, reservation_id, committed) "
                        "VALUES (?, ?, ?, 0)",
                        (domain, nonce, token),
                    )
                except sqlite3.IntegrityError:
                    db.execute("ROLLBACK")
                    return None
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            finally:
                db.close()
        return SQLiteReplayReservation(self, domain, nonce, token)

    def _commit(self, domain: str, nonce: str, token: str) -> bool:
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                cur = db.execute(
                    "UPDATE used_nonces SET committed=1, reservation_id=NULL "
                    "WHERE domain=? AND nonce=? AND committed=0 AND reservation_id=?",
                    (domain, nonce, token),
                )
                if cur.rowcount == 0:
                    row = db.execute(
                        "SELECT committed FROM used_nonces WHERE domain=? AND nonce=?",
                        (domain, nonce),
                    ).fetchone()
                    ok = bool(row and int(row[0]) == 1)
                else:
                    ok = True
                db.execute("COMMIT")
                return ok
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            finally:
                db.close()

    def _release(self, domain: str, nonce: str, token: str) -> None:
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "DELETE FROM used_nonces WHERE domain=? AND nonce=? "
                    "AND committed=0 AND reservation_id=?",
                    (domain, nonce, token),
                )
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            finally:
                db.close()

    def check_and_mark(self, domain: str, nonce: str) -> bool:
        reservation = self.reserve(domain, nonce)
        return reservation is not None and reservation.commit()

    def contains(self, domain: str, nonce: str) -> bool:
        domain, nonce = self._validate(domain, nonce)
        with self._lock:
            db = self._connect()
            try:
                row = db.execute(
                    "SELECT 1 FROM used_nonces WHERE domain=? AND nonce=? LIMIT 1",
                    (domain, nonce),
                ).fetchone()
                return row is not None
            finally:
                db.close()

    def count(self) -> int:
        with self._lock:
            db = self._connect()
            try:
                row = db.execute("SELECT COUNT(*) FROM used_nonces WHERE committed=1").fetchone()
                return int(row[0])
            finally:
                db.close()
