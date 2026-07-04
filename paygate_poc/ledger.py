from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_hex_bytes, utc_now_iso


class AppendOnlyLedger:
    """A small hash-chained JSONL ledger for demo auditability."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        if self.path and self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.records.append(json.loads(line))

    def append(self, record_type: str, record: dict[str, Any]) -> dict[str, Any]:
        prev = self.records[-1]["chain_hash"] if self.records else "0" * 64
        envelope = {
            "seq": len(self.records) + 1,
            "ts": utc_now_iso(),
            "record_type": record_type,
            "record": record,
            "prev_chain_hash": prev,
        }
        envelope["record_hash"] = sha256_hex_bytes(canonical_bytes(envelope))
        envelope["chain_hash"] = sha256_hex_bytes((prev + envelope["record_hash"]).encode("ascii"))
        self.records.append(envelope)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        return envelope

    def verify_chain(self) -> tuple[bool, str]:
        prev = "0" * 64
        for i, rec in enumerate(self.records, start=1):
            if rec.get("seq") != i:
                return False, f"seq mismatch at {i}"
            if rec.get("prev_chain_hash") != prev:
                return False, f"prev hash mismatch at {i}"
            core = {k: rec[k] for k in ["seq", "ts", "record_type", "record", "prev_chain_hash"]}
            rh = sha256_hex_bytes(canonical_bytes(core))
            if rec.get("record_hash") != rh:
                return False, f"record hash mismatch at {i}"
            ch = sha256_hex_bytes((prev + rh).encode("ascii"))
            if rec.get("chain_hash") != ch:
                return False, f"chain hash mismatch at {i}"
            prev = ch
        return True, prev
