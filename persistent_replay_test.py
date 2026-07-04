#!/usr/bin/env python3
"""Persistent SQLite replay-cache restart test for ORPRG-Eval v3.2.

The concurrent replay behavior is covered by replay_concurrency.py. This test
focuses on persistence across a cache reopen: one capability token is accepted
once, later attempts are denied, and the same nonce remains denied after the
SQLite-backed cache is reopened. The execution is deliberately sequential to
avoid nondeterministic SQLite thread scheduling in artifact-review sandboxes.
"""
from __future__ import annotations
import argparse, json, tempfile
from pathlib import Path
from orprg_eval.gateway import MockEgressGateway
from orprg_eval.models import ALLOW, DRC
from orprg_eval.persistent_replay import SQLiteReplayCache
from orprg_eval.vector_factory import base_policy, base_request, make_receipt, make_capability

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

def main(workers: int = 16):
    policy = base_policy()
    req = base_request()
    rec = make_receipt(req, policy=policy, nonce="persistent-replay-receipt")
    cap = make_capability(req, rec, policy=policy, nonce="persistent-replay-cap")
    gateway = MockEgressGateway(req["interface_id"])
    attempts = max(2, int(workers))
    with tempfile.TemporaryDirectory() as td:
        cache = SQLiteReplayCache(Path(td) / "replay.sqlite3")
        ctx = {"now": policy["now"], "capability_replay_cache": cache, "resolved_tenant_id": req["tenant_id"]}
        rows = [gateway.commit(req, cap, policy, ctx) for _ in range(attempts)]
        cache2 = SQLiteReplayCache(Path(td) / "replay.sqlite3")
        replay_after_reopen = cache2.check_and_mark("capability", "persistent-replay-cap")
        successes = sum(1 for r in rows if r["decision"] == ALLOW)
        replay_denials = sum(1 for r in rows if r.get("denial_reason_code") == DRC["CAPABILITY_REPLAY"])
        summary = {
            "synthetic": True,
            "attempts": attempts,
            "successes": successes,
            "replay_denials": replay_denials,
            "db_nonce_count": cache2.count(),
            "replay_after_reopen_accepted": replay_after_reopen,
            "passed": successes == 1 and replay_denials == attempts - 1 and replay_after_reopen is False,
        }
    (RESULTS / "persistent_replay_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# Persistent Replay Summary", "", "Synthetic SQLite single-use replay cache restart test.", "", "| Metric | Value |", "|---|---:|"]
    for k, v in summary.items():
        md.append(f"| {k} | {v} |")
    (RESULTS / "persistent_replay_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["passed"]:
        raise SystemExit(1)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=16, help="number of sequential attempts retained for CLI compatibility")
    args = ap.parse_args()
    main(args.workers)
