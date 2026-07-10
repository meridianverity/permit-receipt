#!/usr/bin/env python3
"""Stateful replay-cache concurrency test for ORPRG-Eval v3.2.

A single-use capability token is submitted concurrently by many workers. Exactly
one worker should commit; all other workers should observe fail-closed replay
denial. This is a synthetic reference test, not a production load test.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
from pathlib import Path

from orprg_eval.gateway import MockEgressGateway
from orprg_eval.vector_factory import base_policy, base_request, make_receipt, make_capability
from orprg_eval.models import ALLOW, DRC
from orprg_eval.canonicalization import digest_obj
from orprg_eval.replay import ReplayCache

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def main(workers: int = 64) -> int:
    policy = base_policy()
    req = base_request()
    receipt = make_receipt(req, policy=policy, nonce="replay-concurrency-receipt")
    cap = make_capability(req, receipt, policy=policy, nonce="replay-concurrency-cap")
    gateway = MockEgressGateway(req["interface_id"])
    cache = ReplayCache()
    ctx = {"now": policy["now"], "capability_replay_cache": cache, "resolved_tenant_id": req["tenant_id"], "expected_receipt_digest": digest_obj(receipt["receipt_core"])}

    def attempt(_idx: int):
        return gateway.commit(req, cap, policy, ctx)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        rows = list(ex.map(attempt, range(workers)))
    successes = sum(1 for r in rows if r["decision"] == ALLOW)
    replay_denials = sum(1 for r in rows if r["denial_reason_code"] == DRC["CAPABILITY_REPLAY"])
    summary = {
        "synthetic": True,
        "workers": workers,
        "successes": successes,
        "replay_denials": replay_denials,
        "passed": successes == 1 and replay_denials == workers - 1,
        "expected_successes": 1,
        "expected_replay_denials": workers - 1,
    }
    (RESULTS / "replay_concurrency_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# Replay Concurrency Summary", "", "Synthetic single-use capability replay test.", "", "| Metric | Value |", "|---|---:|"]
    for k, v in summary.items():
        md.append(f"| {k} | {v} |")
    (RESULTS / "replay_concurrency_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=64, help="number of concurrent replay attempts")
    args = ap.parse_args()
    raise SystemExit(main(args.workers))
