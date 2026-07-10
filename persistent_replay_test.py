#!/usr/bin/env python3
"""Persistent SQLite capability-replay restart test for ORPRG-Eval v3.2.

The test exercises the same scoped replay domain used by the downstream gateway:
one capability is accepted once, subsequent attempts are denied, and reopening
the SQLite-backed cache does not reset the single-use decision.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from orprg_eval.canonicalization import digest_obj
from orprg_eval.gateway import MockEgressGateway
from orprg_eval.models import ALLOW, DRC
from orprg_eval.persistent_replay import SQLiteReplayCache
from orprg_eval.vector_factory import (
    base_policy,
    base_request,
    make_capability,
    make_receipt,
)

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def _context(policy, request, receipt, cache):
    return {
        "now": policy["now"],
        "capability_replay_cache": cache,
        "resolved_tenant_id": request["tenant_id"],
        "expected_receipt_digest": digest_obj(receipt["receipt_core"]),
    }


def main(workers: int = 16) -> int:
    policy = base_policy()
    request = base_request()
    receipt = make_receipt(
        request, policy=policy, nonce="persistent-replay-receipt"
    )
    capability = make_capability(
        request, receipt, policy=policy, nonce="persistent-replay-cap"
    )
    gateway = MockEgressGateway(request["interface_id"])
    attempts = max(2, int(workers))

    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "replay.sqlite3"
        cache = SQLiteReplayCache(db_path)
        rows = [
            gateway.commit(
                request,
                capability,
                policy,
                _context(policy, request, receipt, cache),
            )
            for _ in range(attempts)
        ]

        reopened = SQLiteReplayCache(db_path)
        after_reopen = gateway.commit(
            request,
            capability,
            policy,
            _context(policy, request, receipt, reopened),
        )
        successes = sum(1 for row in rows if row["decision"] == ALLOW)
        replay_denials = sum(
            1
            for row in rows
            if row.get("denial_reason_code") == DRC["CAPABILITY_REPLAY"]
        )
        summary = {
            "synthetic": True,
            "attempts_before_reopen": attempts,
            "successes": successes,
            "replay_denials": replay_denials,
            "db_nonce_count": reopened.count(),
            "reopen_decision": after_reopen["decision"],
            "reopen_denial_reason_code": after_reopen.get("denial_reason_code"),
            "passed": (
                successes == 1
                and replay_denials == attempts - 1
                and after_reopen.get("denial_reason_code")
                == DRC["CAPABILITY_REPLAY"]
                and reopened.count() == 1
            ),
        }

    (RESULTS / "persistent_replay_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown = [
        "# Persistent Replay Summary",
        "",
        "Synthetic SQLite single-use capability replay-cache restart test.",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in summary.items():
        markdown.append(f"| {key} | {value} |")
    (RESULTS / "persistent_replay_summary.md").write_text(
        "\n".join(markdown) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workers",
        type=int,
        default=16,
        help="number of sequential attempts retained for CLI compatibility",
    )
    arguments = parser.parse_args()
    raise SystemExit(main(arguments.workers))
