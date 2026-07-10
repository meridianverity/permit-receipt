#!/usr/bin/env python3
"""Run the complete public-evaluation gate in isolated subprocesses.

Each step receives a fresh interpreter. This prevents test or demo resources from
leaking into later checks and guarantees that a successful summary is followed
by process termination.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
STEP_TIMEOUT_SECONDS = 180


def evaluation_environment() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONWARNINGS": "error",
        }
    )
    return env


def main() -> int:
    CHECKS.mkdir(exist_ok=True)
    py = sys.executable
    steps: list[tuple[str, list[str]]] = [
        ("hybrid_demo", [py, "-m", "paygate_hybrid.hybrid_demo", "--out", "checks", "--json"]),
        ("paygate_demo", [py, "-m", "paygate_poc.demo", "--out", "checks", "--json"]),
        (
            "paygate_ref",
            [
                py,
                "scripts/run_paygate_ref.py",
                "--out",
                "checks/paygate_ref_demo_results.json",
                "--summary-md",
                "checks/paygate_ref_demo_summary.md",
            ],
        ),
        ("orprg_vectors", [py, "run_vectors.py"]),
        ("pytest", [py, "-m", "pytest", "-q", "-p", "no:cacheprovider"]),
        ("ietf126_packet", [py, "ietf126/run_review_packet.py"]),
        ("independent_recompute", [py, "ietf126/independent_recompute.py"]),
        ("independent_crypto_verify", [py, "ietf126/independent_crypto_verify.py"]),
        ("release_gate", [py, "tools/release_gate.py"]),
    ]

    rows: list[dict[str, object]] = []
    started = time.perf_counter()
    env = evaluation_environment()
    for index, (label, command) in enumerate(steps, 1):
        step_started = time.perf_counter()
        stdout_path = CHECKS / f"public_eval_{index:02d}_{label}_stdout.txt"
        stderr_path = CHECKS / f"public_eval_{index:02d}_{label}_stderr.txt"
        exit_code = 1
        failure_kind: str | None = None
        with stdout_path.open("w", encoding="utf-8", newline="\n") as stdout_file, stderr_path.open(
            "w", encoding="utf-8", newline="\n"
        ) as stderr_file:
            try:
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=env,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=STEP_TIMEOUT_SECONDS,
                    check=False,
                )
                exit_code = int(completed.returncode)
            except subprocess.TimeoutExpired:
                exit_code = 124
                failure_kind = "timeout"
                stderr_file.write(f"step exceeded {STEP_TIMEOUT_SECONDS} seconds\n")
            except OSError as exc:
                exit_code = 126
                failure_kind = "spawn_error"
                stderr_file.write(f"unable to execute step: {exc!r}\n")

        row: dict[str, object] = {
            "step": index,
            "label": label,
            "command": command,
            "exit": exit_code,
            "elapsed_seconds": round(time.perf_counter() - step_started, 6),
            "stdout": stdout_path.name,
            "stderr": stderr_path.name,
        }
        if failure_kind is not None:
            row["failure_kind"] = failure_kind
        rows.append(row)
        print(f"[{index}/{len(steps)}] {label} exit={exit_code}", flush=True)
        if exit_code != 0:
            break

    summary = {
        "ok": len(rows) == len(steps) and all(int(row["exit"]) == 0 for row in rows),
        "process_isolation": True,
        "step_timeout_seconds": STEP_TIMEOUT_SECONDS,
        "rows": rows,
        "total_elapsed_seconds": round(time.perf_counter() - started, 6),
    }
    (CHECKS / "public_eval_run_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
