#!/usr/bin/env python3
"""Aggregate reproducibility runner for PermitReceipt reference evaluation.

The runner executes the bounded synthetic evaluation used by the paper and
writes per-step stdout/stderr files for artifact reviewers. It uses in-process
module entry points to avoid subprocess startup variability in constrained
review environments; each underlying module remains directly executable for
independent debugging.
"""
from __future__ import annotations

import argparse
import contextlib
import runpy
import json
import os
import sys
import time
from pathlib import Path
from typing import Callable, List, Tuple

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def _run_pytest() -> int:
    import pytest  # type: ignore
    return int(pytest.main(["-q"]))


def _run_script(script_name: str, argv: List[str] | None = None) -> int:
    old_argv = sys.argv[:]
    try:
        sys.argv = [script_name] + (argv or [])
        runpy.run_path(str(ROOT / script_name), run_name="__main__")
        return 0
    finally:
        sys.argv = old_argv


def _step_list(full: bool, no_bench: bool) -> List[Tuple[str, Callable[[], int]]]:
    steps: List[Tuple[str, Callable[[], int]]] = [
        ("pytest -q", _run_pytest),
        ("run_vectors.py", lambda: _run_script("run_vectors.py")),
        ("canonicalization_fuzz.py", lambda: _run_script("canonicalization_fuzz.py")),
        ("schema_fuzz.py", lambda: _run_script("schema_fuzz.py")),
        ("http_canonicalization_fuzz.py", lambda: _run_script("http_canonicalization_fuzz.py")),
        ("partition_sim.py", lambda: _run_script("partition_sim.py")),
        ("gateway_demo.py", lambda: _run_script("gateway_demo.py")),
        ("retrieval_gateway_demo.py", lambda: _run_script("retrieval_gateway_demo.py")),
        ("egress_gateway_demo.py", lambda: _run_script("egress_gateway_demo.py")),
        ("ext_authz_adapter_demo.py", lambda: _run_script("ext_authz_adapter_demo.py")),
        ("kms_key_release_demo.py", lambda: _run_script("kms_key_release_demo.py")),
        ("integration_contract_check.py", lambda: _run_script("integration_contract_check.py")),
        ("pdp_baseline_matrix.py", lambda: _run_script("pdp_baseline_matrix.py")),
        ("standard_policy_baseline_matrix.py", lambda: _run_script("standard_policy_baseline_matrix.py")),
        ("baseline_compare.py", lambda: _run_script("baseline_compare.py")),
        ("replay_concurrency.py --workers 16", lambda: _run_script("replay_concurrency.py")),
        ("persistent_replay_test.py --workers 16", lambda: _run_script("persistent_replay_test.py", ["--workers", "16"])),
    ]
    if not no_bench:
        bench_args = ["--warm-sizes", "10000", "--merkle-size", "10000", "--cold-sizes", "1000"] if full else ["--warm-sizes", "1000", "--merkle-size", "1000", "--cold-sizes", "100"]
        steps.append(("benchmark.py " + " ".join(bench_args), lambda args=bench_args: _run_script("benchmark.py", args)))
    steps.extend([
        ("summarize_results.py", lambda: _run_script("summarize_results.py")),
        ("make_manifest.py", lambda: _run_script("make_manifest.py")),
        ("verify_manifest.py", lambda: _run_script("verify_manifest.py")),
    ])
    return steps


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PermitReceipt reference evaluation reproducibility sequence")
    parser.add_argument("--full", action="store_true", help="run full bounded evaluation used in the paper")
    parser.add_argument("--no-bench", action="store_true", help="skip benchmarks while still running all semantic checks")
    parser.add_argument("--timeout", type=int, default=240, help="retained for CLI compatibility; in-process runner does not enforce per-step timeout")
    args = parser.parse_args()

    os.environ.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    os.environ.setdefault("ORPRG_EVAL_MODE", "review")

    steps = _step_list(full=args.full, no_bench=args.no_bench)
    log: List[str] = [f"PermitReceipt reference evaluation run_all; full={args.full}; no_bench={args.no_bench}; timeout={args.timeout}; mode=in_process"]
    summary_rows = []
    start_all = time.perf_counter()

    for i, (label, fn) in enumerate(steps, 1):
        out = RESULTS / f"run_all_{i:02d}_stdout.txt"
        err = RESULTS / f"run_all_{i:02d}_stderr.txt"
        print(f"[{i}/{len(steps)}] $ {label}", flush=True)
        t = time.perf_counter()
        rc = 0
        try:
            with out.open("w", encoding="utf-8") as fo, err.open("w", encoding="utf-8") as fe:
                with contextlib.redirect_stdout(fo), contextlib.redirect_stderr(fe):
                    rc = fn()
        except SystemExit as e:
            rc = int(e.code or 0) if isinstance(e.code, int) else 1
        except Exception as e:  # reviewer diagnostics
            rc = 1
            with err.open("a", encoding="utf-8") as fe:
                import traceback
                fe.write(f"\nEXCEPTION: {e!r}\n")
                traceback.print_exc(file=fe)
        elapsed = time.perf_counter() - t
        status = f"exit={rc} elapsed={elapsed:.3f}s stdout={out.name} stderr={err.name}"
        print(status, flush=True)
        log.extend([f"[{i}/{len(steps)}] {label}", status, ""])
        summary_rows.append({"step": i, "command": label, "exit": rc, "elapsed_seconds": elapsed, "stdout": out.name, "stderr": err.name})
        (RESULTS / "run_log.txt").write_text("\n".join(log), encoding="utf-8")
        (RESULTS / "run_all_summary.json").write_text(json.dumps({"ok": all(r["exit"] == 0 for r in summary_rows), "rows": summary_rows, "mode": "in_process"}, indent=2, sort_keys=True), encoding="utf-8")
        if rc != 0:
            return rc

    total = time.perf_counter() - start_all
    log.append(f"total_elapsed={total:.3f}s")
    (RESULTS / "run_log.txt").write_text("\n".join(log), encoding="utf-8")
    (RESULTS / "run_all_summary.json").write_text(json.dumps({"ok": True, "rows": summary_rows, "total_elapsed_seconds": total, "mode": "in_process"}, indent=2, sort_keys=True), encoding="utf-8")
    print(log[-1], flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
