#!/usr/bin/env python3
from __future__ import annotations
import contextlib, json, os, runpy, sys, time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent
CHECKS = ROOT / "checks"
CHECKS.mkdir(exist_ok=True)

def _run_path(label: str, path: str, argv: list[str] | None = None) -> int:
    old = sys.argv[:]
    try:
        sys.argv = [path] + (argv or [])
        runpy.run_path(str(ROOT / path), run_name="__main__")
        return 0
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) else 1
    finally:
        sys.argv = old

def _run_module(label: str, module: str, argv: list[str] | None = None) -> int:
    old = sys.argv[:]
    try:
        sys.argv = [module] + (argv or [])
        runpy.run_module(module, run_name="__main__")
        return 0
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) else 1
    finally:
        sys.argv = old

def _pytest() -> int:
    import pytest  # type: ignore
    return int(pytest.main(["-q"]))


def main() -> int:
    os.environ.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    steps: list[tuple[str, Callable[[], int]]] = [
        ("paygate_hybrid.hybrid_demo", lambda: _run_module("paygate_hybrid.hybrid_demo", "paygate_hybrid.hybrid_demo", ["--out", "checks", "--json"])),
        ("paygate_poc.demo", lambda: _run_module("paygate_poc.demo", "paygate_poc.demo", ["--out", "checks", "--json"])),
        ("scripts/run_paygate_ref.py", lambda: _run_path("scripts/run_paygate_ref.py", "scripts/run_paygate_ref.py")),
        ("run_vectors.py", lambda: _run_path("run_vectors.py", "run_vectors.py")),
        ("canonicalization_fuzz.py", lambda: _run_path("canonicalization_fuzz.py", "canonicalization_fuzz.py")),
        ("schema_fuzz.py", lambda: _run_path("schema_fuzz.py", "schema_fuzz.py")),
        ("http_canonicalization_fuzz.py", lambda: _run_path("http_canonicalization_fuzz.py", "http_canonicalization_fuzz.py")),
        ("partition_sim.py", lambda: _run_path("partition_sim.py", "partition_sim.py")),
        ("gateway_demo.py", lambda: _run_path("gateway_demo.py", "gateway_demo.py")),
        ("retrieval_gateway_demo.py", lambda: _run_path("retrieval_gateway_demo.py", "retrieval_gateway_demo.py")),
        ("egress_gateway_demo.py", lambda: _run_path("egress_gateway_demo.py", "egress_gateway_demo.py")),
        ("ext_authz_adapter_demo.py", lambda: _run_path("ext_authz_adapter_demo.py", "ext_authz_adapter_demo.py")),
        ("kms_key_release_demo.py", lambda: _run_path("kms_key_release_demo.py", "kms_key_release_demo.py")),
        ("integration_contract_check.py", lambda: _run_path("integration_contract_check.py", "integration_contract_check.py")),
        ("pdp_baseline_matrix.py", lambda: _run_path("pdp_baseline_matrix.py", "pdp_baseline_matrix.py")),
        ("standard_policy_baseline_matrix.py", lambda: _run_path("standard_policy_baseline_matrix.py", "standard_policy_baseline_matrix.py")),
        ("baseline_compare.py", lambda: _run_path("baseline_compare.py", "baseline_compare.py")),
        ("replay_concurrency.py", lambda: _run_path("replay_concurrency.py", "replay_concurrency.py")),
        ("persistent_replay_test.py", lambda: _run_path("persistent_replay_test.py", "persistent_replay_test.py", ["--workers", "16"])),
        ("tools/release_gate.py", lambda: _run_path("tools/release_gate.py", "tools/release_gate.py")),
        ("pytest", _pytest),
    ]
    rows = []
    start = time.perf_counter()
    for i, (label, fn) in enumerate(steps, 1):
        out = CHECKS / f"hybrid_run_{i:02d}_stdout.txt"
        err = CHECKS / f"hybrid_run_{i:02d}_stderr.txt"
        t = time.perf_counter()
        rc = 0
        try:
            with out.open("w", encoding="utf-8") as fo, err.open("w", encoding="utf-8") as fe:
                with contextlib.redirect_stdout(fo), contextlib.redirect_stderr(fe):
                    rc = fn()
        except Exception as exc:
            rc = 1
            with err.open("a", encoding="utf-8") as fe:
                import traceback
                fe.write(f"EXCEPTION: {exc!r}\n")
                traceback.print_exc(file=fe)
        elapsed = time.perf_counter() - t
        row = {"step": i, "command": label, "exit": rc, "elapsed_seconds": elapsed, "stdout": out.name, "stderr": err.name}
        rows.append(row)
        print(f"[{i}/{len(steps)}] {label} exit={rc} elapsed={elapsed:.3f}s")
        (CHECKS / "run_all_hybrid_summary.json").write_text(json.dumps({"ok": all(r["exit"] == 0 for r in rows), "rows": rows}, indent=2, sort_keys=True), encoding="utf-8")
        if rc != 0:
            return rc
    (CHECKS / "run_all_hybrid_summary.json").write_text(json.dumps({"ok": True, "rows": rows, "total_elapsed_seconds": time.perf_counter()-start}, indent=2, sort_keys=True), encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
