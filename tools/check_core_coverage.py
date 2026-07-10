#!/usr/bin/env python3
"""Run strict tests and enforce coverage on security-critical verifier modules."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
COVERAGE_JSON = CHECKS / "core_coverage.json"
REPORT_JSON = CHECKS / "core_coverage_gate.json"
CRITICAL_MODULES = [
    "orprg_eval/canonicalization.py",
    "orprg_eval/crypto.py",
    "orprg_eval/httpio.py",
    "orprg_eval/jsonio.py",
    "orprg_eval/merkle.py",
    "orprg_eval/persistent_replay.py",
    "orprg_eval/replay.py",
    "orprg_eval/schema.py",
    "orprg_eval/timeutil.py",
    "orprg_eval/verifier.py",
]
MIN_CRITICAL_LINE_PERCENT = 99.0
MIN_CRITICAL_BRANCH_PERCENT = 97.5
PER_MODULE_BRANCH_MINIMUMS = {
    "orprg_eval/verifier.py": 97.0,
    "orprg_eval/schema.py": 97.0,
    "orprg_eval/merkle.py": 97.0,
    "orprg_eval/persistent_replay.py": 99.0,
}


def _percent(numerator: int, denominator: int) -> float:
    return 100.0 if denominator == 0 else 100.0 * numerator / denominator


def main() -> int:
    CHECKS.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONWARNINGS"] = "error"
    commands = [
        [sys.executable, "-m", "coverage", "erase"],
        [sys.executable, "-m", "coverage", "run", "--branch", "--source=orprg_eval", "-m", "pytest", "-q"],
        [sys.executable, "-m", "coverage", "json", "-o", str(COVERAGE_JSON)],
    ]
    command_results: list[dict[str, object]] = []
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
        command_results.append({
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-8000:],
            "stderr": completed.stderr[-8000:],
        })
        if completed.returncode:
            report = {"ok": False, "error": "coverage_command_failed", "commands": command_results}
            REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

    data = json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))
    files = data.get("files", {})
    missing = [name for name in CRITICAL_MODULES if name not in files]
    covered_lines = statements = covered_branches = branches = 0
    module_rows: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    for name in CRITICAL_MODULES:
        summary = (files.get(name) or {}).get("summary") or {}
        cl = int(summary.get("covered_lines", 0))
        ns = int(summary.get("num_statements", 0))
        cb = int(summary.get("covered_branches", 0))
        nb = int(summary.get("num_branches", 0))
        line_percent = _percent(cl, ns)
        branch_percent = _percent(cb, nb)
        module_rows.append({
            "path": name,
            "covered_lines": cl,
            "statements": ns,
            "line_percent": round(line_percent, 4),
            "covered_branches": cb,
            "branches": nb,
            "branch_percent": round(branch_percent, 4),
        })
        covered_lines += cl
        statements += ns
        covered_branches += cb
        branches += nb
        minimum = PER_MODULE_BRANCH_MINIMUMS.get(name)
        if minimum is not None and branch_percent < minimum:
            findings.append({"kind": "module_branch_coverage_below_threshold", "path": name, "observed": branch_percent, "required": minimum})

    critical_line_percent = _percent(covered_lines, statements)
    critical_branch_percent = _percent(covered_branches, branches)
    if missing:
        findings.append({"kind": "critical_modules_missing", "paths": missing})
    if critical_line_percent < MIN_CRITICAL_LINE_PERCENT:
        findings.append({"kind": "critical_line_coverage_below_threshold", "observed": critical_line_percent, "required": MIN_CRITICAL_LINE_PERCENT})
    if critical_branch_percent < MIN_CRITICAL_BRANCH_PERCENT:
        findings.append({"kind": "critical_branch_coverage_below_threshold", "observed": critical_branch_percent, "required": MIN_CRITICAL_BRANCH_PERCENT})

    report = {
        "ok": not findings,
        "thresholds": {
            "critical_line_percent": MIN_CRITICAL_LINE_PERCENT,
            "critical_branch_percent": MIN_CRITICAL_BRANCH_PERCENT,
            "per_module_branch_percent": PER_MODULE_BRANCH_MINIMUMS,
        },
        "critical_totals": {
            "covered_lines": covered_lines,
            "statements": statements,
            "line_percent": round(critical_line_percent, 4),
            "covered_branches": covered_branches,
            "branches": branches,
            "branch_percent": round(critical_branch_percent, 4),
        },
        "modules": module_rows,
        "findings": findings,
        "commands": command_results,
    }
    REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (ROOT / ".coverage").unlink(missing_ok=True)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
