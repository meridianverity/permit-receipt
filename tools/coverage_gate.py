#!/usr/bin/env python3
"""Execute strict branch coverage and enforce security-critical thresholds."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
SECURITY_THRESHOLDS = {
    "orprg_eval/canonicalization.py": (100.0, 100.0),
    "orprg_eval/crypto.py": (100.0, 100.0),
    "orprg_eval/httpio.py": (100.0, 100.0),
    "orprg_eval/jsonio.py": (100.0, 100.0),
    "orprg_eval/replay.py": (100.0, 100.0),
    "orprg_eval/timeutil.py": (100.0, 100.0),
    "orprg_eval/verifier.py": (98.0, 97.0),
    "orprg_eval/schema.py": (97.0, 97.0),
    "orprg_eval/merkle.py": (99.0, 97.0),
    "orprg_eval/persistent_replay.py": (99.0, 99.0),
}


def run(command: list[str]) -> int:
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONWARNINGS"] = "error"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.call(command, cwd=ROOT, env=env)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reuse", action="store_true", help="Validate existing coverage.json instead of rerunning tests")
    args = parser.parse_args()
    coverage_json = ROOT / "coverage.json"
    test_exit = 0
    export_exit = 0
    if not args.reuse:
        (ROOT / ".coverage").unlink(missing_ok=True)
        coverage_json.unlink(missing_ok=True)
        test_exit = run([sys.executable, "-m", "coverage", "run", "--branch", "-m", "pytest", "-q", "-p", "no:cacheprovider"])
        if test_exit == 0:
            export_exit = run([sys.executable, "-m", "coverage", "json", "-o", str(coverage_json)])
    findings: list[dict[str, object]] = []
    if test_exit != 0:
        findings.append({"kind": "coverage_test_failure", "detail": test_exit})
    if export_exit != 0 or not coverage_json.exists():
        findings.append({"kind": "coverage_export_failure", "detail": export_exit})
        data = {"totals": {}, "files": {}}
    else:
        data = json.loads(coverage_json.read_text(encoding="utf-8"))
    totals = data.get("totals", {})
    overall_combined = float(totals.get("percent_covered", 0.0))
    overall_statement = float(totals.get("percent_statements_covered", 0.0))
    overall_branch = float(totals.get("percent_branches_covered", 0.0))
    if overall_combined < 90.0:
        findings.append({"kind": "overall_combined_coverage_below_gate", "expected": 90.0, "observed": overall_combined})
    if overall_branch < 80.0:
        findings.append({"kind": "overall_branch_coverage_below_gate", "expected": 80.0, "observed": overall_branch})
    modules: dict[str, dict[str, object]] = {}
    for rel, (combined_min, branch_min) in SECURITY_THRESHOLDS.items():
        summary = (data.get("files", {}).get(rel) or {}).get("summary") or {}
        combined = float(summary.get("percent_covered", 0.0))
        branch = float(summary.get("percent_branches_covered", 0.0))
        modules[rel] = {
            "combined_percent": combined,
            "branch_percent": branch,
            "combined_minimum": combined_min,
            "branch_minimum": branch_min,
            "pass": combined >= combined_min and branch >= branch_min,
        }
        if combined < combined_min:
            findings.append({"path": rel, "kind": "combined_coverage_below_gate", "expected": combined_min, "observed": combined})
        if branch < branch_min:
            findings.append({"path": rel, "kind": "branch_coverage_below_gate", "expected": branch_min, "observed": branch})

    package_summaries = [
        row.get("summary") or {}
        for rel, row in (data.get("files", {}) or {}).items()
        if rel.startswith("orprg_eval/")
    ]
    package_statements = sum(int(row.get("num_statements", 0)) for row in package_summaries)
    package_covered_lines = sum(int(row.get("covered_lines", 0)) for row in package_summaries)
    package_branches = sum(int(row.get("num_branches", 0)) for row in package_summaries)
    package_covered_branches = sum(int(row.get("covered_branches", 0)) for row in package_summaries)
    package_statement = 100.0 * package_covered_lines / package_statements if package_statements else 100.0
    package_branch = 100.0 * package_covered_branches / package_branches if package_branches else 100.0
    package_combined_denominator = package_statements + package_branches
    package_combined = (
        100.0 * (package_covered_lines + package_covered_branches) / package_combined_denominator
        if package_combined_denominator
        else 100.0
    )
    report = {
        "ok": not findings,
        "test_exit": test_exit,
        "export_exit": export_exit,
        "test_count_expected_minimum": 250,
        "overall_combined_percent": overall_combined,
        "overall_statement_percent": overall_statement,
        "overall_branch_percent": overall_branch,
        "orprg_eval_combined_percent": package_combined,
        "orprg_eval_statement_percent": package_statement,
        "orprg_eval_branch_percent": package_branch,
        "modules": modules,
        "finding_count": len(findings),
        "findings": findings,
    }
    CHECKS.mkdir(exist_ok=True)
    (CHECKS / "coverage_gate.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
