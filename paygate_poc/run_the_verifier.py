from __future__ import annotations

import json
import sys
from pathlib import Path

from .scenario import run_scenarios


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m paygate_poc.run_the_verifier <expected-results.json>", file=sys.stderr)
        return 2
    expected_path = Path(sys.argv[1])
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    actual = run_scenarios()
    expected_map = {s["scenario"]: {"outcome": s["outcome"], "reason_codes": sorted(s.get("reason_codes", []))} for s in expected["scenarios"]}
    actual_map = {s["scenario"]: {"outcome": s["outcome"], "reason_codes": sorted(s.get("reason_codes", []))} for s in actual["scenarios"]}
    mismatches = []
    for name, exp in expected_map.items():
        act = actual_map.get(name)
        if act != exp:
            mismatches.append({"scenario": name, "expected": exp, "actual": act})
    for name in actual_map:
        if name not in expected_map:
            mismatches.append({"scenario": name, "expected": None, "actual": actual_map[name]})
    output = {"status": "PASS" if not mismatches else "FAIL", "mismatches": mismatches, "checked": len(actual_map)}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
