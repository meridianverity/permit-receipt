#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from paygate_ref.reference import run_all_scenarios


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PAYGATE-Ref sandbox agentic-commerce execution receipt demo")
    parser.add_argument("--out", default=str(ROOT / "results" / "paygate_ref_demo_results.json"), help="Output JSON path")
    parser.add_argument("--summary-md", default=str(ROOT / "results" / "paygate_ref_demo_summary.md"), help="Output Markdown summary path")
    args = parser.parse_args()
    result = run_all_scenarios()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    lines = [
        "# PAYGATE-Ref Demo Summary", "",
        "Synthetic reference only. No live PAN, no live settlement, no production checkout changes.", "",
        "| Scenario | Decision | Reason | Live PAN | Live settlement |", "|---|---|---|---:|---:|",
    ]
    for row in result["summary"]:
        lines.append(f"| {row['scenario']} | {row['decision']} | {row.get('denial_reason_code') or ''} | {row['live_pan_used']} | {row['live_network_settlement']} |")
    Path(args.summary_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"wrote": str(out), "scenarios": len(result["scenarios"]), "summary": result["summary"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
