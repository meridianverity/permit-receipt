#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
from collections import Counter
from orprg_eval.vector_factory import build_vectors
from orprg_eval.verifier import verify_permit_receipt

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
(ROOT / "evaluation_vectors").mkdir(exist_ok=True)

vectors = build_vectors()
serializable_vectors = []
results = []
passed = 0
for v in vectors:
    res = verify_permit_receipt(v["request"], v["permit_receipt"], v["policy_state"], v["revocation_state"], v["context"])
    ok = res.decision == v["expected"]["decision"] and res.denial_reason_code == v["expected"].get("denial_reason_code")
    passed += int(ok)
    row = {
        "vector_id": v["vector_id"],
        "category": v["category"],
        "description": v["description"],
        "invariant": v["invariant"],
        "expected": v["expected"],
        "observed": res.to_dict(),
        "pass": ok,
    }
    results.append(row)
    vec_copy = dict(v)
    serializable_vectors.append(vec_copy)

summary = {
    "package": "ORPRG-Eval v3.2 synthetic public evaluation",
    "synthetic": True,
    "total_vectors": len(vectors),
    "passed": passed,
    "failed": len(vectors) - passed,
    "pass_rate": passed / len(vectors) if vectors else 0,
    "by_category": Counter(v["category"] for v in vectors),
    "denial_reason_coverage": sorted(set(r["observed"]["denial_reason_code"] for r in results if r["observed"]["denial_reason_code"])),
}
# Convert Counter to normal dict.
summary["by_category"] = dict(summary["by_category"])

(ROOT / "evaluation_vectors" / "vectors.json").write_text(json.dumps(serializable_vectors, indent=2, sort_keys=True), encoding="utf-8")
(RESULTS / "results.json").write_text(json.dumps({"summary": summary, "results": results}, indent=2, sort_keys=True), encoding="utf-8")

md = []
md.append("# ORPRG-Eval v3.2 Evaluation Vector Results\n")
md.append("Synthetic public evaluation. No production secrets; see license/access terms.\n")
md.append(f"- Total vectors: **{summary['total_vectors']}**")
md.append(f"- Passed: **{summary['passed']}**")
md.append(f"- Failed: **{summary['failed']}**")
md.append(f"- Pass rate: **{summary['pass_rate']:.4f}**")
md.append("\n## Category coverage\n")
md.append("| Category | Count |")
md.append("|---|---:|")
for k, c in sorted(summary["by_category"].items()):
    md.append(f"| {k} | {c} |")
md.append("\n## Vector outcomes\n")
md.append("| Vector | Category | Expected | Observed | Reason | Pass |")
md.append("|---|---|---|---|---|---:|")
for r in results:
    md.append(f"| {r['vector_id']} | {r['category']} | {r['expected']['decision']} | {r['observed']['decision']} | {r['observed']['denial_reason_code'] or ''} | {r['pass']} |")
(RESULTS / "evaluation_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
