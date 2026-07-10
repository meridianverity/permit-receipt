#!/usr/bin/env python3
"""Deterministic schema-negative fuzzing for ORPRG-Eval v3.2.

This deliberately mutates required request and receipt fields and verifies that
malformed artifacts fail closed. It complements canonicalization stability fuzzing.
"""
from __future__ import annotations
import copy
import json
import random
from pathlib import Path
from typing import Any, Dict, List

from orprg_eval.models import DENY, DRC
from orprg_eval.vector_factory import base_context, base_policy, base_request, base_revocation, make_receipt
from orprg_eval.verifier import verify_permit_receipt

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

REQ_REQUIRED = ["effect_type", "interface_id", "action_type", "target_id", "tenant_id", "payload_digest"]
RECEIPT_CORE_REQUIRED = ["policy_digest", "epoch_id", "valid_from", "valid_to", "action_digest", "scope", "anti_replay", "canonicalization_profile_ref", "issuer_id"]
AUTH_REQUIRED = ["issuer_id", "signature"]
BAD_VALUES = [None, "", [], {}, 3.14159, True]


def mutate_delete(d: Dict[str, Any], key: str) -> Dict[str, Any]:
    out = copy.deepcopy(d); out.pop(key, None); return out


def mutate_set(d: Dict[str, Any], key: str, value: Any) -> Dict[str, Any]:
    out = copy.deepcopy(d); out[key] = value; return out


def main() -> int:
    rng = random.Random(20260603)
    policy = base_policy()
    request = base_request()
    receipt = make_receipt(request, policy=policy, nonce="nonce-schema-fuzz")
    revocation = base_revocation(receipt)
    context = base_context()
    rows: List[Dict[str, Any]] = []

    # Required request-field deletion/type fuzz.
    for key in REQ_REQUIRED:
        mutated = mutate_delete(request, key)
        res = verify_permit_receipt(mutated, receipt, policy, revocation, context)
        rows.append({"case": f"request_missing_{key}", "kind": "request", "expected": DRC["SCHEMA_VALIDATION_FAILURE"], "observed": res.denial_reason_code, "pass": res.decision == DENY and res.denial_reason_code == DRC["SCHEMA_VALIDATION_FAILURE"]})
        for idx, bad in enumerate(BAD_VALUES):
            mutated = mutate_set(request, key, bad)
            res = verify_permit_receipt(mutated, receipt, policy, revocation, context)
            expected = (
                DRC["CANONICALIZATION_PROFILE_MISMATCH"]
                if isinstance(bad, float)
                else DRC["SCHEMA_VALIDATION_FAILURE"]
            )
            rows.append({"case": f"request_bad_{key}_{idx}", "kind": "request", "expected": expected, "observed": res.denial_reason_code, "pass": res.decision == DENY and res.denial_reason_code == expected})

    # Required receipt-core deletion/type fuzz.
    for key in RECEIPT_CORE_REQUIRED:
        mutated_receipt = copy.deepcopy(receipt)
        mutated_receipt["receipt_core"].pop(key, None)
        res = verify_permit_receipt(request, mutated_receipt, policy, revocation, context)
        rows.append({"case": f"receipt_core_missing_{key}", "kind": "receipt", "expected": DRC["SCHEMA_VALIDATION_FAILURE"], "observed": res.denial_reason_code, "pass": res.decision == DENY and res.denial_reason_code in {DRC["SCHEMA_VALIDATION_FAILURE"], DRC["RECEIPT_MALFORMED"]}})
        for idx, bad in enumerate(rng.sample(BAD_VALUES, k=len(BAD_VALUES))):
            mutated_receipt = copy.deepcopy(receipt)
            mutated_receipt["receipt_core"][key] = bad
            res = verify_permit_receipt(request, mutated_receipt, policy, revocation, context)
            rows.append({"case": f"receipt_core_bad_{key}_{idx}", "kind": "receipt", "expected": "DENY", "observed": res.denial_reason_code, "pass": res.decision == DENY})

    # Authenticity field deletion/type fuzz.
    for key in AUTH_REQUIRED:
        mutated_receipt = copy.deepcopy(receipt)
        mutated_receipt["authenticity"].pop(key, None)
        res = verify_permit_receipt(request, mutated_receipt, policy, revocation, context)
        rows.append({"case": f"auth_missing_{key}", "kind": "receipt_authenticity", "expected": "DENY", "observed": res.denial_reason_code, "pass": res.decision == DENY})
        for idx, bad in enumerate(BAD_VALUES):
            mutated_receipt = copy.deepcopy(receipt)
            mutated_receipt["authenticity"][key] = bad
            res = verify_permit_receipt(request, mutated_receipt, policy, revocation, context)
            rows.append({"case": f"auth_bad_{key}_{idx}", "kind": "receipt_authenticity", "expected": "DENY", "observed": res.denial_reason_code, "pass": res.decision == DENY})

    summary = {
        "package": "ORPRG-Eval v3.2 schema-negative fuzzing",
        "synthetic": True,
        "seed": 20260603,
        "cases": len(rows),
        "passed": sum(1 for r in rows if r["pass"]),
        "failed": sum(1 for r in rows if not r["pass"]),
        "denial_codes_observed": sorted(set(str(r["observed"]) for r in rows)),
    }
    (RESULTS / "schema_fuzz_summary.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# Schema-Negative Fuzz Results", "", "Synthetic malformed request/receipt vectors. No production secrets; see license/access terms.", "", f"- Cases: **{summary['cases']}**", f"- Passed: **{summary['passed']}**", f"- Failed: **{summary['failed']}**", "", "## Observed denial codes", ""]
    for code in summary["denial_codes_observed"]:
        md.append(f"- {code}")
    (RESULTS / "schema_fuzz_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
