#!/usr/bin/env python3
"""Production-adjacent baseline matrix for ORPRG-Eval v3.2.

This is a deliberately small, auditable model of common integration shapes:
- API gateway / JWT-like token with scope and expiry;
- OPA-style PDP that evaluates request attributes and revocation freshness;
- Cedar/Zanzibar-like relation/scope check;
- capability-token-only gate;
- ORPRG reference.

It is not a claim about any production implementation. It makes explicit which
proof obligations are absent from each simplified shape.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

CASES = [
    {"id": "valid", "authorized": True, "scope_ok": True, "token_valid": True, "digest_bound": True, "epoch_ok": True, "revocation_fresh": True, "capability_ok": True},
    {"id": "missing-receipt", "authorized": False, "scope_ok": True, "token_valid": True, "digest_bound": False, "epoch_ok": True, "revocation_fresh": True, "capability_ok": True},
    {"id": "action-substitution", "authorized": False, "scope_ok": True, "token_valid": True, "digest_bound": False, "epoch_ok": True, "revocation_fresh": True, "capability_ok": True},
    {"id": "epoch-rollback", "authorized": False, "scope_ok": True, "token_valid": True, "digest_bound": True, "epoch_ok": False, "revocation_fresh": True, "capability_ok": True},
    {"id": "stale-revocation", "authorized": False, "scope_ok": True, "token_valid": True, "digest_bound": True, "epoch_ok": True, "revocation_fresh": False, "capability_ok": True},
    {"id": "broad-scope-wrong-target", "authorized": False, "scope_ok": True, "token_valid": True, "digest_bound": False, "epoch_ok": True, "revocation_fresh": True, "capability_ok": True},
    {"id": "capability-replay", "authorized": False, "scope_ok": True, "token_valid": True, "digest_bound": True, "epoch_ok": True, "revocation_fresh": True, "capability_ok": False},
    {"id": "scope-violation", "authorized": False, "scope_ok": False, "token_valid": True, "digest_bound": True, "epoch_ok": True, "revocation_fresh": True, "capability_ok": True},
    {"id": "token-expired", "authorized": False, "scope_ok": True, "token_valid": False, "digest_bound": True, "epoch_ok": True, "revocation_fresh": True, "capability_ok": True},
    {"id": "ambiguous-policy-context", "authorized": False, "scope_ok": True, "token_valid": True, "digest_bound": True, "epoch_ok": False, "revocation_fresh": False, "capability_ok": True},
]


def api_gateway_token(c: Dict[str, Any]) -> bool:
    return bool(c["token_valid"] and c["scope_ok"])


def opa_style_revocation_pdp(c: Dict[str, Any]) -> bool:
    return bool(c["token_valid"] and c["scope_ok"] and c["revocation_fresh"])


def cedar_zanzibar_scope(c: Dict[str, Any]) -> bool:
    return bool(c["scope_ok"])


def capability_only(c: Dict[str, Any]) -> bool:
    return bool(c["capability_ok"] and c["token_valid"])


def best_effort_pdp_with_digest(c: Dict[str, Any]) -> bool:
    return bool(c["token_valid"] and c["scope_ok"] and c["digest_bound"] and c["revocation_fresh"])


def orprg_reference(c: Dict[str, Any]) -> bool:
    return bool(c["token_valid"] and c["scope_ok"] and c["digest_bound"] and c["epoch_ok"] and c["revocation_fresh"] and c["capability_ok"])


BASELINES: Dict[str, Callable[[Dict[str, Any]], bool]] = {
    "api_gateway_token_scope": api_gateway_token,
    "opa_style_revocation_pdp": opa_style_revocation_pdp,
    "cedar_zanzibar_scope_only": cedar_zanzibar_scope,
    "capability_only": capability_only,
    "best_effort_digest_pdp_no_epoch_capability": best_effort_pdp_with_digest,
    "orprg_reference": orprg_reference,
}


def main() -> int:
    rows: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {"synthetic": True, "cases": len(CASES), "baselines": {}}
    for name, fn in BASELINES.items():
        false_allows = 0; false_denies = 0; correct = 0
        for c in CASES:
            allow = fn(c)
            expected = bool(c["authorized"])
            if allow == expected:
                correct += 1
            elif allow and not expected:
                false_allows += 1
            elif not allow and expected:
                false_denies += 1
            rows.append({"case": c["id"], "model": name, "observed_allow": allow, "expected_allow": expected, "correct": allow == expected})
        summary["baselines"][name] = {"correct": correct, "false_allows": false_allows, "false_denies": false_denies}
    summary["rows"] = rows
    (RESULTS / "standard_policy_baseline_matrix_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# Production-Adjacent Policy Baseline Matrix", "", "Synthetic baseline shapes. These are not claims about production OPA, Cedar, Zanzibar, Envoy, IAM, or KMS deployments.", "", "| Model | Correct | False allows | False denies |", "|---|---:|---:|---:|"]
    for name, vals in summary["baselines"].items():
        md.append(f"| {name} | {vals['correct']} | {vals['false_allows']} | {vals['false_denies']} |")
    (RESULTS / "standard_policy_baseline_matrix_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"cases": summary["cases"], "orprg": summary["baselines"]["orprg_reference"]}, indent=2, sort_keys=True))
    reference = summary["baselines"]["orprg_reference"]
    return 0 if (
        reference["correct"] == summary["cases"]
        and reference["false_allows"] == 0
        and reference["false_denies"] == 0
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
