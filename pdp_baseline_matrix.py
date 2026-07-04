#!/usr/bin/env python3
"""Production-adjacent PDP/PEP-shaped baseline matrix for ORPRG-Eval v3.2.

This file is a self-contained synthetic ablation. It does not invoke production
OPA, Envoy, SPIFFE/SPIRE, cloud IAM, or KMS. The goal is to compare proof
obligations: token-only, scope-only, revocation-aware PDP, capability-only, and
ORPRG reference verifier on the same synthetic oracle vectors.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.verifier import verify_permit_receipt
from orprg_eval.vector_factory import base_context, base_policy, base_request, base_revocation, make_capability, make_receipt, make_revocation_state

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def token_only(req: Mapping[str, Any], receipt: Mapping[str, Any] | None, policy: Mapping[str, Any], revocation: Mapping[str, Any], ctx: Mapping[str, Any]) -> str:
    return ALLOW if ctx.get("session_token") == "synthetic-valid-session" else DENY


def scope_only(req: Mapping[str, Any], receipt: Mapping[str, Any] | None, policy: Mapping[str, Any], revocation: Mapping[str, Any], ctx: Mapping[str, Any]) -> str:
    if not receipt:
        return DENY
    scope = receipt.get("receipt_core", {}).get("scope", {}) if isinstance(receipt, Mapping) else {}
    for key in ("effect_type", "interface_id", "action_type", "target_id", "tenant_id", "purpose_id"):
        if scope.get(key) != req.get(key):
            return DENY
    return ALLOW


def revocation_aware_pdp(req: Mapping[str, Any], receipt: Mapping[str, Any] | None, policy: Mapping[str, Any], revocation: Mapping[str, Any], ctx: Mapping[str, Any]) -> str:
    # Stronger than scope-only, but intentionally does not bind the receipt to a
    # canonical action digest, signature, policy epoch, capability token, or replay domain.
    if scope_only(req, receipt, policy, revocation, ctx) != ALLOW:
        return DENY
    if revocation.get("revoked") or revocation.get("fresh") is False:
        return DENY
    return ALLOW


def capability_only(req: Mapping[str, Any], receipt: Mapping[str, Any] | None, policy: Mapping[str, Any], revocation: Mapping[str, Any], ctx: Mapping[str, Any]) -> str:
    token = ctx.get("capability_token")
    if not isinstance(token, Mapping):
        return DENY
    core = token.get("capability_core", {})
    return ALLOW if core.get("audience") == req.get("interface_id") and core.get("target_id", req.get("target_id")) == req.get("target_id") else DENY


def orprg(req: Mapping[str, Any], receipt: Mapping[str, Any] | None, policy: Mapping[str, Any], revocation: Mapping[str, Any], ctx: Mapping[str, Any]) -> str:
    return verify_permit_receipt(dict(req), receipt, dict(policy), dict(revocation), dict(ctx)).decision


def build_cases() -> list[dict[str, Any]]:
    req = base_request()
    pol = base_policy()
    rec = make_receipt(req, policy=pol, nonce="baseline-matrix-valid")
    cap = make_capability(req, rec, pol, nonce="baseline-matrix-cap")
    ctx = base_context(); ctx["session_token"] = "synthetic-valid-session"
    valid = {"case": "valid_authorized", "request": req, "receipt": rec, "policy": pol, "revocation": base_revocation(rec), "context": {**ctx, "capability_token": cap}, "oracle": ALLOW}

    missing_receipt = {**valid, "case": "missing_receipt", "receipt": None, "oracle": DENY}
    stale_revocation = {**valid, "case": "stale_revocation", "revocation": make_revocation_state(issued_at="2026-06-01T00:00:00Z"), "oracle": DENY}
    substituted = json.loads(json.dumps(valid)); substituted["case"] = "action_substitution"; substituted["request"]["target_id"] = "attacker-target"; substituted["oracle"] = DENY
    epoch_rollback = json.loads(json.dumps(valid)); epoch_rollback["case"] = "epoch_rollback"; epoch_rollback["receipt"] = make_receipt(req, policy=pol, core_overrides={"epoch_id": 46}, nonce="baseline-rollback"); epoch_rollback["revocation"] = base_revocation(epoch_rollback["receipt"]); epoch_rollback["oracle"] = DENY
    invalid_signature = json.loads(json.dumps(valid)); invalid_signature["case"] = "invalid_signature"; invalid_signature["receipt"]["authenticity"]["signature"] = invalid_signature["receipt"]["authenticity"]["signature"][:-8] + "AAAAAAAA"; invalid_signature["oracle"] = DENY
    replay_or_cap_absent = json.loads(json.dumps(valid)); replay_or_cap_absent["case"] = "capability_absent_when_required"; replay_or_cap_absent["policy"]["require_capability_token"] = True; replay_or_cap_absent["context"].pop("capability_token", None); replay_or_cap_absent["oracle"] = DENY
    return [valid, missing_receipt, stale_revocation, substituted, epoch_rollback, invalid_signature, replay_or_cap_absent]


def main() -> None:
    baselines = {
        "token_only": token_only,
        "scope_only": scope_only,
        "revocation_aware_pdp_shape": revocation_aware_pdp,
        "capability_only": capability_only,
        "orprg_reference": orprg,
    }
    rows = []
    aggregate = {name: {"false_allows": 0, "false_denies": 0, "correct": 0} for name in baselines}
    for case in build_cases():
        for name, fn in baselines.items():
            decision = fn(case["request"], case["receipt"], case["policy"], case["revocation"], case["context"])
            oracle = case["oracle"]
            false_allow = decision == ALLOW and oracle == DENY
            false_deny = decision == DENY and oracle == ALLOW
            aggregate[name]["false_allows"] += int(false_allow)
            aggregate[name]["false_denies"] += int(false_deny)
            aggregate[name]["correct"] += int(decision == oracle)
            rows.append({"case": case["case"], "baseline": name, "decision": decision, "oracle": oracle, "false_allow": false_allow, "false_deny": false_deny})
    summary = {"package": "ORPRG-Eval v3.2 PDP/PEP-shaped baseline matrix", "synthetic": True, "cases": len(build_cases()), "baselines": aggregate, "rows": rows, "caveat": "Baselines are synthetic policy shapes, not claims about production OPA, Envoy, SPIFFE/SPIRE, cloud IAM, KMS, or API-gateway products."}
    (RESULTS / "pdp_baseline_matrix_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# PDP/PEP-Shaped Baseline Matrix", "", summary["caveat"], "", "| Baseline | Correct | False allows | False denies |", "|---|---:|---:|---:|"]
    for name, stats in aggregate.items():
        md.append(f"| {name} | {stats['correct']}/{len(build_cases())} | {stats['false_allows']} | {stats['false_denies']} |")
    (RESULTS / "pdp_baseline_matrix_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
