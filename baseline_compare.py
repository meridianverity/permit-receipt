#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
from orprg_eval.vector_factory import build_vectors
from orprg_eval.verifier import verify_permit_receipt
from orprg_eval.crypto import verify_signature
from orprg_eval.models import ALLOW, DENY

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

def no_gate(v):
    return ALLOW

def session_api_token(v):
    # Session/API-token baseline: if a syntactic receipt/token object exists, allow.
    return ALLOW if isinstance(v.get("permit_receipt"), dict) else DENY

def scope_only_pep(v):
    # PEP/PDP-like baseline: checks a few scope fields but ignores signature, action digest,
    # epoch, revocation, transparency, attestation, and capability-token evidence.
    rec = v.get("permit_receipt")
    if not isinstance(rec, dict) or not isinstance(rec.get("receipt_core"), dict):
        return DENY
    scope = rec["receipt_core"].get("scope", {})
    req = v["request"]
    for k in ("effect_type", "interface_id", "action_type", "target_id", "tenant_id"):
        if k in scope and k in req and scope[k] != req[k]:
            return DENY
    return ALLOW

def signature_epoch_scope_pdp(v):
    # Stronger but still incomplete PDP approximation: checks issuer signature, epoch, validity,
    # and scope, but intentionally ignores action-digest binding, revocation recency, Merkle proofs,
    # assurance evidence, and downstream capability tokens.
    rec = v.get("permit_receipt")
    pol = v.get("policy_state", {})
    req = v.get("request", {})
    if not isinstance(rec, dict) or not isinstance(rec.get("receipt_core"), dict) or not isinstance(rec.get("authenticity"), dict):
        return DENY
    core = rec["receipt_core"]
    issuer = rec["authenticity"].get("issuer_id")
    pub = pol.get("trusted_issuers", {}).get(issuer)
    if not pub or not verify_signature(pub, rec["authenticity"].get("signature", ""), core):
        return DENY
    try:
        if int(core.get("epoch_id")) < int(pol.get("minimum_epoch_id", pol.get("current_epoch_id", 0))):
            return DENY
    except Exception:
        return DENY
    scope = core.get("scope", {})
    for k in ("effect_type", "interface_id", "action_type", "target_id", "tenant_id"):
        if k in scope and k in req and scope[k] != req[k]:
            return DENY
    return ALLOW

def revocation_aware_no_digest_pdp(v):
    # Stronger synthetic comparator: checks signed revocation list freshness superficially but
    # still ignores action-digest binding and capability-token obligations. This illustrates why
    # revocation-aware PDPs are not equivalent to permit-before-commit effect binding.
    pred = signature_epoch_scope_pdp(v)
    if pred == DENY:
        return DENY
    rev = v.get("revocation_state", {})
    signed = rev.get("signed_revocation_list") if isinstance(rev, dict) else None
    if not isinstance(signed, dict) or not isinstance(signed.get("body"), dict):
        return DENY
    if rev.get("status") in {"stale", "missing", "conflicting"}:
        return DENY
    return ALLOW

def bearer_token_ext_authz_baseline(v):
    # Production-adjacent shape, synthetic semantics: an external-authorization
    # service that allows when a bearer/session token is present. It intentionally
    # ignores action digest, PermitReceipt, epoch, revocation, and capability-token
    # proof obligations. This is not a claim about any product.
    return ALLOW if v.get("context", {}).get("session_bearer_token", True) else DENY

def capability_only(v):
    # Capability-token-only comparator: admits any request with a token-like object in context;
    # ignores receipt, issuer, epoch, revocation, and action-digest consistency.
    return ALLOW if isinstance(v.get("context", {}).get("capability_token"), dict) else DENY

def orprg(v):
    r = verify_permit_receipt(v["request"], v["permit_receipt"], v["policy_state"], v["revocation_state"], v["context"])
    return r.decision

def main():
    vectors = build_vectors()
    models = {
        "no_gate": no_gate,
        "session_api_token": session_api_token,
        "scope_only_pep": scope_only_pep,
        "signature_epoch_scope_pdp": signature_epoch_scope_pdp,
        "revocation_aware_no_digest_pdp": revocation_aware_no_digest_pdp,
        "capability_only": capability_only,
        "bearer_token_ext_authz_baseline": bearer_token_ext_authz_baseline,
        "orprg_v3_2_reference": orprg,
    }
    rows = []
    for name, fn in models.items():
        tp = tn = fp = fnn = 0
        mistakes = []
        for v in vectors:
            expected = v["expected"]["decision"]
            pred = fn(v)
            if expected == ALLOW and pred == ALLOW: tp += 1
            elif expected == DENY and pred == DENY: tn += 1
            elif expected == DENY and pred == ALLOW:
                fp += 1; mistakes.append(v["vector_id"])
            elif expected == ALLOW and pred == DENY: fnn += 1
        rows.append({"model": name, "true_allow": tp, "true_deny": tn, "false_allow": fp, "false_deny": fnn, "mistake_examples": mistakes[:12]})
    summary = {"synthetic": True, "baseline_warning": "Baselines are synthetic ablations, not claims about production OPA, Envoy, SPIFFE/SPIRE, IAM, or API gateway products.", "rows": rows}
    (RESULTS / "baseline_compare_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# Synthetic Baseline/Ablation Comparison", "", summary["baseline_warning"], "", "| Model | True allow | True deny | False allow | False deny |", "|---|---:|---:|---:|---:|"]
    for r in rows:
        md.append(f"| {r['model']} | {r['true_allow']} | {r['true_deny']} | {r['false_allow']} | {r['false_deny']} |")
    (RESULTS / "baseline_compare_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
