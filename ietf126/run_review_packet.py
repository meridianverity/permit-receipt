#!/usr/bin/env python3
"""IETF 126 public review packet runner for PermitReceipt.

Synthetic-only review artifact. It writes public outputs under ietf126/results/.
It is not production software, not an IETF-operated implementation,
not a certification or conformance service, and grants no patent license.

V2 runner behavior:
- Full-repo mode: uses the repository's orprg_eval package and vector corpus.
- Standalone packet mode: if orprg_eval is unavailable, runs a standard-library
  synthetic evaluator so the IETF packet can still be reviewed from the overlay
  ZIP alone. Standalone mode is deliberately narrow and does not replace the
  full repository evaluation suite.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "ietf126" / "results"
OUT.mkdir(parents=True, exist_ok=True)

AUTH_REF_PROFILE = "orprg.authorization-ref.public-eval.v2"
STANDALONE_PROFILE = "CP-JSON-2"
NOW = "2026-06-03T00:00:00Z"
VALID_FROM = "2026-06-02T00:00:00Z"
VALID_TO = "2026-06-04T00:00:00Z"
EXPIRED_TO = "2026-06-02T00:00:00Z"

try:  # Full-repository mode.
    from orprg_eval.canonicalization import SUPPORTED_PROFILE, canonicalize_request, compute_action_digest, digest_obj
    from orprg_eval.vector_factory import base_context, base_policy, base_request, base_revocation, build_vectors, make_receipt
    from orprg_eval.verifier import verify_permit_receipt
    HAVE_ORPRG_EVAL = True
except Exception as import_error:  # Standalone overlay mode.
    HAVE_ORPRG_EVAL = False
    ORPRG_EVAL_IMPORT_ERROR = repr(import_error)
    SUPPORTED_PROFILE = STANDALONE_PROFILE

SELECTED_NEGATIVES = [
    "KNEG-MISSING-RECEIPT",
    "KNEG-ACTION-DIGEST-MISMATCH",
    "KNEG-SCOPE-VIOLATION-TARGET",
    "KNEG-SCOPE-VIOLATION-BUDGET-OMITTED",
    "KNEG-VALIDITY-EXPIRED",
    "KNEG-REVOCATION-STATE-STALE",
    "KNEG-ANTI-REPLAY-NONCE-REUSE",
    "KNEG-CANONICALIZATION-PROFILE-MISMATCH",
    "KNEG-TRANSPARENCY-PROOF-MISSING",
]

# Standalone mode deliberately mirrors the public DRC registry in
# orprg_eval.models for the selected IETF review packet. Keeping the codes
# here explicit prevents packet-only review from drifting away from the full
# repository verifier.
STANDALONE_DRC = {
    "MISSING_RECEIPT": "DRC-000-MISSING_RECEIPT",
    "EPOCH_MISMATCH": "DRC-003_EPOCH_MISMATCH",
    "VALIDITY_WINDOW_EXPIRED": "DRC-004_VALIDITY_WINDOW_EXPIRED",
    "SCOPE_VIOLATION": "DRC-005_SCOPE_VIOLATION",
    "ANTI_REPLAY_FAILURE": "DRC-006_ANTI_REPLAY_FAILURE",
    "REVOCATION_UNKNOWN_OR_STALE": "DRC-008_REVOCATION_UNKNOWN_OR_STALE",
    "ACTION_DIGEST_MISMATCH": "DRC-009_ACTION_DIGEST_MISMATCH",
    "CANONICALIZATION_PROFILE_MISMATCH": "DRC-016_CANONICALIZATION_PROFILE_MISMATCH",
    "TRANSPARENCY_PROOF_MISSING": "DRC-053_TRANSPARENCY_PROOF_MISSING",
    "POLICY_DIGEST_MISMATCH": "DRC-054_POLICY_DIGEST_MISMATCH",
    "RECEIPT_MALFORMED": "DRC-056_RECEIPT_MALFORMED",
}

def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_standalone(x: Any) -> Any:
    if x is None or isinstance(x, (bool, int)):
        return x
    if isinstance(x, float):
        raise ValueError("CP-JSON-2 rejects floating point inputs")
    if isinstance(x, str):
        return unicodedata.normalize("NFC", x)
    if isinstance(x, list):
        return [_normalize_standalone(v) for v in x]
    if isinstance(x, tuple):
        return [_normalize_standalone(v) for v in x]
    if isinstance(x, Mapping):
        normalized: Dict[str, Any] = {}
        for k, v in x.items():
            nk = unicodedata.normalize("NFC", str(k))
            if nk in normalized:
                raise ValueError(f"duplicate normalized key: {nk}")
            normalized[nk] = _normalize_standalone(v)
        return {k: normalized[k] for k in sorted(normalized)}
    raise ValueError(f"unsupported canonicalization type: {type(x)!r}")


def canonicalize_standalone(obj: Mapping[str, Any], profile: str = STANDALONE_PROFILE) -> bytes:
    if profile != STANDALONE_PROFILE:
        raise ValueError(f"unsupported canonicalization profile {profile}")
    return json.dumps(_normalize_standalone(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_obj_standalone(obj: Mapping[str, Any]) -> str:
    return sha256_hex(canonicalize_standalone(obj))


def base_request_standalone() -> Dict[str, Any]:
    return {
        "effect_type": "DATA_EGRESS",
        "interface_id": "egress-gateway-1",
        "action_type": "POST",
        "target_id": "partner-api-submit",
        "tenant_id": "tenant-A",
        "purpose_id": "support",
        "representation_class_id": "json-v1",
        "max_effect_budget": 10,
        "payload_digest": "payload-synth-001",
    }


def base_scope_standalone() -> Dict[str, Any]:
    return {
        "effect_type": "DATA_EGRESS",
        "interface_id": "egress-gateway-1",
        "action_type": "POST",
        "target_id": "partner-api-submit",
        "tenant_id": "tenant-A",
        "purpose_id": "support",
        "representation_class_id": "json-v1",
        "max_effect_budget": 10,
    }


def base_policy_standalone() -> Dict[str, Any]:
    return {
        "now": NOW,
        "policy_digest": "policy-digest-synth-v12",
        "current_epoch_id": 47,
        "minimum_epoch_id": 47,
        "canonicalization_profile_ref": STANDALONE_PROFILE,
        "trusted_issuers": {"issuer-operator-synth": "public-key-synthetic"},
        "revocation_max_age_seconds": 3600,
        "require_transparency": False,
        "require_permit_provenance": True,
    }


def base_context_standalone() -> Dict[str, Any]:
    return {"now": NOW, "jurisdiction": "US", "resolved_tenant_id": "tenant-A", "used_nonces": []}


def make_receipt_standalone(
    request: Optional[Dict[str, Any]] = None,
    policy: Optional[Dict[str, Any]] = None,
    *,
    core_overrides: Optional[Dict[str, Any]] = None,
    scope: Optional[Dict[str, Any]] = None,
    nonce: str = "nonce-base",
) -> Dict[str, Any]:
    req = copy.deepcopy(request or base_request_standalone())
    pol = copy.deepcopy(policy or base_policy_standalone())
    sc = copy.deepcopy(scope or base_scope_standalone())
    profile = pol.get("canonicalization_profile_ref", STANDALONE_PROFILE)
    action_digest = sha256_hex(canonicalize_standalone(req, profile))
    core: Dict[str, Any] = {
        "receipt_type": "PermitReceipt",
        "policy_digest": pol["policy_digest"],
        "epoch_id": pol["current_epoch_id"],
        "issuer_id": "issuer-operator-synth",
        "valid_from": VALID_FROM,
        "valid_to": VALID_TO,
        "action_digest": action_digest,
        "scope": sc,
        "anti_replay": {"nonce": nonce},
        "tenant_id": sc.get("tenant_id"),
        "purpose_id": sc.get("purpose_id"),
        "canonicalization_profile_ref": profile,
        "permit_provenance_digest": "permit-synth-001",
    }
    if core_overrides:
        core.update(copy.deepcopy(core_overrides))
    return {
        "receipt_core": core,
        "authenticity": {
            "issuer_id": core["issuer_id"],
            "signature_coverage": "receipt_core",
            "signature": sha256_hex(("synthetic-signature:" + digest_obj_standalone(core)).encode("utf-8")),
        },
    }


def base_revocation_standalone(receipt: Optional[Dict[str, Any]] = None, *, status: str = "fresh") -> Dict[str, Any]:
    return {
        "status": status,
        "last_updated": "2026-06-02T23:59:40Z",
        "signed_revocation_list": {
            "body": {"issuer_id": "revocation-authority-synth", "revoked_receipt_digests": [], "revoked_issuers": []},
            "authenticity": {"issuer_id": "revocation-authority-synth", "signature_coverage": "body"},
        },
    }


def verify_standalone(
    request: Dict[str, Any],
    receipt: Optional[Dict[str, Any]],
    policy_state: Dict[str, Any],
    revocation_state: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    def deny(code: str) -> Dict[str, Any]:
        return {"decision": "DENY", "denial_reason_code": code, "evidence_digests": {}}

    if not receipt:
        return deny(STANDALONE_DRC["MISSING_RECEIPT"])
    if not isinstance(receipt, dict) or "receipt_core" not in receipt or "authenticity" not in receipt:
        return deny(STANDALONE_DRC["RECEIPT_MALFORMED"])
    core = receipt["receipt_core"]
    profile = core.get("canonicalization_profile_ref")
    if profile != policy_state.get("canonicalization_profile_ref", STANDALONE_PROFILE):
        return deny(STANDALONE_DRC["CANONICALIZATION_PROFILE_MISMATCH"])
    try:
        observed_digest = sha256_hex(canonicalize_standalone(request, profile))
    except Exception:
        return deny(STANDALONE_DRC["CANONICALIZATION_PROFILE_MISMATCH"])
    if observed_digest != core.get("action_digest"):
        return deny(STANDALONE_DRC["ACTION_DIGEST_MISMATCH"])
    if core.get("policy_digest") != policy_state.get("policy_digest"):
        return deny(STANDALONE_DRC["POLICY_DIGEST_MISMATCH"])
    if int(core.get("epoch_id", -1)) != int(policy_state.get("current_epoch_id", -2)):
        return deny(STANDALONE_DRC["EPOCH_MISMATCH"])
    if core.get("valid_to") <= context.get("now", NOW) or core.get("valid_from") > context.get("now", NOW):
        return deny(STANDALONE_DRC["VALIDITY_WINDOW_EXPIRED"])
    scope = core.get("scope", {})
    for field in ["effect_type", "interface_id", "action_type", "target_id", "tenant_id", "purpose_id", "representation_class_id"]:
        if scope.get(field) is not None and request.get(field) != scope.get(field):
            return deny(STANDALONE_DRC["SCOPE_VIOLATION"])
    if "max_effect_budget" in scope:
        if "max_effect_budget" not in request:
            return deny(STANDALONE_DRC["SCOPE_VIOLATION"])
        try:
            if request.get("max_effect_budget", 0) > scope.get("max_effect_budget", 0):
                return deny(STANDALONE_DRC["SCOPE_VIOLATION"])
        except TypeError:
            return deny(STANDALONE_DRC["SCOPE_VIOLATION"])
    nonce = (core.get("anti_replay") or {}).get("nonce")
    if nonce in set(context.get("used_nonces", [])):
        return deny(STANDALONE_DRC["ANTI_REPLAY_FAILURE"])
    if revocation_state.get("status") != "fresh":
        return deny(STANDALONE_DRC["REVOCATION_UNKNOWN_OR_STALE"])
    if policy_state.get("require_transparency") and not revocation_state.get("merkle"):
        return deny(STANDALONE_DRC["TRANSPARENCY_PROOF_MISSING"])
    return {"decision": "ALLOW", "denial_reason_code": None, "evidence_digests": {}}


def build_selected_vectors_standalone() -> List[Dict[str, Any]]:
    req = base_request_standalone()
    pol = base_policy_standalone()
    base_rec = make_receipt_standalone(req, pol, nonce="nonce-standalone")
    vectors: List[Dict[str, Any]] = []

    def add(vector_id: str, description: str, expected_code: str, *, request=None, receipt="DEFAULT", policy=None, revocation=None, context=None, invariant="IETF126") -> None:
        request_obj = copy.deepcopy(request or req)
        receipt_obj = make_receipt_standalone(request_obj, policy or pol, nonce=f"nonce-{vector_id}") if receipt == "DEFAULT" else copy.deepcopy(receipt)
        vectors.append({
            "vector_id": vector_id,
            "category": "standalone-negative",
            "description": description,
            "invariant": invariant,
            "request": request_obj,
            "permit_receipt": receipt_obj,
            "policy_state": copy.deepcopy(policy or pol),
            "revocation_state": copy.deepcopy(revocation or base_revocation_standalone(receipt_obj if isinstance(receipt_obj, dict) else None)),
            "context": copy.deepcopy(context or base_context_standalone()),
            "expected": {"decision": "DENY", "denial_reason_code": expected_code},
        })

    add("KNEG-MISSING-RECEIPT", "External effect without PermitReceipt is denied.", STANDALONE_DRC["MISSING_RECEIPT"], receipt=None)
    wrong_req = copy.deepcopy(req); wrong_req["target_id"] = "attacker-exfil-api"
    add("KNEG-ACTION-DIGEST-MISMATCH", "Receipt binds a different action digest.", STANDALONE_DRC["ACTION_DIGEST_MISMATCH"], receipt=make_receipt_standalone(wrong_req, nonce="wrong-action"))
    scope = base_scope_standalone(); scope["target_id"] = "approved-only"
    add("KNEG-SCOPE-VIOLATION-TARGET", "Receipt scope excludes requested target.", STANDALONE_DRC["SCOPE_VIOLATION"], receipt=make_receipt_standalone(req, scope=scope, nonce="scope-target"))
    req_no_budget = copy.deepcopy(req); req_no_budget.pop("max_effect_budget", None)
    scope = base_scope_standalone()
    add("KNEG-SCOPE-VIOLATION-BUDGET-OMITTED", "Receipt scope constrains max_effect_budget, so omission by the request fails closed.", STANDALONE_DRC["SCOPE_VIOLATION"], request=req_no_budget, receipt=make_receipt_standalone(req_no_budget, scope=scope, nonce="scope-budget-omitted"))
    add("KNEG-VALIDITY-EXPIRED", "Receipt validity window is expired.", STANDALONE_DRC["VALIDITY_WINDOW_EXPIRED"], receipt=make_receipt_standalone(req, core_overrides={"valid_to": EXPIRED_TO}, nonce="expired"))
    add("KNEG-REVOCATION-STATE-STALE", "Revocation/status evidence is stale.", STANDALONE_DRC["REVOCATION_UNKNOWN_OR_STALE"], revocation=base_revocation_standalone(base_rec, status="stale"))
    add("KNEG-ANTI-REPLAY-NONCE-REUSE", "Receipt nonce reuse is denied.", STANDALONE_DRC["ANTI_REPLAY_FAILURE"], receipt=base_rec, context={**base_context_standalone(), "used_nonces": ["nonce-standalone"]})
    add("KNEG-CANONICALIZATION-PROFILE-MISMATCH", "Unsupported canonicalization profile is denied.", STANDALONE_DRC["CANONICALIZATION_PROFILE_MISMATCH"], receipt=make_receipt_standalone(req, core_overrides={"canonicalization_profile_ref": "CP-OLD"}, nonce="canon"))
    pol_t = copy.deepcopy(pol); pol_t["require_transparency"] = True
    add("KNEG-TRANSPARENCY-PROOF-MISSING", "Required transparency proof is missing.", STANDALONE_DRC["TRANSPARENCY_PROOF_MISSING"], policy=pol_t)
    return vectors


def crossref_decision(ref: Any, *, expected_action_commitment: str, supported_profile: str) -> Dict[str, Any]:
    """Public-eval shape checker for signature-covered authorization references.

    This is intentionally not a cryptographic signature implementation. It checks
    whether a downstream artifact exposes the minimum verifier-readable,
    signature-covered reference shape needed for ORPRG interop review. Actual
    signature validation remains the job of the carrying artifact and/or the
    referenced artifact.
    """
    if not isinstance(ref, dict):
        return {"decision": "DENY", "reason": "AUTHREF_NOT_AN_OBJECT"}
    if ("action_id" in ref or "action_type" in ref) and "protected_action_commitment" not in ref:
        return {"decision": "DENY", "reason": "AUTHREF_NAME_ONLY_NON_AUTHORIZING"}
    required = [
        "ref_profile",
        "reference_kind",
        "artifact_digest",
        "issuer_id",
        "digest_algorithm",
        "canonicalization_profile_ref",
        "domain_sep",
        "protected_action_commitment",
        "signature_coverage",
        "failure_behavior",
    ]
    missing = [k for k in required if k not in ref]
    if missing:
        return {"decision": "DENY", "reason": "AUTHREF_REQUIRED_FIELD_MISSING", "missing": missing}
    if ref.get("ref_profile") != AUTH_REF_PROFILE:
        return {"decision": "DENY", "reason": "AUTHREF_PROFILE_UNSUPPORTED"}
    if ref.get("signature_coverage") is not True:
        return {"decision": "DENY", "reason": "AUTHREF_NOT_SIGNATURE_COVERED"}
    if ref.get("digest_algorithm") != "sha-256":
        return {"decision": "DENY", "reason": "AUTHREF_DIGEST_ALGORITHM_UNSUPPORTED"}
    if ref.get("canonicalization_profile_ref") != supported_profile:
        return {"decision": "DENY", "reason": "AUTHREF_CANONICALIZATION_PROFILE_UNSUPPORTED"}
    if ref.get("protected_action_commitment") != expected_action_commitment:
        return {"decision": "DENY", "reason": "AUTHREF_PROTECTED_ACTION_COMMITMENT_MISMATCH"}
    if ref.get("status") == "stale":
        return {"decision": "DENY", "reason": "AUTHREF_STATUS_STALE"}
    return {"decision": "BOUND", "reason": None}


def make_authorization_ref(receipt: Dict[str, Any], action_digest: str, *, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    core = receipt["receipt_core"]
    if HAVE_ORPRG_EVAL:
        artifact_digest = digest_obj(core)
    else:
        artifact_digest = digest_obj_standalone(core)
    ref: Dict[str, Any] = {
        "ref_profile": AUTH_REF_PROFILE,
        "reference_kind": "PermitReceipt",
        "artifact_digest": artifact_digest,
        "issuer_id": receipt["authenticity"]["issuer_id"],
        "digest_algorithm": "sha-256",
        "canonicalization_profile_ref": core.get("canonicalization_profile_ref", SUPPORTED_PROFILE),
        "domain_sep": None,
        "protected_action_commitment": action_digest,
        "scope": {
            "effect_type": core.get("scope", {}).get("effect_type"),
            "interface_id": core.get("scope", {}).get("interface_id"),
            "target_id": core.get("scope", {}).get("target_id"),
            "tenant_id": core.get("tenant_id"),
            "purpose_id": core.get("purpose_id"),
        },
        "validity": {"valid_from": core.get("valid_from"), "valid_to": core.get("valid_to")},
        "epoch_id": core.get("epoch_id"),
        "anti_replay": core.get("anti_replay"),
        "signature_coverage": True,
        "failure_behavior": "DENY when unsupported, mismatched, stale, replayed, or unverifiable",
        "status": "fresh",
        "note": "Public-eval shape. Field names are not a wire-profile requirement.",
    }
    if overrides:
        ref.update(overrides)
    return ref


def main() -> int:
    runner_mode = "full-repository" if HAVE_ORPRG_EVAL else "standalone-ietf-packet"
    if HAVE_ORPRG_EVAL:
        request = base_request()
        policy_state = base_policy()
        context = base_context()
        receipt = make_receipt(request, policy_state, nonce="nonce-IETF126-ONE-PROTECTED-ACTION")
        revocation_state = base_revocation(receipt)
        canonical_bytes = canonicalize_request(request, SUPPORTED_PROFILE)
        canonical_text = canonical_bytes.decode("utf-8")
        action_digest = compute_action_digest(canonical_bytes)
        verifier_result = verify_permit_receipt(request, receipt, policy_state, revocation_state, context).to_dict()
        receipt_core_digest = digest_obj(receipt["receipt_core"])
        signed_revocation_list_digest = digest_obj(revocation_state["signed_revocation_list"]["body"])
        vector_map = {v["vector_id"]: v for v in build_vectors()}
        selected_vectors = [vector_map[v] for v in SELECTED_NEGATIVES]
    else:
        request = base_request_standalone()
        policy_state = base_policy_standalone()
        context = base_context_standalone()
        receipt = make_receipt_standalone(request, policy_state, nonce="nonce-IETF126-ONE-PROTECTED-ACTION")
        revocation_state = base_revocation_standalone(receipt)
        canonical_bytes = canonicalize_standalone(request, STANDALONE_PROFILE)
        canonical_text = canonical_bytes.decode("utf-8")
        action_digest = sha256_hex(canonical_bytes)
        verifier_result = verify_standalone(request, receipt, policy_state, revocation_state, context)
        receipt_core_digest = digest_obj_standalone(receipt["receipt_core"])
        signed_revocation_list_digest = digest_obj_standalone(revocation_state["signed_revocation_list"]["body"])
        selected_vectors = build_selected_vectors_standalone()

    authorization_ref = make_authorization_ref(receipt, action_digest)
    authorization_ref_result = crossref_decision(authorization_ref, expected_action_commitment=action_digest, supported_profile=SUPPORTED_PROFILE)

    one_action: Dict[str, Any] = {
        "packet": "IETF126-ORPRG-one-protected-action-v2",
        "runner_mode": runner_mode,
        "synthetic": True,
        "public_boundary": "Synthetic public artifact only; no production credentials, no live payment, no customer data, no regulated data.",
        "canonicalization_profile_ref": SUPPORTED_PROFILE,
        "digest_algorithm": "sha-256",
        "domain_sep": None,
        "request": request,
        "canonical_request_utf8": canonical_text,
        "canonical_request_hex": canonical_bytes.hex(),
        "canonical_request_length_bytes": len(canonical_bytes),
        "action_digest": action_digest,
        "permit_receipt_core_digest": receipt_core_digest,
        "permit_receipt": receipt,
        "policy_state_public_subset": {
            "policy_digest": policy_state["policy_digest"],
            "current_epoch_id": policy_state["current_epoch_id"],
            "minimum_epoch_id": policy_state.get("minimum_epoch_id"),
            "canonicalization_profile_ref": policy_state["canonicalization_profile_ref"],
        },
        "revocation_state_public_subset": {
            "status": revocation_state["status"],
            "last_updated": revocation_state["last_updated"],
            "signed_revocation_list_digest": signed_revocation_list_digest,
        },
        "verifier_result": verifier_result,
        "authorization_ref_sample": authorization_ref,
        "authorization_ref_sample_result": authorization_ref_result,
    }
    if not HAVE_ORPRG_EVAL:
        one_action["standalone_note"] = "orprg_eval package was not importable; ran the standard-library IETF packet evaluator. Apply this overlay to the full permit-receipt repo to run the full public vector corpus."
        one_action["orprg_eval_import_error"] = ORPRG_EVAL_IMPORT_ERROR

    write_json(OUT / "one-protected-action.json", one_action)
    (OUT / "canonical-request.bytes.txt").write_text(canonical_text + "\n", encoding="utf-8")
    (OUT / "canonical-request.hex.txt").write_text(canonical_bytes.hex() + "\n", encoding="utf-8")
    write_json(OUT / "positive-path.json", {
        "vector_id": "IETF126-ONE-PROTECTED-ACTION",
        "runner_mode": runner_mode,
        "decision": verifier_result["decision"],
        "pass": verifier_result["decision"] == "ALLOW",
        "action_digest": action_digest,
        "permit_receipt_core_digest": receipt_core_digest,
    })

    negative_results: List[Dict[str, Any]] = []
    for vector in selected_vectors:
        if HAVE_ORPRG_EVAL:
            observed = verify_permit_receipt(
                vector["request"],
                vector["permit_receipt"],
                vector["policy_state"],
                vector["revocation_state"],
                vector["context"],
            ).to_dict()
        else:
            observed = verify_standalone(
                vector["request"],
                vector["permit_receipt"],
                vector["policy_state"],
                vector["revocation_state"],
                vector["context"],
            )
        expected = vector["expected"]
        passed = observed["decision"] == expected["decision"] and observed.get("denial_reason_code") == expected.get("denial_reason_code")
        negative_results.append({
            "vector_id": vector["vector_id"],
            "category": vector["category"],
            "description": vector["description"],
            "invariant": vector["invariant"],
            "expected": expected,
            "observed": observed,
            "pass": passed,
        })
    write_json(OUT / "negative-vector-results.json", {"runner_mode": runner_mode, "selected_negative_vectors": negative_results})

    crossref_cases = [
        {
            "case_id": "AUTHREF-POS-SIGNATURE-COVERED",
            "description": "Signature-covered authorization_ref commits to the ORPRG protected-action commitment.",
            "ref": authorization_ref,
            "expected_decision": "BOUND",
        },
        {
            "case_id": "AUTHREF-NEG-NAME-ONLY",
            "description": "action_id/action_type without a protected-action commitment is naming-level only.",
            "ref": {"action_id": "synthetic-action-001", "action_type": "POST"},
            "expected_decision": "DENY",
        },
        {
            "case_id": "AUTHREF-NEG-UNSIGNED-METADATA",
            "description": "Out-of-band metadata not covered by signature is non-authorizing.",
            "ref": make_authorization_ref(receipt, action_digest, overrides={"signature_coverage": False}),
            "expected_decision": "DENY",
        },
        {
            "case_id": "AUTHREF-NEG-COMMITMENT-MISMATCH",
            "description": "Reference commits to a different protected action.",
            "ref": make_authorization_ref(receipt, "sha256:deadbeef", overrides={}),
            "expected_decision": "DENY",
        },
        {
            "case_id": "AUTHREF-NEG-UNSUPPORTED-PROFILE",
            "description": "Unsupported cross-reference profile fails closed.",
            "ref": make_authorization_ref(receipt, action_digest, overrides={"ref_profile": "example.unsupported.profile"}),
            "expected_decision": "DENY",
        },
        {
            "case_id": "AUTHREF-NEG-STALE-STATUS",
            "description": "Stale referenced status/evidence marker fails closed.",
            "ref": make_authorization_ref(receipt, action_digest, overrides={"status": "stale"}),
            "expected_decision": "DENY",
        },
        {
            "case_id": "AUTHREF-NEG-UNSUPPORTED-CANONICALIZATION-PROFILE",
            "description": "Unsupported canonicalization profile in the reference fails closed.",
            "ref": make_authorization_ref(receipt, action_digest, overrides={"canonicalization_profile_ref": "CP-UNDECLARED"}),
            "expected_decision": "DENY",
        },
    ]
    crossref_results: List[Dict[str, Any]] = []
    for case in crossref_cases:
        observed = crossref_decision(case["ref"], expected_action_commitment=action_digest, supported_profile=SUPPORTED_PROFILE)
        passed = observed["decision"] == case["expected_decision"]
        crossref_results.append({
            "case_id": case["case_id"],
            "description": case["description"],
            "expected_decision": case["expected_decision"],
            "observed": observed,
            "pass": passed,
        })
    write_json(OUT / "interop-crossref-results.json", {
        "profile": AUTH_REF_PROFILE,
        "runner_mode": runner_mode,
        "status": "public-evaluation shape check; not a wire-format standard",
        "primary_model": "signature-covered cross-reference first; byte-identical digest equality only when test vectors prove it",
        "results": crossref_results,
    })

    positive_pass = verifier_result["decision"] == "ALLOW"
    negative_pass = sum(1 for row in negative_results if row["pass"])
    crossref_pass = sum(1 for row in crossref_results if row["pass"])
    total = 1 + len(negative_results) + len(crossref_results)
    passed = int(positive_pass) + negative_pass + crossref_pass

    passport = {
        "packet": "IETF126-ORPRG-public-review-passport-v2",
        "runner_mode": runner_mode,
        "synthetic": True,
        "ok": passed == total,
        "passed": passed,
        "total": total,
        "positive_path_pass": positive_pass,
        "selected_negative_vectors_passed": negative_pass,
        "selected_negative_vectors_total": len(negative_results),
        "interop_crossref_checks_passed": crossref_pass,
        "interop_crossref_checks_total": len(crossref_results),
        "action_digest": action_digest,
        "canonicalization_profile_ref": SUPPORTED_PROFILE,
        "domain_sep": None,
        "outputs": [
            "one-protected-action.json",
            "canonical-request.bytes.txt",
            "canonical-request.hex.txt",
            "positive-path.json",
            "negative-vector-results.json",
            "interop-crossref-results.json",
            "review-summary.md",
        ],
        "public_boundary": "No production data, no customer data, no regulated data, no live payments, no certification service, no conformance service, no legal/commercial position, no patent license by publication.",
    }
    write_json(OUT / "public-review-passport.json", passport)

    summary = [
        "# IETF 126 PermitReceipt Review Summary",
        "",
        "Synthetic public review packet. No production secrets, no customer data, no regulated data, no live payment, no wallet, issuer, PSP, network-token, or settlement-rail function.",
        "",
        f"- Runner mode: `{runner_mode}`",
        f"- One protected-action positive path: {'PASS' if positive_pass else 'FAIL'}",
        f"- Selected executable negative vectors: {negative_pass} / {len(negative_results)} PASS",
        f"- Interop authorization_ref shape checks: {crossref_pass} / {len(crossref_results)} PASS",
        f"- Overall selected packet: {passed} / {total} PASS",
        "",
        "## One protected action",
        "",
        f"- canonicalization_profile_ref: `{SUPPORTED_PROFILE}`",
        "- domain_sep: `null` in this synthetic profile; interop uses signature-covered cross-references unless byte equality is proven",
        f"- canonical_request_length_bytes: `{len(canonical_bytes)}`",
        f"- action_digest: `{action_digest}`",
        f"- permit_receipt_core_digest: `{receipt_core_digest}`",
        "",
        "## Selected negative vectors",
        "",
        "| Vector | Expected | Observed | Reason | Pass |",
        "|---|---|---|---|---:|",
    ]
    for row in negative_results:
        summary.append(f"| {row['vector_id']} | {row['expected']['decision']} | {row['observed']['decision']} | {row['observed'].get('denial_reason_code') or ''} | {row['pass']} |")
    summary.extend([
        "",
        "## Signature-covered authorization reference checks",
        "",
        "| Case | Expected | Observed | Reason | Pass |",
        "|---|---|---|---|---:|",
    ])
    for row in crossref_results:
        summary.append(f"| {row['case_id']} | {row['expected_decision']} | {row['observed']['decision']} | {row['observed'].get('reason') or ''} | {row['pass']} |")
    summary.extend([
        "",
        "## Public boundary",
        "",
        "This output is a public technical review artifact only. It is not production software, not an IETF-operated implementation, not a certification service, not a conformance service, not a legal/commercial position, and grants no patent license.",
    ])
    (OUT / "review-summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")

    print(json.dumps({"ok": passed == total, "passed": passed, "total": total, "runner_mode": runner_mode, "output_dir": str(OUT.relative_to(ROOT))}, indent=2, sort_keys=True))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
