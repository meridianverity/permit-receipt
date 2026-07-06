"""Synthetic evaluation-vector generator for ORPRG-Eval v3.2."""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Dict, List, Optional

from .canonicalization import SUPPORTED_PROFILE, digest_obj, canonicalize_request, compute_action_digest
from .crypto import deterministic_private_key, public_key_b64, sign_object
from .merkle import build_inclusion_proof, build_non_inclusion_proof, entry_key, revocation_entry, sign_checkpoint
from .models import ALLOW, DENY, DRC
from .verifier import issue_capability_token, issue_receipt, make_capability_core, make_receipt_core

NOW = "2026-06-03T00:00:00Z"
VALID_FROM = "2026-06-02T00:00:00Z"
VALID_TO = "2026-06-04T00:00:00Z"
EXPIRED_TO = "2026-06-02T00:00:00Z"
FUTURE_FROM = "2026-06-04T00:00:00Z"
OLD = "2026-06-01T00:00:00Z"

ISSUER_ID = "issuer-operator-synth"
ROGUE_ID = "issuer-rogue-synth"
REVOCATION_ID = "revocation-authority-synth"
LOG_ID = "revocation-log-synth"
CAP_ID = "capability-issuer-synth"

ISSUER_KEY = deterministic_private_key(ISSUER_ID)
ROGUE_KEY = deterministic_private_key(ROGUE_ID)
REVOCATION_KEY = deterministic_private_key(REVOCATION_ID)
LOG_KEY = deterministic_private_key(LOG_ID)
CAP_KEY = deterministic_private_key(CAP_ID)

ISSUER_PUB = public_key_b64(ISSUER_KEY)
ROGUE_PUB = public_key_b64(ROGUE_KEY)
REVOCATION_PUB = public_key_b64(REVOCATION_KEY)
LOG_PUB = public_key_b64(LOG_KEY)
CAP_PUB = public_key_b64(CAP_KEY)


def base_request() -> Dict[str, Any]:
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


def base_scope() -> Dict[str, Any]:
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


def base_policy() -> Dict[str, Any]:
    return {
        "now": NOW,
        "policy_digest": "policy-digest-synth-v12",
        "current_epoch_id": 47,
        "minimum_epoch_id": 47,
        "epoch_compatibility": "strict",
        "canonicalization_profile_ref": SUPPORTED_PROFILE,
        "trusted_issuers": {ISSUER_ID: ISSUER_PUB},
        "revocation_authorities": {REVOCATION_ID: REVOCATION_PUB},
        "transparency_logs": {LOG_ID: LOG_PUB},
        "trusted_capability_issuers": {CAP_ID: CAP_PUB},
        "max_clock_drift_seconds": 300,
        "revocation_max_age_seconds": 3600,
        "checkpoint_max_age_seconds": 3600,
        "require_signed_revocation_list": True,
        "require_merkle_revocation_proof": False,
        "require_transparency": False,
        "require_purpose": False,
        "require_identity_binding": False,
        "require_permit_provenance": True,
        "require_assurance_evidence": False,
        "require_capability_token": False,
        "offline_constrained_mode_allowed": False,
        "offline_constrained_effect_types": [],
    }


def base_context() -> Dict[str, Any]:
    return {"now": NOW, "jurisdiction": "US", "resolved_tenant_id": "tenant-A", "used_nonces": [], "used_capability_nonces": []}


def sign_revocation_list(revoked_receipts=None, revoked_issuers=None, issued_at: str = "2026-06-02T23:59:40Z", sequence: int = 100) -> Dict[str, Any]:
    body = {
        "issuer_id": REVOCATION_ID,
        "issued_at": issued_at,
        "sequence": sequence,
        "revoked_receipt_digests": sorted(list(revoked_receipts or [])),
        "revoked_issuers": sorted(list(revoked_issuers or [])),
    }
    return {"body": body, "authenticity": {"issuer_id": REVOCATION_ID, "signature": sign_object(REVOCATION_KEY, body)}}


def make_revocation_state(revoked_receipts=None, revoked_issuers=None, issued_at: str = "2026-06-02T23:59:40Z", status: str = "fresh") -> Dict[str, Any]:
    return {"status": status, "last_updated": issued_at, "signed_revocation_list": sign_revocation_list(revoked_receipts, revoked_issuers, issued_at)}


def add_merkle_proofs(state: Dict[str, Any], receipt: Dict[str, Any], issuer_id: str = ISSUER_ID, checkpoint_at: str = "2026-06-02T23:59:40Z", sequence: int = 100) -> Dict[str, Any]:
    state = deepcopy(state)
    receipt_digest = digest_obj(receipt["receipt_core"])
    body = state["signed_revocation_list"]["body"]
    entries = [revocation_entry("receipt", d) for d in body.get("revoked_receipt_digests", [])]
    entries += [revocation_entry("issuer", i) for i in body.get("revoked_issuers", [])]
    signed_cp = sign_checkpoint(LOG_KEY, log_id=LOG_ID, sequence=sequence, issued_at=checkpoint_at, entries=entries)
    receipt_key = entry_key("receipt", receipt_digest)
    issuer_key = entry_key("issuer", issuer_id)
    if receipt_digest in set(body.get("revoked_receipt_digests", [])):
        receipt_proof = build_inclusion_proof(entries, receipt_key)
    else:
        receipt_proof = build_non_inclusion_proof(entries, receipt_key)
    if issuer_id in set(body.get("revoked_issuers", [])):
        issuer_proof = build_inclusion_proof(entries, issuer_key)
    else:
        issuer_proof = build_non_inclusion_proof(entries, issuer_key)
    state["merkle"] = {"signed_checkpoint": signed_cp, "receipt_proof": receipt_proof, "issuer_proof": issuer_proof}
    return state


def base_revocation(receipt: Optional[Dict[str, Any]] = None, merkle: bool = False) -> Dict[str, Any]:
    state = make_revocation_state()
    if merkle and receipt is not None:
        state = add_merkle_proofs(state, receipt)
    return state


def make_receipt(request: Optional[Dict[str, Any]] = None, policy: Optional[Dict[str, Any]] = None, *, core_overrides: Optional[Dict[str, Any]] = None, scope: Optional[Dict[str, Any]] = None, key=ISSUER_KEY, issuer_id: str = ISSUER_ID, nonce: str = "nonce-base", permit_provenance_digest: Optional[str] = "permit-synth-001", extras: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    req = deepcopy(request or base_request())
    pol = deepcopy(policy or base_policy())
    sc = deepcopy(scope or base_scope())
    core = make_receipt_core(
        req,
        policy_digest=pol["policy_digest"],
        epoch_id=int(pol["current_epoch_id"]),
        issuer_id=issuer_id,
        valid_from=VALID_FROM,
        valid_to=VALID_TO,
        scope=sc,
        nonce=nonce,
        canonicalization_profile_ref=pol.get("canonicalization_profile_ref", SUPPORTED_PROFILE),
        permit_provenance_digest=permit_provenance_digest,
        tenant_id=sc.get("tenant_id", "tenant-A"),
        purpose_id=sc.get("purpose_id", "support"),
        extras=extras,
    )
    if core_overrides:
        core.update(deepcopy(core_overrides))
    return issue_receipt(core, key)


def make_capability(request: Dict[str, Any], receipt: Dict[str, Any], policy: Optional[Dict[str, Any]] = None, *, nonce="cap-nonce-base", valid_to: str = VALID_TO, key=CAP_KEY, issuer_id=CAP_ID, core_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    pol = policy or base_policy()
    core = make_capability_core(request=request, receipt_core=receipt["receipt_core"], policy_digest=pol["policy_digest"], valid_to=valid_to, nonce=nonce)
    if core_overrides:
        core.update(deepcopy(core_overrides))
    return issue_capability_token(core, key, issuer_id)


def _v(vector_id: str, description: str, invariant: str, expected_decision: str, expected_code: Optional[str], *, request=None, receipt="DEFAULT", policy_state=None, revocation_state=None, context=None, category="core") -> Dict[str, Any]:
    req = deepcopy(request or base_request())
    rec = make_receipt(req, nonce=f"nonce-{vector_id}") if receipt == "DEFAULT" else deepcopy(receipt)
    rev = deepcopy(revocation_state if revocation_state is not None else base_revocation(rec if isinstance(rec, dict) else None))
    return {
        "vector_id": vector_id,
        "category": category,
        "description": description,
        "invariant": invariant,
        "request": req,
        "permit_receipt": rec,
        "policy_state": deepcopy(policy_state or base_policy()),
        "revocation_state": rev,
        "context": deepcopy(context or base_context()),
        "expected": {"decision": expected_decision, "denial_reason_code": expected_code},
    }


def build_vectors() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # Positive controls.
    out.append(_v("KPOS-BASELINE-ALLOW", "Valid receipt, signed revocation list, current epoch, exact action.", "I1/I2/I3/I4/I5", ALLOW, None, category="positive"))

    pol_merkle = base_policy(); pol_merkle["require_merkle_revocation_proof"] = True; pol_merkle["require_transparency"] = True
    req = base_request(); rec = make_receipt(req, policy=pol_merkle, nonce="nonce-KPOS-MERKLE")
    out.append(_v("KPOS-MERKLE-NON-INCLUSION-ALLOW", "Valid signed checkpoint plus receipt/issuer non-inclusion proofs allow.", "I4", ALLOW, None, request=req, receipt=rec, policy_state=pol_merkle, revocation_state=add_merkle_proofs(make_revocation_state(), rec), category="positive"))

    pol_cap = base_policy(); pol_cap["require_capability_token"] = True
    req = base_request(); rec = make_receipt(req, policy=pol_cap, nonce="nonce-KPOS-CAP")
    cap = make_capability(req, rec, pol_cap, nonce="cap-KPOS")
    ctx = base_context(); ctx["capability_token"] = cap
    out.append(_v("KPOS-SIGNED-CAPABILITY-ALLOW", "Valid audience-bound signed capability token allows dual-enforcement path.", "I6", ALLOW, None, request=req, receipt=rec, policy_state=pol_cap, context=ctx, category="positive"))

    # Core negative tests.
    out.append(_v("KNEG-MISSING-RECEIPT", "External effect without PermitReceipt is denied.", "I1", DENY, DRC["MISSING_RECEIPT"], receipt=None))
    out.append(_v("KNEG-MALFORMED-RECEIPT", "Receipt envelope missing receipt_core/authenticity.", "I1", DENY, DRC["RECEIPT_MALFORMED"], receipt={"bad": True}))
    req_bad = base_request(); del req_bad["target_id"]
    out.append(_v("KNEG-REQUEST-SCHEMA-MISSING-FIELD", "Missing authorization-critical request field is denied.", "I7", DENY, DRC["SCHEMA_VALIDATION_FAILURE"], request=req_bad, receipt=None, category="schema"))
    rec_bad = make_receipt(nonce="schema-missing"); del rec_bad["receipt_core"]["policy_digest"]
    out.append(_v("KNEG-RECEIPT-SCHEMA-MISSING-FIELD", "Missing required receipt_core field is denied before commit.", "I1/I7", DENY, DRC["SCHEMA_VALIDATION_FAILURE"], receipt=rec_bad, category="schema"))

    r = make_receipt(nonce="bad-sig"); r["authenticity"]["signature"] = r["authenticity"]["signature"][:-8] + "AAAAAAAA"
    out.append(_v("KNEG-SIGNATURE-INVALID", "Receipt signature verification fails.", "I1", DENY, DRC["SIGNATURE_INVALID"], receipt=r))
    r = make_receipt(nonce="issuer-mismatch"); r["authenticity"]["issuer_id"] = ROGUE_ID
    out.append(_v("KNEG-AUTH-ISSUER-MISMATCH", "Receipt core issuer and authenticity issuer disagree.", "I5", DENY, DRC["SIGNATURE_INVALID"], receipt=r))
    r = make_receipt(issuer_id=ROGUE_ID, key=ROGUE_KEY, nonce="rogue")
    out.append(_v("KNEG-ISSUER-UNTRUSTED", "Receipt issuer is outside trusted authority profile.", "I5", DENY, DRC["ISSUER_UNTRUSTED"], receipt=r))
    out.append(_v("KNEG-POLICY-DIGEST-MISMATCH", "Receipt policy digest does not match current policy.", "I3", DENY, DRC["POLICY_DIGEST_MISMATCH"], receipt=make_receipt(core_overrides={"policy_digest": "old-policy"}, nonce="policy-mismatch")))
    out.append(_v("KNEG-VALIDITY-EXPIRED", "Receipt validity window is expired.", "I4", DENY, DRC["VALIDITY_WINDOW_EXPIRED"], receipt=make_receipt(core_overrides={"valid_to": EXPIRED_TO}, nonce="expired")))
    out.append(_v("KNEG-VALIDITY-FUTURE", "Receipt is not yet valid.", "I4", DENY, DRC["VALIDITY_WINDOW_EXPIRED"], receipt=make_receipt(core_overrides={"valid_from": FUTURE_FROM}, nonce="future")))

    wrong_req = base_request(); wrong_req["target_id"] = "attacker-exfil-api"
    out.append(_v("KNEG-ACTION-DIGEST-MISMATCH", "Receipt binds a different action digest.", "I2", DENY, DRC["ACTION_DIGEST_MISMATCH"], receipt=make_receipt(wrong_req, nonce="wrong-action")))
    out.append(_v("KNEG-CANONICALIZATION-PROFILE-MISMATCH", "Receipt canonicalization profile is not the active profile.", "I2/I7", DENY, DRC["CANONICALIZATION_PROFILE_MISMATCH"], receipt=make_receipt(core_overrides={"canonicalization_profile_ref": "CP-OLD"}, nonce="canon")))
    req_float = base_request(); req_float["max_effect_budget"] = 10.5
    out.append(_v("KNEG-CANONICALIZATION-FLOAT-REJECTED", "Floating-point request field is rejected by CP-JSON-2.", "I2/I7", DENY, DRC["CANONICALIZATION_PROFILE_MISMATCH"], request=req_float, receipt=None, category="canonicalization"))

    scope = base_scope(); scope["target_id"] = "approved-only"
    out.append(_v("KNEG-SCOPE-VIOLATION-TARGET", "Receipt scope excludes requested target.", "I5", DENY, DRC["SCOPE_VIOLATION"], receipt=make_receipt(scope=scope, nonce="scope-target")))
    req_budget_omitted = base_request(); del req_budget_omitted["max_effect_budget"]
    out.append(_v("KNEG-SCOPE-VIOLATION-BUDGET-OMITTED", "Receipt scope requires max_effect_budget but request omits it.", "I5", DENY, DRC["SCOPE_VIOLATION"], request=req_budget_omitted, receipt=make_receipt(req_budget_omitted, scope=base_scope(), nonce="scope-budget-omitted")))
    scope = base_scope(); scope["max_effect_budget"] = 5
    out.append(_v("KNEG-SCOPE-VIOLATION-BUDGET", "Requested effect budget exceeds receipt scope.", "I5", DENY, DRC["SCOPE_VIOLATION"], receipt=make_receipt(scope=scope, nonce="scope-budget")))
    reqB = base_request(); reqB["tenant_id"] = "tenant-B"
    recB = make_receipt(reqB, scope={**base_scope(), "tenant_id": "tenant-B"}, core_overrides={"tenant_id": "tenant-A"}, nonce="tenant-core")
    ctxB = base_context(); ctxB["resolved_tenant_id"] = "tenant-B"
    out.append(_v("KNEG-TENANT-MISMATCH-CORE", "Resolved tenant differs from receipt tenant binding.", "I5/I7", DENY, DRC["TENANT_MISMATCH"], request=reqB, receipt=recB, context=ctxB))
    reqB2 = base_request(); reqB2["tenant_id"] = "tenant-B"
    scopeA = base_scope(); scopeA["tenant_id"] = "tenant-A"
    out.append(_v("KNEG-TENANT-MISMATCH-SCOPE", "Receipt scope tenant differs from request tenant.", "I5", DENY, DRC["TENANT_MISMATCH"], request=reqB2, receipt=make_receipt(reqB2, scope=scopeA, core_overrides={"tenant_id":"tenant-B"}, nonce="tenant-scope")))
    pol_purpose = base_policy(); pol_purpose["require_purpose"] = True
    ctx = base_context(); ctx["purpose_id"] = "clinical-care"
    out.append(_v("KNEG-PURPOSE-OUT-OF-SCOPE", "Purpose binding is required and mismatched.", "I5", DENY, DRC["PURPOSE_OUT_OF_SCOPE_OR_MISSING"], receipt=make_receipt(core_overrides={"purpose_id": "marketing"}, nonce="purpose"), policy_state=pol_purpose, context=ctx))
    req_repr = base_request(); req_repr["representation_class_id"] = "xml-v0"
    out.append(_v("KNEG-REPRESENTATION-CLASS-VIOLATION", "Representation class differs from authorized class.", "I5", DENY, DRC["REPRESENTATION_CLASS_VIOLATION"], request=req_repr, receipt=make_receipt(req_repr, scope=base_scope(), core_overrides={"tenant_id":"tenant-A"}, nonce="repr")))
    pol_ident = base_policy(); pol_ident["require_identity_binding"] = True
    out.append(_v("KNEG-IDENTITY-BINDING-MISMATCH", "Required identity binding does not match context.", "I5", DENY, DRC["IDENTITY_BINDING_MISMATCH"], receipt=make_receipt(core_overrides={"identity_binding": {"workload":"agent-A"}}, nonce="idbind"), policy_state=pol_ident, context={**base_context(), "identity_binding": {"workload":"agent-B"}}))
    out.append(_v("KNEG-JURISDICTION-AMBIGUOUS", "Authorization-critical jurisdiction ambiguity denies.", "I7", DENY, DRC["JURISDICTION_CONTEXT_INDETERMINATE_OR_CONFLICT"], context={**base_context(), "jurisdiction_ambiguous": True}))
    out.append(_v("KNEG-JURISDICTION-CONFLICT", "Receipt jurisdiction and context conflict.", "I7", DENY, DRC["JURISDICTION_CONTEXT_INDETERMINATE_OR_CONFLICT"], receipt=make_receipt(core_overrides={"jurisdiction":"EU"}, nonce="juris"), context=base_context()))
    out.append(_v("KNEG-AUTHORITY-PROFILE-AMBIGUOUS", "Ambiguous authority profile selection denies.", "I7", DENY, DRC["AUTHORITY_PROFILE_SELECTION_FAILED"], context={**base_context(), "authority_profile_ambiguous": True}))
    out.append(_v("KNEG-PERMIT-PROVENANCE-MISSING", "Required permit provenance digest is missing.", "I5", DENY, DRC["PERMIT_PROVENANCE_INVALID_OR_MISSING"], receipt=make_receipt(permit_provenance_digest=None, nonce="prov")))
    pol_assurance = base_policy(); pol_assurance["require_assurance_evidence"] = True
    out.append(_v("KNEG-ASSURANCE-EVIDENCE-MISSING", "Required assurance evidence is missing.", "I5", DENY, DRC["ASSURANCE_PROFILE_NOT_SATISFIED"], policy_state=pol_assurance))
    out.append(_v("KNEG-ATTESTATION-MISSING", "Required attestation is absent for high-risk egress.", "I5", DENY, DRC["ATTESTATION_FAILURE"], context={**base_context(), "attestation_required": True, "attestation_present": False}))
    out.append(_v("KNEG-ATTESTATION-STALE", "Attestation nonce/freshness check fails.", "I4", DENY, DRC["ATTESTATION_STALE"], context={**base_context(), "attestation_required": True, "attestation_stale": True}))
    out.append(_v("KNEG-TIME-SOURCE-UNTRUSTED", "Time source is untrusted.", "I4/I7", DENY, DRC["TIME_SOURCE_UNTRUSTED_OR_DRIFT"], context={**base_context(), "time_source_untrusted": True}))
    out.append(_v("KNEG-CLOCK-DRIFT", "Clock drift exceeds policy bound.", "I4", DENY, DRC["TIME_SOURCE_UNTRUSTED_OR_DRIFT"], context={**base_context(), "clock_drift_seconds": 9999}))
    out.append(_v("KNEG-EPOCH-MISMATCH", "Receipt epoch is not current under strict compatibility.", "I3", DENY, DRC["EPOCH_MISMATCH"], receipt=make_receipt(core_overrides={"epoch_id": 48}, nonce="epoch-mismatch")))
    out.append(_v("KNEG-EPOCH-ROLLBACK", "Receipt epoch is below minimum epoch.", "I3", DENY, DRC["EPOCH_ROLLBACK_ATTEMPT"], receipt=make_receipt(core_overrides={"epoch_id": 46}, nonce="epoch-rollback")))
    out.append(_v("KNEG-EPOCH-SPLIT-BRAIN", "Epoch sources conflict.", "I3/I7", DENY, DRC["EPOCH_ROLLBACK_ATTEMPT"], context={**base_context(), "epoch_sources": [47, 46]}))

    # Revocation, Merkle, transparency.
    out.append(_v("KNEG-REVOCATION-STATE-STALE", "Revocation status is explicitly stale.", "I4", DENY, DRC["REVOCATION_UNKNOWN_OR_STALE"], revocation_state={"status":"stale", "last_updated":OLD}))
    out.append(_v("KNEG-REVOCATION-STATE-MISSING", "Revocation status is unavailable.", "I4", DENY, DRC["REVOCATION_UNKNOWN_OR_STALE"], revocation_state={"status":"missing"}))
    state_bad_sig = make_revocation_state(); state_bad_sig["signed_revocation_list"]["authenticity"]["signature"] = "AAAA" + state_bad_sig["signed_revocation_list"]["authenticity"]["signature"][4:]
    out.append(_v("KNEG-REVOCATION-LIST-SIGNATURE-INVALID", "Signed revocation list signature fails.", "I4", DENY, DRC["REVOCATION_SIGNATURE_INVALID"], revocation_state=state_bad_sig, category="revocation"))
    rec = make_receipt(nonce="revoked-receipt"); state = make_revocation_state(revoked_receipts=[digest_obj(rec["receipt_core"])])
    out.append(_v("KNEG-REVOCATION-CONFIRMED-RECEIPT", "Signed revocation list revokes receipt digest.", "I4", DENY, DRC["REVOKED_CONFIRMED"], receipt=rec, revocation_state=state, category="revocation"))
    state = make_revocation_state(revoked_issuers=[ISSUER_ID])
    out.append(_v("KNEG-REVOCATION-CONFIRMED-ISSUER", "Signed revocation list revokes issuer credential.", "I4", DENY, DRC["REVOKED_CONFIRMED"], revocation_state=state, category="revocation"))
    state_old = make_revocation_state(issued_at=OLD)
    out.append(_v("KNEG-REVOCATION-LIST-AGE-EXCEEDED", "Signed revocation list age exceeds recency threshold.", "I4", DENY, DRC["REVOCATION_UNKNOWN_OR_STALE"], revocation_state=state_old, category="revocation"))
    polM = base_policy(); polM["require_merkle_revocation_proof"] = True; polM["require_transparency"] = True
    recM = make_receipt(policy=polM, nonce="merkle-missing")
    out.append(_v("KNEG-MERKLE-PROOF-MISSING", "Policy requires Merkle proof but no proof is supplied.", "I4", DENY, DRC["TRANSPARENCY_PROOF_MISSING"], receipt=recM, policy_state=polM, revocation_state=make_revocation_state(), category="merkle"))
    state = add_merkle_proofs(make_revocation_state(), recM); state["merkle"]["signed_checkpoint"]["signature"] = "BBBB" + state["merkle"]["signed_checkpoint"]["signature"][4:]
    out.append(_v("KNEG-MERKLE-CHECKPOINT-SIGNATURE-INVALID", "Signed checkpoint signature fails.", "I4", DENY, DRC["SIGNED_CHECKPOINT_INVALID"], receipt=recM, policy_state=polM, revocation_state=state, category="merkle"))
    state = add_merkle_proofs(make_revocation_state(), recM, checkpoint_at=OLD)
    out.append(_v("KNEG-MERKLE-CHECKPOINT-STALE", "Signed checkpoint is stale.", "I4", DENY, DRC["REVOCATION_UNKNOWN_OR_STALE"], receipt=recM, policy_state=polM, revocation_state=state, category="merkle"))
    state = add_merkle_proofs(make_revocation_state(), recM); state["merkle"]["receipt_proof"]["target_key"] = "receipt:wrong"
    out.append(_v("KNEG-MERKLE-NON-INCLUSION-TARGET-MISMATCH", "Non-inclusion proof targets a different digest.", "I4", DENY, DRC["NON_INCLUSION_PROOF_INVALID"], receipt=recM, policy_state=polM, revocation_state=state, category="merkle"))
    state = add_merkle_proofs(make_revocation_state(revoked_receipts=["some-other-digest"]), recM); state["merkle"]["receipt_proof"].setdefault("prev", {}).setdefault("audit_path", [])
    if state["merkle"]["receipt_proof"].get("prev", {}).get("audit_path"):
        state["merkle"]["receipt_proof"]["prev"]["audit_path"][0]["hash"] = "00" * 32
    else:
        state["merkle"]["receipt_proof"]["target_key"] = "receipt:corrupt"
    out.append(_v("KNEG-MERKLE-AUDIT-PATH-INVALID", "Merkle proof path is corrupted.", "I4", DENY, DRC["NON_INCLUSION_PROOF_INVALID"], receipt=recM, policy_state=polM, revocation_state=state, category="merkle"))
    recRev = make_receipt(policy=polM, nonce="merkle-revoked-receipt"); state = add_merkle_proofs(make_revocation_state(revoked_receipts=[digest_obj(recRev["receipt_core"])]), recRev)
    out.append(_v("KNEG-MERKLE-REVOKED-RECEIPT-INCLUSION", "Merkle inclusion proof confirms receipt revocation.", "I4", DENY, DRC["REVOKED_CONFIRMED"], receipt=recRev, policy_state=polM, revocation_state=state, category="merkle"))
    recRevI = make_receipt(policy=polM, nonce="merkle-revoked-issuer"); state = add_merkle_proofs(make_revocation_state(revoked_issuers=[ISSUER_ID]), recRevI)
    out.append(_v("KNEG-MERKLE-REVOKED-ISSUER-INCLUSION", "Merkle inclusion proof confirms issuer revocation.", "I4", DENY, DRC["REVOKED_CONFIRMED"], receipt=recRevI, policy_state=polM, revocation_state=state, category="merkle"))
    polT = base_policy(); polT["require_transparency"] = True
    out.append(_v("KNEG-TRANSPARENCY-PROOF-MISSING", "Transparency is required but no anchor/proof is supplied.", "I4", DENY, DRC["TRANSPARENCY_PROOF_MISSING"], policy_state=polT, category="transparency"))
    out.append(_v("KNEG-TRANSPARENCY-PROOF-INVALID", "Transparency proof is supplied but invalid.", "I4", DENY, DRC["TRANSPARENCY_PROOF_INVALID"], policy_state=polT, context={**base_context(), "transparency_proof_present": True, "transparency_proof_valid": False}, category="transparency"))
    out.append(_v("KNEG-CROSS-LOG-CONFLICT", "Cross-log coherence conflict denies.", "I4/I7", DENY, DRC["CROSS_LOG_COHERENCE_NOT_SATISFIED"], revocation_state={"status":"conflicting"}, category="transparency"))

    # Replay and specialized interfaces.
    out.append(_v("KNEG-ANTI-REPLAY-NONCE-REUSE", "Receipt nonce was already used.", "I8", DENY, DRC["ANTI_REPLAY_FAILURE"], receipt=make_receipt(nonce="used-nonce"), context={**base_context(), "used_nonces": ["used-nonce"]}, category="replay"))
    reqKey = {**base_request(), "effect_type": "KEY_RELEASE", "interface_id": "kms-1", "action_type": "KEY_OP", "target_id": "kms:key/123", "key_id": "kms:key/123", "key_op": "SIGN"}
    scopeKey = {**base_scope(), "effect_type": "KEY_RELEASE", "interface_id": "kms-1", "action_type":"KEY_OP", "target_id":"kms:key/123", "tenant_id":"tenant-A", "key_id":"kms:key/123", "key_ops":["DECRYPT"]}
    out.append(_v("KNEG-KEY-RELEASE-OP-OUT-OF-SCOPE", "KMS key operation differs from authorized key_ops.", "I5/I6", DENY, DRC["KEY_RELEASE_DENIED"], request=reqKey, receipt=make_receipt(reqKey, scope=scopeKey, nonce="keyscope"), category="key_gate"))
    reqKey2 = {**reqKey, "key_op":"DECRYPT"}; scopeKey2 = {**scopeKey, "key_ops":["DECRYPT"]}
    out.append(_v("KNEG-KEY-RELEASE-ATTESTATION-MISSING", "KMS gate requires attestation and none is present.", "I5/I6", DENY, DRC["KEY_RELEASE_DENIED"], request=reqKey2, receipt=make_receipt(reqKey2, scope=scopeKey2, nonce="keyattest"), context={**base_context(), "attestation_required": True, "attestation_present": False}, category="key_gate"))

    # Capability-token negatives.
    polC = base_policy(); polC["require_capability_token"] = True
    reqC = base_request(); recC = make_receipt(reqC, policy=polC, nonce="cap-base")
    out.append(_v("KNEG-CAPABILITY-MISSING", "Downstream capability token required but absent.", "I6", DENY, DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"], request=reqC, receipt=recC, policy_state=polC, category="capability"))
    cap = make_capability(reqC, recC, polC, nonce="cap-invalid-sig"); cap["authenticity"]["signature"] = "CCCC" + cap["authenticity"]["signature"][4:]
    out.append(_v("KNEG-CAPABILITY-SIGNATURE-INVALID", "Capability token signature fails.", "I6", DENY, DRC["CAPABILITY_SIGNATURE_INVALID"], request=reqC, receipt=recC, policy_state=polC, context={**base_context(), "capability_token": cap}, category="capability"))
    cap = make_capability(reqC, recC, polC, nonce="cap-aud", core_overrides={"audience":"other-gateway"})
    out.append(_v("KNEG-CAPABILITY-AUDIENCE-MISMATCH", "Capability token is audience-bound to another interface.", "I6", DENY, DRC["CAPABILITY_AUDIENCE_MISMATCH"], request=reqC, receipt=recC, policy_state=polC, context={**base_context(), "capability_token": cap}, category="capability"))
    cap = make_capability(reqC, recC, polC, nonce="cap-exp", valid_to=EXPIRED_TO)
    out.append(_v("KNEG-CAPABILITY-EXPIRED", "Capability token validity window expired.", "I6", DENY, DRC["CAPABILITY_EXPIRED"], request=reqC, receipt=recC, policy_state=polC, context={**base_context(), "capability_token": cap}, category="capability"))
    cap = make_capability(reqC, recC, polC, nonce="cap-replay")
    out.append(_v("KNEG-CAPABILITY-REPLAY", "Capability token nonce was already used.", "I6/I8", DENY, DRC["CAPABILITY_REPLAY"], request=reqC, receipt=recC, policy_state=polC, context={**base_context(), "capability_token": cap, "used_capability_nonces":["cap-replay"]}, category="capability"))
    cap = make_capability(reqC, recC, polC, nonce="cap-action", core_overrides={"action_digest":"00"*32})
    out.append(_v("KNEG-CAPABILITY-ACTION-MISMATCH", "Capability token action digest differs from request.", "I6", DENY, DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"], request=reqC, receipt=recC, policy_state=polC, context={**base_context(), "capability_token": cap}, category="capability"))
    cap = make_capability(reqC, recC, polC, nonce="cap-tenant", core_overrides={"tenant_id":"tenant-B"})
    out.append(_v("KNEG-CAPABILITY-TENANT-MISMATCH", "Capability token tenant binding differs from request.", "I6", DENY, DRC["TENANT_MISMATCH"], request=reqC, receipt=recC, policy_state=polC, context={**base_context(), "capability_token": cap}, category="capability"))

    # Offline/partition semantics.
    polOff = base_policy(); polOff["offline_constrained_mode_allowed"] = True; polOff["offline_constrained_effect_types"] = ["SAFETY_HEARTBEAT"]
    reqSafe = {**base_request(), "effect_type":"SAFETY_HEARTBEAT", "interface_id":"safety-bus-1", "action_type":"PUBLISH", "target_id":"heartbeat", "representation_class_id":"json-v1"}
    scopeSafe = {**base_scope(), "effect_type":"SAFETY_HEARTBEAT", "interface_id":"safety-bus-1", "action_type":"PUBLISH", "target_id":"heartbeat"}
    out.append(_v("KPOS-OFFLINE-CONSTRAINED-ALLOW", "Partitioned node allows only explicitly constrained safety heartbeat.", "I9", ALLOW, None, request=reqSafe, receipt=make_receipt(reqSafe, policy=polOff, scope=scopeSafe, nonce="offline-allow"), policy_state=polOff, revocation_state={"status":"missing"}, context={**base_context(), "partitioned": True}, category="partition"))
    out.append(_v("KNEG-OFFLINE-NONCONSTRAINED-DENY", "Partitioned node denies non-constrained data egress.", "I9", DENY, DRC["CONSTRAINED_MODE_DENIAL"], policy_state=polOff, revocation_state={"status":"missing"}, context={**base_context(), "partitioned": True}, category="partition"))

    # Extension/schema edge.
    reqExt = {**base_request(), "effect_type":"EXTENSION_INSTALL", "interface_id":"ext-market-1", "action_type":"INSTALL", "target_id":"ext:pub/tool@1.0"}
    # artifact_id intentionally missing -> schema fail.
    out.append(_v("KNEG-EXTENSION-SCHEMA-MISSING-ARTIFACT", "Extension install request without artifact_id is denied.", "I7", DENY, DRC["SCHEMA_VALIDATION_FAILURE"], request=reqExt, receipt=None, category="schema"))

    return out
