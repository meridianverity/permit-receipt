"""ORPRG-Eval v3.2 synthetic reference verifier.

This verifier implements executable, synthetic versions of the ORPRG semantics:
canonicalized action digests, PermitReceipt signature checks, epoch binding,
revocation recency, signed revocation lists, Merkle inclusion/non-inclusion
proofs, replay checks, scope checks, and signed capability-token validation.
"""
from __future__ import annotations
from datetime import datetime, timezone
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from .canonicalization import CanonicalizationError, SUPPORTED_PROFILE, canonicalize_request, compute_action_digest, digest_obj
from .crypto import sign_object, verify_signature
from .merkle import entry_key, verify_inclusion_proof, verify_non_inclusion_proof, verify_signed_checkpoint
from .models import ALLOW, DENY, DRC, VerifyResult
from .schema import validate_request_schema, validate_receipt_schema


def parse_time(s: str) -> datetime:
    return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc)


def _finish_timings(timings: Dict[str, int]) -> Dict[str, int]:
    if "total_ns" not in timings:
        start = timings.pop("start_ns")
        timings["total_ns"] = time.perf_counter_ns() - start
    return timings


def deny(code: str, evidence: Dict[str, Any], recency: Dict[str, Any], timings: Dict[str, int]) -> VerifyResult:
    return VerifyResult(DENY, code, evidence, recency, _finish_timings(timings))


def allow(evidence: Dict[str, Any], recency: Dict[str, Any], timings: Dict[str, int], constrained: bool = False) -> VerifyResult:
    return VerifyResult(ALLOW, None, evidence, recency, _finish_timings(timings), constrained_mode=constrained)


def issue_receipt(core: Mapping[str, Any], priv) -> Dict[str, Any]:
    return {"receipt_core": dict(core), "authenticity": {"issuer_id": core["issuer_id"], "signature": sign_object(priv, core)}}


def make_receipt_core(request: Mapping[str, Any], *, policy_digest: str, epoch_id: int, issuer_id: str, valid_from: str, valid_to: str, scope: Mapping[str, Any], nonce: str, canonicalization_profile_ref: str = SUPPORTED_PROFILE, authority_profile_id: str = "AP-SYNTH-AL5", assurance_level_id: str = "AL5", permit_provenance_digest: Optional[str] = "permit-synth-001", tenant_id: Optional[str] = "tenant-A", purpose_id: Optional[str] = "support", jurisdiction: Optional[str] = "US", extras: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    canonical = canonicalize_request(request, canonicalization_profile_ref)
    core: Dict[str, Any] = {
        "policy_digest": policy_digest,
        "epoch_id": epoch_id,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "action_digest": compute_action_digest(canonical),
        "scope": dict(scope),
        "anti_replay": {"nonce": nonce},
        "canonicalization_profile_ref": canonicalization_profile_ref,
        "authority_profile_id": authority_profile_id,
        "assurance_level_id": assurance_level_id,
        "issuer_id": issuer_id,
    }
    if permit_provenance_digest is not None:
        core["permit_provenance_digest"] = permit_provenance_digest
    if tenant_id is not None:
        core["tenant_id"] = tenant_id
    if purpose_id is not None:
        core["purpose_id"] = purpose_id
    if jurisdiction is not None:
        core["jurisdiction"] = jurisdiction
    if extras:
        core.update(dict(extras))
    return core


def issue_capability_token(core: Mapping[str, Any], priv, issuer_id: str = "cap-issuer") -> Dict[str, Any]:
    return {"token_core": dict(core), "authenticity": {"issuer_id": issuer_id, "signature": sign_object(priv, core)}}


def make_capability_core(*, request: Mapping[str, Any], receipt_core: Mapping[str, Any], policy_digest: str, valid_to: str, nonce: str = "cap-nonce-1") -> Dict[str, Any]:
    canonical = canonicalize_request(request, receipt_core.get("canonicalization_profile_ref", SUPPORTED_PROFILE))
    action_digest = compute_action_digest(canonical)
    return {
        "action_digest": action_digest,
        "receipt_digest": digest_obj(receipt_core),
        "policy_digest": policy_digest,
        "epoch_id": receipt_core["epoch_id"],
        "audience": request.get("interface_id"),
        "tenant_id": request.get("tenant_id"),
        "valid_to": valid_to,
        "nonce": nonce,
    }


def _scope_code(request: Mapping[str, Any], scope: Mapping[str, Any]) -> Optional[str]:
    if scope.get("tenant_id") and request.get("tenant_id") and scope["tenant_id"] != request["tenant_id"]:
        return DRC["TENANT_MISMATCH"]
    if scope.get("purpose_id") and request.get("purpose_id") != scope["purpose_id"]:
        return DRC["PURPOSE_OUT_OF_SCOPE_OR_MISSING"]
    if scope.get("representation_class_id") and request.get("representation_class_id") != scope["representation_class_id"]:
        return DRC["REPRESENTATION_CLASS_VIOLATION"]
    for key in ("effect_type", "interface_id", "action_type", "target_id", "artifact_id", "key_id", "key_op"):
        if key in scope and scope[key] is not None and request.get(key) != scope[key]:
            return DRC["KEY_RELEASE_DENIED"] if request.get("effect_type") == "KEY_RELEASE" else DRC["SCOPE_VIOLATION"]
    if "key_ops" in scope and request.get("key_op") not in set(scope["key_ops"]):
        return DRC["KEY_RELEASE_DENIED"]
    if "max_effect_budget" in scope:
        if "max_effect_budget" not in request:
            return DRC["SCOPE_VIOLATION"]
        if int(request["max_effect_budget"]) > int(scope["max_effect_budget"]):
            return DRC["SCOPE_VIOLATION"]
    return None


def _verify_signed_revocation_list(revocation_state: Mapping[str, Any], policy_state: Mapping[str, Any], evidence: Dict[str, Any], recency: Dict[str, Any], now: datetime) -> Tuple[Optional[str], Dict[str, Any]]:
    """Return (denial_code, list_body). None denial means the list verified."""
    signed = revocation_state.get("signed_revocation_list")
    if not signed:
        return DRC["REVOCATION_UNKNOWN_OR_STALE"], {}
    body = signed.get("body") if isinstance(signed, Mapping) else None
    auth = signed.get("authenticity") if isinstance(signed, Mapping) else None
    if not isinstance(body, Mapping) or not isinstance(auth, Mapping):
        return DRC["REVOCATION_UNKNOWN_OR_STALE"], {}
    pub = policy_state.get("revocation_authorities", {}).get(auth.get("issuer_id"))
    if not pub:
        return DRC["REVOCATION_SIGNATURE_INVALID"], dict(body)
    if not verify_signature(pub, auth.get("signature", ""), body):
        return DRC["REVOCATION_SIGNATURE_INVALID"], dict(body)
    evidence["revocation_list_digest"] = digest_obj(body)
    issued_at = parse_time(body.get("issued_at", revocation_state.get("last_updated", policy_state["now"])))
    age = int((now - issued_at).total_seconds())
    recency["revocation_list_age_seconds"] = age
    recency["revocation_max_age_seconds"] = int(policy_state.get("revocation_max_age_seconds", 3600))
    if age < 0 or age > recency["revocation_max_age_seconds"]:
        return DRC["REVOCATION_UNKNOWN_OR_STALE"], dict(body)
    return None, dict(body)


def _verify_merkle_revocation_proofs(revocation_state: Mapping[str, Any], policy_state: Mapping[str, Any], evidence: Dict[str, Any], recency: Dict[str, Any], now: datetime, receipt_digest: str, issuer_id: str) -> Optional[str]:
    merkle = revocation_state.get("merkle")
    if not isinstance(merkle, Mapping):
        return DRC["TRANSPARENCY_PROOF_MISSING"]
    signed_cp = merkle.get("signed_checkpoint")
    if not isinstance(signed_cp, Mapping):
        return DRC["TRANSPARENCY_PROOF_MISSING"]
    log_id = signed_cp.get("checkpoint", {}).get("log_id")
    log_pub = policy_state.get("transparency_logs", {}).get(log_id)
    if not log_pub or not verify_signed_checkpoint(signed_cp, log_pub):
        return DRC["SIGNED_CHECKPOINT_INVALID"]
    cp = signed_cp["checkpoint"]
    evidence["revocation_checkpoint_digest"] = digest_obj(cp)
    issued_at = parse_time(cp.get("issued_at", policy_state["now"]))
    age = int((now - issued_at).total_seconds())
    recency["checkpoint_age_seconds"] = age
    recency["checkpoint_max_age_seconds"] = int(policy_state.get("checkpoint_max_age_seconds", policy_state.get("revocation_max_age_seconds", 3600)))
    if age < 0 or age > recency["checkpoint_max_age_seconds"]:
        return DRC["REVOCATION_UNKNOWN_OR_STALE"]
    root = cp["root_hash"]
    for target_kind, target_id, proof_name in (("receipt", receipt_digest, "receipt_proof"), ("issuer", issuer_id, "issuer_proof")):
        proof = merkle.get(proof_name)
        if not isinstance(proof, Mapping):
            return DRC["MERKLE_INCLUSION_REQUIRED_BUT_MISSING"]
        if proof.get("proof_type") == "inclusion":
            if not verify_inclusion_proof(proof, root):
                return DRC["TRANSPARENCY_PROOF_INVALID"]
            if proof["entry"].get("key") == entry_key(target_kind, target_id):
                return DRC["REVOKED_CONFIRMED"]
            return DRC["TRANSPARENCY_PROOF_INVALID"]
        if proof.get("proof_type") == "non_inclusion":
            if proof.get("target_key") != entry_key(target_kind, target_id):
                return DRC["NON_INCLUSION_PROOF_INVALID"]
            if not verify_non_inclusion_proof(proof, root):
                return DRC["NON_INCLUSION_PROOF_INVALID"]
        else:
            return DRC["TRANSPARENCY_PROOF_INVALID"]
    return None


def verify_capability_token(request: Mapping[str, Any], token: Optional[Mapping[str, Any]], policy_state: Mapping[str, Any], context: Mapping[str, Any], evidence: Dict[str, Any], now: Optional[datetime] = None) -> Optional[str]:
    if not isinstance(token, Mapping):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    core = token.get("token_core")
    auth = token.get("authenticity")
    if not isinstance(core, Mapping) or not isinstance(auth, Mapping):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    issuer_id = auth.get("issuer_id")
    pub = policy_state.get("trusted_capability_issuers", {}).get(issuer_id)
    if not pub:
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if not verify_signature(pub, auth.get("signature", ""), core):
        return DRC["CAPABILITY_SIGNATURE_INVALID"]
    token_digest = digest_obj(core)
    evidence["capability_token_digest"] = token_digest
    if now is None:
        now = parse_time(context.get("now", policy_state["now"]))
    if parse_time(core.get("valid_to")) < now:
        return DRC["CAPABILITY_EXPIRED"]
    canonical = canonicalize_request(request, request.get("canonicalization_profile_ref", SUPPORTED_PROFILE))
    action_digest = compute_action_digest(canonical)
    if core.get("action_digest") != action_digest:
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if core.get("audience") != request.get("interface_id"):
        return DRC["CAPABILITY_AUDIENCE_MISMATCH"]
    if core.get("tenant_id") != request.get("tenant_id"):
        return DRC["TENANT_MISMATCH"]
    if core.get("policy_digest") != policy_state.get("policy_digest"):
        return DRC["POLICY_DIGEST_MISMATCH"]
    if int(core.get("epoch_id", -1)) != int(policy_state.get("current_epoch_id")):
        return DRC["EPOCH_MISMATCH"]
    nonce = core.get("nonce")
    replay_cache = context.get("capability_replay_cache")
    if replay_cache is not None and nonce:
        if not replay_cache.check_and_mark("capability", str(nonce)):
            return DRC["CAPABILITY_REPLAY"]
    elif nonce and nonce in set(context.get("used_capability_nonces", [])):
        return DRC["CAPABILITY_REPLAY"]
    return None


def verify_permit_receipt(request: Mapping[str, Any], receipt: Optional[Mapping[str, Any]], policy_state: Mapping[str, Any], revocation_state: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> VerifyResult:
    context = dict(context or {})
    timings: Dict[str, int] = {"start_ns": time.perf_counter_ns()}
    evidence: Dict[str, Any] = {}
    recency: Dict[str, Any] = {}

    schema_code = validate_request_schema(request)
    if schema_code:
        return deny(schema_code, evidence, recency, timings)

    t0 = time.perf_counter_ns()
    profile = context.get("canonicalization_profile_ref", policy_state.get("canonicalization_profile_ref", SUPPORTED_PROFILE))
    try:
        canonical = canonicalize_request(request, profile)
        evidence["action_digest"] = compute_action_digest(canonical)
    except CanonicalizationError:
        timings["canonicalization_and_digest_ns"] = time.perf_counter_ns() - t0
        return deny(DRC["CANONICALIZATION_PROFILE_MISMATCH"], evidence, recency, timings)
    timings["canonicalization_and_digest_ns"] = time.perf_counter_ns() - t0

    if receipt is None:
        return deny(DRC["MISSING_RECEIPT"], evidence, recency, timings)
    schema_code = validate_receipt_schema(receipt)
    if schema_code:
        return deny(schema_code, evidence, recency, timings)
    core = receipt["receipt_core"]
    auth = receipt["authenticity"]

    try:
        receipt_digest = digest_obj(core)
    except Exception:
        return deny(DRC["SCHEMA_VALIDATION_FAILURE"], evidence, recency, timings)
    evidence.update({
        "receipt_digest": receipt_digest,
        "policy_digest": core.get("policy_digest"),
        "epoch_id": core.get("epoch_id"),
        "authority_profile_id": core.get("authority_profile_id"),
        "assurance_level_id": core.get("assurance_level_id"),
    })

    if core.get("canonicalization_profile_ref") != policy_state.get("canonicalization_profile_ref", SUPPORTED_PROFILE):
        return deny(DRC["CANONICALIZATION_PROFILE_MISMATCH"], evidence, recency, timings)

    t1 = time.perf_counter_ns()
    issuer_id = auth.get("issuer_id")
    if issuer_id != core.get("issuer_id"):
        timings["signature_verification_ns"] = time.perf_counter_ns() - t1
        return deny(DRC["SIGNATURE_INVALID"], evidence, recency, timings)
    trusted = policy_state.get("trusted_issuers", {})
    if issuer_id not in trusted:
        timings["signature_verification_ns"] = time.perf_counter_ns() - t1
        return deny(DRC["ISSUER_UNTRUSTED"], evidence, recency, timings)
    try:
        sig_ok = verify_signature(trusted[issuer_id], auth.get("signature", ""), core)
    except Exception:
        sig_ok = False
    if not sig_ok:
        timings["signature_verification_ns"] = time.perf_counter_ns() - t1
        return deny(DRC["SIGNATURE_INVALID"], evidence, recency, timings)
    timings["signature_verification_ns"] = time.perf_counter_ns() - t1

    if core.get("policy_digest") != policy_state.get("policy_digest"):
        return deny(DRC["POLICY_DIGEST_MISMATCH"], evidence, recency, timings)

    if context.get("epoch_sources") and len({str(x) for x in context["epoch_sources"]}) > 1:
        return deny(DRC["EPOCH_ROLLBACK_ATTEMPT"], evidence, recency, timings)
    try:
        epoch = int(core.get("epoch_id"))
    except Exception:
        return deny(DRC["EPOCH_MISMATCH"], evidence, recency, timings)
    if epoch < int(policy_state.get("minimum_epoch_id", policy_state.get("current_epoch_id"))):
        return deny(DRC["EPOCH_ROLLBACK_ATTEMPT"], evidence, recency, timings)
    if policy_state.get("epoch_compatibility", "strict") == "strict" and epoch != int(policy_state.get("current_epoch_id")):
        return deny(DRC["EPOCH_MISMATCH"], evidence, recency, timings)

    if context.get("time_source_untrusted") or int(context.get("clock_drift_seconds", 0)) > int(policy_state.get("max_clock_drift_seconds", 300)):
        return deny(DRC["TIME_SOURCE_UNTRUSTED_OR_DRIFT"], evidence, recency, timings)
    try:
        now = parse_time(context.get("now", policy_state["now"]))
        valid_from = parse_time(core["valid_from"])
        valid_to = parse_time(core["valid_to"])
    except Exception:
        return deny(DRC["VALIDITY_WINDOW_EXPIRED"], evidence, recency, timings)
    if not (valid_from <= now <= valid_to):
        return deny(DRC["VALIDITY_WINDOW_EXPIRED"], evidence, recency, timings)

    if core.get("action_digest") != evidence["action_digest"]:
        return deny(DRC["ACTION_DIGEST_MISMATCH"], evidence, recency, timings)

    if context.get("authority_profile_ambiguous"):
        return deny(DRC["AUTHORITY_PROFILE_SELECTION_FAILED"], evidence, recency, timings)
    if context.get("jurisdiction_ambiguous") or context.get("jurisdiction_conflict"):
        return deny(DRC["JURISDICTION_CONTEXT_INDETERMINATE_OR_CONFLICT"], evidence, recency, timings)
    if core.get("jurisdiction") and context.get("jurisdiction") and core.get("jurisdiction") != context.get("jurisdiction"):
        return deny(DRC["JURISDICTION_CONTEXT_INDETERMINATE_OR_CONFLICT"], evidence, recency, timings)
    if context.get("resolved_tenant_id") and core.get("tenant_id") and context["resolved_tenant_id"] != core["tenant_id"]:
        return deny(DRC["TENANT_MISMATCH"], evidence, recency, timings)
    if policy_state.get("require_identity_binding") and core.get("identity_binding") != context.get("identity_binding"):
        return deny(DRC["IDENTITY_BINDING_MISMATCH"], evidence, recency, timings)
    if policy_state.get("require_purpose") and (not core.get("purpose_id") or core.get("purpose_id") != context.get("purpose_id")):
        return deny(DRC["PURPOSE_OUT_OF_SCOPE_OR_MISSING"], evidence, recency, timings)
    if policy_state.get("require_permit_provenance") and not core.get("permit_provenance_digest"):
        return deny(DRC["PERMIT_PROVENANCE_INVALID_OR_MISSING"], evidence, recency, timings)
    if policy_state.get("require_assurance_evidence") and not core.get("assurance_evidence_digest"):
        return deny(DRC["ASSURANCE_PROFILE_NOT_SATISFIED"], evidence, recency, timings)

    if context.get("attestation_required"):
        if context.get("attestation_present") is False:
            return deny(DRC["KEY_RELEASE_DENIED"] if request.get("effect_type") == "KEY_RELEASE" else DRC["ATTESTATION_FAILURE"], evidence, recency, timings)
        if context.get("attestation_stale") or context.get("attestation_nonce_mismatch"):
            return deny(DRC["ATTESTATION_STALE"], evidence, recency, timings)

    scope_code = _scope_code(request, core.get("scope", {}))
    if scope_code:
        return deny(scope_code, evidence, recency, timings)

    # Transparency proof checks may be receipt-local or revocation-state-local.
    if policy_state.get("require_transparency"):
        if not core.get("transparency_anchor_digest") and not context.get("transparency_proof_present") and not revocation_state.get("merkle"):
            return deny(DRC["TRANSPARENCY_PROOF_MISSING"], evidence, recency, timings)
        if context.get("transparency_proof_valid") is False:
            return deny(DRC["TRANSPARENCY_PROOF_INVALID"], evidence, recency, timings)

    # Revocation and recency.
    t2 = time.perf_counter_ns()
    status = revocation_state.get("status", "fresh")
    if status == "conflicting" or context.get("cross_log_coherence") == "conflict":
        timings["revocation_check_ns"] = time.perf_counter_ns() - t2
        return deny(DRC["CROSS_LOG_COHERENCE_NOT_SATISFIED"], evidence, recency, timings)
    if status in {"missing", "stale", "unknown"}:
        timings["revocation_check_ns"] = time.perf_counter_ns() - t2
        if context.get("partitioned") and policy_state.get("offline_constrained_mode_allowed") and request.get("effect_type") in set(policy_state.get("offline_constrained_effect_types", [])):
            return allow(evidence, recency, timings, constrained=True)
        if context.get("partitioned") and policy_state.get("offline_constrained_mode_allowed"):
            return deny(DRC["CONSTRAINED_MODE_DENIAL"], evidence, recency, timings)
        return deny(DRC["REVOCATION_UNKNOWN_OR_STALE"], evidence, recency, timings)

    if policy_state.get("require_signed_revocation_list", True):
        denial, list_body = _verify_signed_revocation_list(revocation_state, policy_state, evidence, recency, now)
        if denial:
            timings["revocation_check_ns"] = time.perf_counter_ns() - t2
            return deny(denial, evidence, recency, timings)
        if receipt_digest in set(list_body.get("revoked_receipt_digests", [])) or issuer_id in set(list_body.get("revoked_issuers", [])):
            timings["revocation_check_ns"] = time.perf_counter_ns() - t2
            return deny(DRC["REVOKED_CONFIRMED"], evidence, recency, timings)
    else:
        if receipt_digest in set(revocation_state.get("revoked_receipt_digests", [])) or issuer_id in set(revocation_state.get("revoked_issuers", [])) or status == "revoked":
            timings["revocation_check_ns"] = time.perf_counter_ns() - t2
            return deny(DRC["REVOKED_CONFIRMED"], evidence, recency, timings)
        last_updated = parse_time(revocation_state.get("last_updated", context.get("now", policy_state["now"])))
        age = int((now - last_updated).total_seconds())
        recency["revocation_age_seconds"] = age
        recency["revocation_max_age_seconds"] = int(policy_state.get("revocation_max_age_seconds", 3600))
        if age < 0 or age > recency["revocation_max_age_seconds"]:
            timings["revocation_check_ns"] = time.perf_counter_ns() - t2
            return deny(DRC["REVOCATION_UNKNOWN_OR_STALE"], evidence, recency, timings)

    if policy_state.get("require_merkle_revocation_proof"):
        denial = _verify_merkle_revocation_proofs(revocation_state, policy_state, evidence, recency, now, receipt_digest, issuer_id)
        if denial:
            timings["revocation_check_ns"] = time.perf_counter_ns() - t2
            return deny(denial, evidence, recency, timings)
    timings["revocation_check_ns"] = time.perf_counter_ns() - t2

    # Anti-replay. If a ReplayCache is supplied, it is atomically updated.
    nonce = (core.get("anti_replay") or {}).get("nonce")
    replay_cache = context.get("replay_cache")
    if nonce and replay_cache is not None:
        if not replay_cache.check_and_mark("receipt", str(nonce)):
            return deny(DRC["ANTI_REPLAY_FAILURE"], evidence, recency, timings)
    elif nonce and nonce in set(context.get("used_nonces", [])):
        return deny(DRC["ANTI_REPLAY_FAILURE"], evidence, recency, timings)

    if policy_state.get("require_capability_token") or context.get("downstream_capability_present") is False:
        if context.get("downstream_capability_present") is False:
            return deny(DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"], evidence, recency, timings)
        cap_code = verify_capability_token(request, context.get("capability_token"), policy_state, context, evidence, now)
        if cap_code:
            return deny(cap_code, evidence, recency, timings)

    return allow(evidence, recency, timings)
