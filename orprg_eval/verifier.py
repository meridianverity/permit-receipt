"""PermitReceipt / ORPRG public-evaluation verifier, hardened in v2.2.6.

The selected profile is deliberately strict and fail closed.  Every public
verification call is total over Python inputs: malformed, unsupported, or
resource-exhausting structures produce a structured DENY rather than escaping
as an exception.  Receipt and capability replay state is committed only after
all mandatory checks have passed.
"""
from __future__ import annotations

from datetime import datetime
import time
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .canonicalization import (
    CanonicalizationError,
    SUPPORTED_PROFILE,
    canonicalize_request,
    compute_action_digest,
    digest_obj,
)
from .crypto import sign_object, verify_signature
from .merkle import (
    entry_key,
    verify_inclusion_proof,
    verify_non_inclusion_proof,
    verify_signed_checkpoint,
)
from .models import ALLOW, DENY, DRC, VerifyResult
from .replay import MutableNonceListReplayCache
from .schema import (
    validate_capability_schema,
    is_sha256_hex,
    validate_context_schema,
    validate_policy_state_schema,
    validate_receipt_schema,
    validate_request_schema,
    validate_revocation_state_schema,
)
from .timeutil import parse_rfc3339


# Kept as a public compatibility name for the gateway examples.
def parse_time(value: Any) -> datetime:
    return parse_rfc3339(value)


def _finish_timings(timings: Dict[str, int]) -> Dict[str, int]:
    if "total_ns" not in timings:
        start = timings.pop("start_ns", time.perf_counter_ns())
        timings["total_ns"] = max(0, time.perf_counter_ns() - start)
    return timings


def deny(
    code: str,
    evidence: Dict[str, Any],
    recency: Dict[str, Any],
    timings: Dict[str, int],
) -> VerifyResult:
    return VerifyResult(DENY, code, evidence, recency, _finish_timings(timings))


def allow(
    evidence: Dict[str, Any],
    recency: Dict[str, Any],
    timings: Dict[str, int],
    constrained: bool = False,
) -> VerifyResult:
    return VerifyResult(
        ALLOW,
        None,
        evidence,
        recency,
        _finish_timings(timings),
        constrained_mode=constrained,
    )


def issue_receipt(core: Mapping[str, Any], priv) -> Dict[str, Any]:
    return {
        "receipt_core": dict(core),
        "authenticity": {
            "issuer_id": core["issuer_id"],
            "signature": sign_object(priv, core),
        },
    }


def make_receipt_core(
    request: Mapping[str, Any],
    *,
    policy_digest: str,
    epoch_id: int,
    issuer_id: str,
    valid_from: str,
    valid_to: str,
    scope: Mapping[str, Any],
    nonce: str,
    canonicalization_profile_ref: str = SUPPORTED_PROFILE,
    authority_profile_id: str = "AP-SYNTH-AL5",
    assurance_level_id: str = "AL5",
    permit_provenance_digest: Optional[str] = (
        "sha256:25981c1dfe8af9109a3edaea029af66c"
        "beca1f423ff3953b0007871a8effbf7a"
    ),
    tenant_id: Optional[str] = "tenant-A",
    purpose_id: Optional[str] = "support",
    jurisdiction: Optional[str] = "US",
    extras: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
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


def issue_capability_token(
    core: Mapping[str, Any], priv, issuer_id: str = "cap-issuer"
) -> Dict[str, Any]:
    return {
        "token_core": dict(core),
        "authenticity": {
            "issuer_id": issuer_id,
            "signature": sign_object(priv, core),
        },
    }


def make_capability_core(
    *,
    request: Mapping[str, Any],
    receipt_core: Mapping[str, Any],
    policy_digest: str,
    valid_to: str,
    nonce: str = "cap-nonce-1",
) -> Dict[str, Any]:
    profile = receipt_core.get("canonicalization_profile_ref", SUPPORTED_PROFILE)
    canonical = canonicalize_request(request, profile)
    return {
        "action_digest": compute_action_digest(canonical),
        "receipt_digest": digest_obj(receipt_core),
        "policy_digest": policy_digest,
        "epoch_id": receipt_core["epoch_id"],
        "audience": request.get("interface_id"),
        "tenant_id": request.get("tenant_id"),
        "valid_to": valid_to,
        "nonce": nonce,
    }


def replay_domain(
    kind: str,
    *,
    issuer_id: str,
    tenant_id: str,
    audience: str,
    policy_digest: str,
    epoch_id: int,
    canonicalization_profile_ref: str,
) -> str:
    """Return the selected profile's unambiguous replay namespace."""

    namespace_digest = digest_obj(
        {
            "profile": "PermitReceipt-Public-Eval-v2.2.6",
            "kind": kind,
            "issuer_id": issuer_id,
            "tenant_id": tenant_id,
            "audience": audience,
            "policy_digest": policy_digest,
            "epoch_id": epoch_id,
            "canonicalization_profile_ref": canonicalization_profile_ref,
        }
    )
    return f"orprg-v2.2.6:{kind}:{namespace_digest}"


def _scope_code(request: Mapping[str, Any], scope: Mapping[str, Any]) -> Optional[str]:
    if "tenant_id" in scope and request.get("tenant_id") != scope["tenant_id"]:
        return DRC["TENANT_MISMATCH"]
    if "purpose_id" in scope and request.get("purpose_id") != scope["purpose_id"]:
        return DRC["PURPOSE_OUT_OF_SCOPE_OR_MISSING"]
    if (
        "representation_class_id" in scope
        and request.get("representation_class_id") != scope["representation_class_id"]
    ):
        return DRC["REPRESENTATION_CLASS_VIOLATION"]
    for key in (
        "effect_type",
        "interface_id",
        "action_type",
        "target_id",
        "artifact_id",
        "key_id",
        "key_op",
    ):
        if key in scope and request.get(key) != scope[key]:
            return (
                DRC["KEY_RELEASE_DENIED"]
                if request.get("effect_type") == "KEY_RELEASE"
                else DRC["SCOPE_VIOLATION"]
            )
    if "key_ops" in scope and request.get("key_op") not in scope["key_ops"]:
        return DRC["KEY_RELEASE_DENIED"]
    if "max_effect_budget" in scope:
        if "max_effect_budget" not in request:
            return DRC["SCOPE_VIOLATION"]
        if request["max_effect_budget"] > scope["max_effect_budget"]:
            return DRC["SCOPE_VIOLATION"]
    return None


def _verify_signed_revocation_list(
    revocation_state: Mapping[str, Any],
    policy_state: Mapping[str, Any],
    evidence: Dict[str, Any],
    recency: Dict[str, Any],
    now: datetime,
) -> Tuple[Optional[str], Dict[str, Any]]:
    """Return ``(denial_code, list_body)`` for a strictly shaped list."""

    signed = revocation_state.get("signed_revocation_list")
    if not isinstance(signed, Mapping):
        return DRC["REVOCATION_UNKNOWN_OR_STALE"], {}
    body = signed["body"]
    auth = signed["authenticity"]
    issuer_id = auth["issuer_id"]
    if issuer_id != body["issuer_id"]:
        return DRC["REVOCATION_SIGNATURE_INVALID"], dict(body)
    pub = policy_state.get("revocation_authorities", {}).get(issuer_id)
    if not pub:
        return DRC["REVOCATION_SIGNATURE_INVALID"], dict(body)
    if not verify_signature(pub, auth["signature"], body):
        return DRC["REVOCATION_SIGNATURE_INVALID"], dict(body)
    evidence["revocation_list_digest"] = digest_obj(body)
    issued_at = parse_time(body["issued_at"])
    age = int((now - issued_at).total_seconds())
    maximum = policy_state.get("revocation_max_age_seconds", 3600)
    recency["revocation_list_age_seconds"] = age
    recency["revocation_max_age_seconds"] = maximum
    if age < 0 or age > maximum:
        return DRC["REVOCATION_UNKNOWN_OR_STALE"], dict(body)
    return None, dict(body)


def _verify_merkle_revocation_proofs(
    revocation_state: Mapping[str, Any],
    policy_state: Mapping[str, Any],
    evidence: Dict[str, Any],
    recency: Dict[str, Any],
    now: datetime,
    receipt_digest: str,
    issuer_id: str,
) -> Optional[str]:
    try:
        merkle = revocation_state.get("merkle")
        if not isinstance(merkle, Mapping):
            return DRC["TRANSPARENCY_PROOF_MISSING"]
        signed_cp = merkle.get("signed_checkpoint")
        if not isinstance(signed_cp, Mapping):
            return DRC["TRANSPARENCY_PROOF_MISSING"]
        checkpoint = signed_cp.get("checkpoint")
        if not isinstance(checkpoint, Mapping):
            return DRC["SIGNED_CHECKPOINT_INVALID"]
        log_id = checkpoint.get("log_id")
        log_pub = policy_state.get("transparency_logs", {}).get(log_id)
        if not log_pub or not verify_signed_checkpoint(signed_cp, log_pub):
            return DRC["SIGNED_CHECKPOINT_INVALID"]
        evidence["revocation_checkpoint_digest"] = digest_obj(checkpoint)
        issued_at = parse_time(checkpoint["issued_at"])
        age = int((now - issued_at).total_seconds())
        maximum = policy_state.get(
            "checkpoint_max_age_seconds",
            policy_state.get("revocation_max_age_seconds", 3600),
        )
        recency["checkpoint_age_seconds"] = age
        recency["checkpoint_max_age_seconds"] = maximum
        if age < 0 or age > maximum:
            return DRC["REVOCATION_UNKNOWN_OR_STALE"]
        root = checkpoint["root_hash"]
        targets = (
            ("receipt", receipt_digest, "receipt_proof"),
            ("issuer", issuer_id, "issuer_proof"),
        )
        for target_kind, target_id, proof_name in targets:
            proof = merkle.get(proof_name)
            if not isinstance(proof, Mapping):
                return DRC["MERKLE_INCLUSION_REQUIRED_BUT_MISSING"]
            proof_type = proof.get("proof_type")
            if proof_type == "inclusion":
                if not verify_inclusion_proof(proof, root):
                    return DRC["TRANSPARENCY_PROOF_INVALID"]
                entry = proof.get("entry")
                if not isinstance(entry, Mapping):
                    return DRC["TRANSPARENCY_PROOF_INVALID"]
                if entry.get("key") == entry_key(target_kind, target_id):
                    return DRC["REVOKED_CONFIRMED"]
                return DRC["TRANSPARENCY_PROOF_INVALID"]
            if proof_type == "non_inclusion":
                if proof.get("target_key") != entry_key(target_kind, target_id):
                    return DRC["NON_INCLUSION_PROOF_INVALID"]
                if not verify_non_inclusion_proof(proof, root):
                    return DRC["NON_INCLUSION_PROOF_INVALID"]
            else:
                return DRC["TRANSPARENCY_PROOF_INVALID"]
        return None
    except Exception:
        # Merkle structures are untrusted evidence.  Parser/proof failures are
        # protocol denials, not process failures.
        return DRC["TRANSPARENCY_PROOF_INVALID"]


def _validate_capability_token(
    request: Mapping[str, Any],
    token: Any,
    policy_state: Mapping[str, Any],
    context: Mapping[str, Any],
    evidence: Dict[str, Any],
    now: datetime,
    *,
    expected_receipt_digest: str,
) -> Tuple[Optional[str], Optional[Tuple[Any, str, str]]]:
    schema_code = validate_capability_schema(token)
    if schema_code:
        return schema_code, None
    core = token["token_core"]
    auth = token["authenticity"]
    issuer_id = auth["issuer_id"]
    pub = policy_state.get("trusted_capability_issuers", {}).get(issuer_id)
    if not pub:
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"], None
    if not verify_signature(pub, auth["signature"], core):
        return DRC["CAPABILITY_SIGNATURE_INVALID"], None

    evidence["capability_token_digest"] = digest_obj(core)
    if parse_time(core["valid_to"]) < now:
        return DRC["CAPABILITY_EXPIRED"], None

    profile = policy_state.get("canonicalization_profile_ref", SUPPORTED_PROFILE)
    try:
        action_digest = compute_action_digest(canonicalize_request(request, profile))
    except CanonicalizationError:
        return DRC["CANONICALIZATION_PROFILE_MISMATCH"], None
    if core["action_digest"] != action_digest:
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"], None
    if core["receipt_digest"] != expected_receipt_digest:
        return DRC["CAPABILITY_RECEIPT_BINDING_MISMATCH"], None
    if core["audience"] != request.get("interface_id"):
        return DRC["CAPABILITY_AUDIENCE_MISMATCH"], None
    if core["tenant_id"] != request.get("tenant_id"):
        return DRC["TENANT_MISMATCH"], None
    if core["policy_digest"] != policy_state.get("policy_digest"):
        return DRC["POLICY_DIGEST_MISMATCH"], None
    if core["epoch_id"] != policy_state.get("current_epoch_id"):
        return DRC["EPOCH_MISMATCH"], None

    nonce = core["nonce"]
    if nonce in context.get("used_capability_nonces", ()):
        return DRC["CAPABILITY_REPLAY"], None
    domain = replay_domain(
        "capability",
        issuer_id=issuer_id,
        tenant_id=core["tenant_id"],
        audience=core["audience"],
        policy_digest=core["policy_digest"],
        epoch_id=core["epoch_id"],
        canonicalization_profile_ref=profile,
    )
    cache = context.get("capability_replay_cache")
    if cache is None:
        mutable_state = context.get("used_capability_nonces")
        if not isinstance(mutable_state, list):
            return DRC["REPLAY_STATE_FAILURE"], None
        cache = MutableNonceListReplayCache(mutable_state)
    return None, (cache, domain, nonce)


def _reserve(cache: Any, domain: str, nonce: str) -> Any:
    """Reserve one nonce, returning ``None`` for an absent optional cache."""

    if cache is None:
        return None
    return cache.reserve(domain, nonce)


def _release_all(reservations: Sequence[Any]) -> None:
    for reservation in reversed(reservations):
        try:
            if reservation is not None:
                reservation.release()
        except Exception:
            # A release failure remains fail closed.  The nonce may stay
            # reserved/consumed, which is safer than allowing reuse.
            pass


def _commit_all(reservations: Sequence[Any]) -> bool:
    for reservation in reservations:
        if reservation is not None and not reservation.commit():
            return False
    return True


def verify_capability_token(
    request: Mapping[str, Any],
    token: Optional[Mapping[str, Any]],
    policy_state: Mapping[str, Any],
    context: Mapping[str, Any],
    evidence: Dict[str, Any],
    now: Optional[datetime] = None,
    *,
    expected_receipt_digest: Optional[str] = None,
) -> Optional[str]:
    """Validate and consume a standalone capability token.

    Direct gateway callers must supply the active receipt digest either through
    ``expected_receipt_digest`` or ``context['expected_receipt_digest']``.
    PermitReceipt verification supplies it internally.
    """

    try:
        if validate_request_schema(request):
            return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
        if validate_policy_state_schema(policy_state) or validate_context_schema(context):
            return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
        expected = expected_receipt_digest or context.get("expected_receipt_digest")
        if not is_sha256_hex(expected):
            return DRC["CAPABILITY_RECEIPT_BINDING_MISMATCH"]
        if now is None:
            now = parse_time(context.get("now", policy_state["now"]))
        code, replay = _validate_capability_token(
            request,
            token,
            policy_state,
            context,
            evidence,
            now,
            expected_receipt_digest=expected,
        )
        if code:
            return code
        if replay is None:
            return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
        cache, domain, nonce = replay
        reservation = _reserve(cache, domain, nonce)
        if reservation is None:
            return DRC["CAPABILITY_REPLAY"]
        if not reservation.commit():
            return DRC["CAPABILITY_REPLAY"]
        return None
    except Exception:
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]


def _verify_permit_receipt_inner(
    request: Mapping[str, Any],
    receipt: Optional[Mapping[str, Any]],
    policy_state: Mapping[str, Any],
    revocation_state: Mapping[str, Any],
    context: Mapping[str, Any],
    timings: Dict[str, int],
    evidence: Dict[str, Any],
    recency: Dict[str, Any],
) -> VerifyResult:
    # Canonicalization is intentionally before the detailed request schema so
    # unsupported CP-JSON-2 values map to the profile-specific DRC-016.
    if not isinstance(request, Mapping):
        return deny(DRC["SCHEMA_VALIDATION_FAILURE"], evidence, recency, timings)
    if validate_policy_state_schema(policy_state):
        return deny(DRC["SCHEMA_VALIDATION_FAILURE"], evidence, recency, timings)
    if validate_context_schema(context):
        return deny(DRC["SCHEMA_VALIDATION_FAILURE"], evidence, recency, timings)
    if validate_revocation_state_schema(revocation_state):
        return deny(DRC["SCHEMA_VALIDATION_FAILURE"], evidence, recency, timings)

    t0 = time.perf_counter_ns()
    profile = context.get(
        "canonicalization_profile_ref",
        policy_state.get("canonicalization_profile_ref", SUPPORTED_PROFILE),
    )
    if profile != policy_state.get("canonicalization_profile_ref", SUPPORTED_PROFILE):
        timings["canonicalization_and_digest_ns"] = time.perf_counter_ns() - t0
        return deny(DRC["CANONICALIZATION_PROFILE_MISMATCH"], evidence, recency, timings)
    try:
        canonical = canonicalize_request(request, profile)
        evidence["action_digest"] = compute_action_digest(canonical)
    except CanonicalizationError:
        timings["canonicalization_and_digest_ns"] = time.perf_counter_ns() - t0
        return deny(DRC["CANONICALIZATION_PROFILE_MISMATCH"], evidence, recency, timings)
    timings["canonicalization_and_digest_ns"] = time.perf_counter_ns() - t0

    request_schema_code = validate_request_schema(request)
    if request_schema_code:
        return deny(request_schema_code, evidence, recency, timings)
    if receipt is None:
        return deny(DRC["MISSING_RECEIPT"], evidence, recency, timings)
    receipt_schema_code = validate_receipt_schema(receipt)
    if receipt_schema_code:
        return deny(receipt_schema_code, evidence, recency, timings)

    core = receipt["receipt_core"]
    auth = receipt["authenticity"]
    receipt_digest = digest_obj(core)
    evidence.update(
        {
            "receipt_digest": receipt_digest,
            "policy_digest": core["policy_digest"],
            "epoch_id": core["epoch_id"],
            "authority_profile_id": core["authority_profile_id"],
            "assurance_level_id": core["assurance_level_id"],
        }
    )

    if core["canonicalization_profile_ref"] != policy_state.get(
        "canonicalization_profile_ref", SUPPORTED_PROFILE
    ):
        return deny(DRC["CANONICALIZATION_PROFILE_MISMATCH"], evidence, recency, timings)

    t1 = time.perf_counter_ns()
    issuer_id = auth["issuer_id"]
    if issuer_id != core["issuer_id"]:
        timings["signature_verification_ns"] = time.perf_counter_ns() - t1
        return deny(DRC["SIGNATURE_INVALID"], evidence, recency, timings)
    trusted = policy_state.get("trusted_issuers", {})
    if issuer_id not in trusted:
        timings["signature_verification_ns"] = time.perf_counter_ns() - t1
        return deny(DRC["ISSUER_UNTRUSTED"], evidence, recency, timings)
    if not verify_signature(trusted[issuer_id], auth["signature"], core):
        timings["signature_verification_ns"] = time.perf_counter_ns() - t1
        return deny(DRC["SIGNATURE_INVALID"], evidence, recency, timings)
    timings["signature_verification_ns"] = time.perf_counter_ns() - t1

    if core["policy_digest"] != policy_state["policy_digest"]:
        return deny(DRC["POLICY_DIGEST_MISMATCH"], evidence, recency, timings)

    epoch_sources = context.get("epoch_sources", ())
    if epoch_sources and len({str(item) for item in epoch_sources}) > 1:
        return deny(DRC["EPOCH_ROLLBACK_ATTEMPT"], evidence, recency, timings)
    epoch = core["epoch_id"]
    minimum_epoch = policy_state.get("minimum_epoch_id", policy_state["current_epoch_id"])
    if epoch < minimum_epoch:
        return deny(DRC["EPOCH_ROLLBACK_ATTEMPT"], evidence, recency, timings)
    if (
        policy_state.get("epoch_compatibility", "strict") == "strict"
        and epoch != policy_state["current_epoch_id"]
    ):
        return deny(DRC["EPOCH_MISMATCH"], evidence, recency, timings)

    drift = context.get("clock_drift_seconds", 0)
    if context.get("time_source_untrusted") or abs(drift) > policy_state.get(
        "max_clock_drift_seconds", 300
    ):
        return deny(DRC["TIME_SOURCE_UNTRUSTED_OR_DRIFT"], evidence, recency, timings)
    now = parse_time(context.get("now", policy_state["now"]))
    valid_from = parse_time(core["valid_from"])
    valid_to = parse_time(core["valid_to"])
    if not (valid_from <= now <= valid_to):
        return deny(DRC["VALIDITY_WINDOW_EXPIRED"], evidence, recency, timings)

    if core["action_digest"] != evidence["action_digest"]:
        return deny(DRC["ACTION_DIGEST_MISMATCH"], evidence, recency, timings)

    if context.get("authority_profile_ambiguous"):
        return deny(DRC["AUTHORITY_PROFILE_SELECTION_FAILED"], evidence, recency, timings)
    if core.get("authority_profile_id") not in set(
        policy_state.get("trusted_authority_profile_ids", [])
    ):
        return deny(DRC["AUTHORITY_PROFILE_SELECTION_FAILED"], evidence, recency, timings)
    if core.get("assurance_level_id") not in set(
        policy_state.get("trusted_assurance_level_ids", [])
    ):
        return deny(DRC["ASSURANCE_PROFILE_NOT_SATISFIED"], evidence, recency, timings)
    if context.get("jurisdiction_ambiguous") or context.get("jurisdiction_conflict"):
        return deny(
            DRC["JURISDICTION_CONTEXT_INDETERMINATE_OR_CONFLICT"],
            evidence,
            recency,
            timings,
        )
    if (
        core.get("jurisdiction")
        and context.get("jurisdiction")
        and core["jurisdiction"] != context["jurisdiction"]
    ):
        return deny(
            DRC["JURISDICTION_CONTEXT_INDETERMINATE_OR_CONFLICT"],
            evidence,
            recency,
            timings,
        )
    if (
        context.get("resolved_tenant_id")
        and core.get("tenant_id")
        and context["resolved_tenant_id"] != core["tenant_id"]
    ):
        return deny(DRC["TENANT_MISMATCH"], evidence, recency, timings)
    if policy_state.get("require_identity_binding"):
        receipt_identity = core.get("identity_binding")
        context_identity = context.get("identity_binding")
        if (
            not isinstance(receipt_identity, Mapping)
            or not isinstance(context_identity, Mapping)
            or receipt_identity != context_identity
        ):
            return deny(DRC["IDENTITY_BINDING_MISMATCH"], evidence, recency, timings)
    if policy_state.get("require_purpose") and (
        not core.get("purpose_id") or core.get("purpose_id") != context.get("purpose_id")
    ):
        return deny(DRC["PURPOSE_OUT_OF_SCOPE_OR_MISSING"], evidence, recency, timings)
    if policy_state.get("require_permit_provenance"):
        provenance = core.get("permit_provenance_digest")
        if provenance not in set(
            policy_state.get("trusted_permit_provenance_digests", [])
        ):
            return deny(
                DRC["PERMIT_PROVENANCE_INVALID_OR_MISSING"],
                evidence,
                recency,
                timings,
            )
    if policy_state.get("require_assurance_evidence") and not core.get(
        "assurance_evidence_digest"
    ):
        return deny(DRC["ASSURANCE_PROFILE_NOT_SATISFIED"], evidence, recency, timings)

    if context.get("attestation_required"):
        # Freshness/nonce evidence is more specific than generic absence.  The
        # selected profile reports the strongest observed failure deterministically.
        if context.get("attestation_stale") or context.get("attestation_nonce_mismatch"):
            return deny(DRC["ATTESTATION_STALE"], evidence, recency, timings)
        if context.get("attestation_present") is not True:
            code = (
                DRC["KEY_RELEASE_DENIED"]
                if request.get("effect_type") == "KEY_RELEASE"
                else DRC["ATTESTATION_FAILURE"]
            )
            return deny(code, evidence, recency, timings)

    scope_code = _scope_code(request, core["scope"])
    if scope_code:
        return deny(scope_code, evidence, recency, timings)

    if policy_state.get("require_transparency"):
        has_merkle_evidence = isinstance(revocation_state.get("merkle"), Mapping)
        has_context_proof = context.get("transparency_proof_present") is True
        if not has_merkle_evidence and not has_context_proof:
            return deny(DRC["TRANSPARENCY_PROOF_MISSING"], evidence, recency, timings)
        if has_context_proof and context.get("transparency_proof_valid") is not True:
            return deny(DRC["TRANSPARENCY_PROOF_INVALID"], evidence, recency, timings)

    # Revocation availability is the only check relaxed by constrained mode.
    t2 = time.perf_counter_ns()
    status = revocation_state["status"]
    constrained = False
    if status == "revoked":
        timings["revocation_check_ns"] = time.perf_counter_ns() - t2
        return deny(DRC["REVOKED_CONFIRMED"], evidence, recency, timings)
    if status == "conflicting" or context.get("cross_log_coherence") == "conflict":
        timings["revocation_check_ns"] = time.perf_counter_ns() - t2
        return deny(
            DRC["CROSS_LOG_COHERENCE_NOT_SATISFIED"], evidence, recency, timings
        )
    if status in {"missing", "stale", "unknown"}:
        constrained_allowed = (
            context.get("partitioned")
            and policy_state.get("offline_constrained_mode_allowed")
        )
        if constrained_allowed and request["effect_type"] in policy_state.get(
            "offline_constrained_effect_types", ()
        ):
            constrained = True
            recency["revocation_status"] = status
            recency["revocation_relaxed_by_constrained_mode"] = True
        elif constrained_allowed:
            timings["revocation_check_ns"] = time.perf_counter_ns() - t2
            return deny(DRC["CONSTRAINED_MODE_DENIAL"], evidence, recency, timings)
        else:
            timings["revocation_check_ns"] = time.perf_counter_ns() - t2
            return deny(DRC["REVOCATION_UNKNOWN_OR_STALE"], evidence, recency, timings)
    else:
        if policy_state.get("require_signed_revocation_list", True):
            revocation_code, list_body = _verify_signed_revocation_list(
                revocation_state, policy_state, evidence, recency, now
            )
            if revocation_code:
                timings["revocation_check_ns"] = time.perf_counter_ns() - t2
                return deny(revocation_code, evidence, recency, timings)
            if receipt_digest in list_body["revoked_receipt_digests"] or issuer_id in list_body[
                "revoked_issuers"
            ]:
                timings["revocation_check_ns"] = time.perf_counter_ns() - t2
                return deny(DRC["REVOKED_CONFIRMED"], evidence, recency, timings)
        else:
            if receipt_digest in revocation_state.get(
                "revoked_receipt_digests", ()
            ) or issuer_id in revocation_state.get("revoked_issuers", ()):
                timings["revocation_check_ns"] = time.perf_counter_ns() - t2
                return deny(DRC["REVOKED_CONFIRMED"], evidence, recency, timings)
            last_updated = parse_time(
                revocation_state.get(
                    "last_updated", context.get("now", policy_state["now"])
                )
            )
            age = int((now - last_updated).total_seconds())
            maximum = policy_state.get("revocation_max_age_seconds", 3600)
            recency["revocation_age_seconds"] = age
            recency["revocation_max_age_seconds"] = maximum
            if age < 0 or age > maximum:
                timings["revocation_check_ns"] = time.perf_counter_ns() - t2
                return deny(DRC["REVOCATION_UNKNOWN_OR_STALE"], evidence, recency, timings)

        if policy_state.get("require_merkle_revocation_proof"):
            merkle_code = _verify_merkle_revocation_proofs(
                revocation_state,
                policy_state,
                evidence,
                recency,
                now,
                receipt_digest,
                issuer_id,
            )
            if merkle_code:
                timings["revocation_check_ns"] = time.perf_counter_ns() - t2
                return deny(merkle_code, evidence, recency, timings)
    timings["revocation_check_ns"] = time.perf_counter_ns() - t2

    # Validate all mandatory capability semantics before reserving either nonce.
    replay_specs: list[Tuple[Any, str, str, str]] = []
    receipt_nonce = core["anti_replay"]["nonce"]
    if receipt_nonce in context.get("used_nonces", ()):
        return deny(DRC["ANTI_REPLAY_FAILURE"], evidence, recency, timings)
    receipt_domain = replay_domain(
        "receipt",
        issuer_id=issuer_id,
        tenant_id=core.get("tenant_id", request["tenant_id"]),
        audience=request["interface_id"],
        policy_digest=core["policy_digest"],
        epoch_id=core["epoch_id"],
        canonicalization_profile_ref=profile,
    )
    receipt_cache = context.get("replay_cache")
    if receipt_cache is None:
        mutable_state = context.get("used_nonces")
        if not isinstance(mutable_state, list):
            return deny(DRC["REPLAY_STATE_FAILURE"], evidence, recency, timings)
        receipt_cache = MutableNonceListReplayCache(mutable_state)
    replay_specs.append(
        (receipt_cache, receipt_domain, receipt_nonce, DRC["ANTI_REPLAY_FAILURE"])
    )

    capability_required = policy_state.get("require_capability_token") or context.get(
        "downstream_capability_present"
    ) is False
    if capability_required:
        if context.get("downstream_capability_present") is False:
            return deny(
                DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"], evidence, recency, timings
            )
        cap_code, cap_replay = _validate_capability_token(
            request,
            context.get("capability_token"),
            policy_state,
            context,
            evidence,
            now,
            expected_receipt_digest=receipt_digest,
        )
        if cap_code:
            return deny(cap_code, evidence, recency, timings)
        if cap_replay is None:
            return deny(
                DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"], evidence, recency, timings
            )
        cap_cache, cap_domain, cap_nonce = cap_replay
        replay_specs.append((cap_cache, cap_domain, cap_nonce, DRC["CAPABILITY_REPLAY"]))

    reservations: list[Any] = []
    try:
        for cache, domain, nonce, replay_code in replay_specs:
            reservation = _reserve(cache, domain, nonce)
            if reservation is None:
                _release_all(reservations)
                return deny(replay_code, evidence, recency, timings)
            reservations.append(reservation)
        if not _commit_all(reservations):
            _release_all(reservations)
            return deny(DRC["ANTI_REPLAY_FAILURE"], evidence, recency, timings)
    except Exception:
        _release_all(reservations)
        return deny(DRC["REPLAY_STATE_FAILURE"], evidence, recency, timings)

    return allow(evidence, recency, timings, constrained=constrained)


def verify_permit_receipt(
    request: Mapping[str, Any],
    receipt: Optional[Mapping[str, Any]],
    policy_state: Mapping[str, Any],
    revocation_state: Mapping[str, Any],
    context: Optional[Mapping[str, Any]] = None,
) -> VerifyResult:
    """Verify a PermitReceipt and return a total, structured result."""

    timings: Dict[str, int] = {"start_ns": time.perf_counter_ns()}
    evidence: Dict[str, Any] = {}
    recency: Dict[str, Any] = {}
    try:
        safe_context = dict(context or {})
        return _verify_permit_receipt_inner(
            request,
            receipt,
            policy_state,
            revocation_state,
            safe_context,
            timings,
            evidence,
            recency,
        )
    except Exception as exc:
        # Never expose exception text (which may contain attacker-controlled
        # data); the exception class is enough for reproducible diagnostics.
        evidence["fail_closed_error_category"] = type(exc).__name__
        return deny(DRC["INTERNAL_FAIL_CLOSED"], evidence, recency, timings)
