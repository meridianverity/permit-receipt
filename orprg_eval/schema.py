"""Strict, total shape checks for the selected ORPRG public-evaluation profile.

The validators return a public denial-reason code rather than raising.  Semantic
checks that depend on trust state remain in :mod:`orprg_eval.verifier`.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence, Set
from typing import Any, Optional

from .canonicalization import CanonicalizationError, normalize_json_value
from .models import DRC
from .timeutil import TimeFormatError, is_strict_int, parse_rfc3339

_REQUEST_ALLOWED_FIELDS = {
    "effect_type",
    "interface_id",
    "action_type",
    "target_id",
    "tenant_id",
    "purpose_id",
    "payload_digest",
    "representation_class_id",
    "artifact_id",
    "key_id",
    "key_op",
    "max_effect_budget",
    # Selected payment-adjacent bridge extension fields. These are part of the
    # signed request digest and are explicitly typed rather than silently
    # accepting an open-ended request object.
    "agent_id",
    "merchant_id",
    "currency",
    "cart_digest",
    "idempotency_key",
    "sensor_receipt_core_digest",
}
BASE_REQUEST_REQUIRED = {
    "effect_type",
    "interface_id",
    "action_type",
    "target_id",
    "tenant_id",
    "purpose_id",
    "payload_digest",
}
RECEIPT_CORE_REQUIRED = {
    "policy_digest",
    "epoch_id",
    "valid_from",
    "valid_to",
    "action_digest",
    "scope",
    "anti_replay",
    "canonicalization_profile_ref",
    "authority_profile_id",
    "assurance_level_id",
    "issuer_id",
}
AUTH_REQUIRED = {"issuer_id", "signature"}
CAPABILITY_CORE_REQUIRED = {
    "action_digest",
    "receipt_digest",
    "policy_digest",
    "epoch_id",
    "audience",
    "tenant_id",
    "valid_to",
    "nonce",
}

MAX_IDENTIFIER_LENGTH = 1024
MAX_NONCE_LENGTH = 256
MAX_LIST_ITEMS = 10_000
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")

_SCOPE_STRING_FIELDS = {
    "effect_type",
    "interface_id",
    "action_type",
    "target_id",
    "tenant_id",
    "purpose_id",
    "representation_class_id",
    "artifact_id",
    "key_id",
    "key_op",
}
_SCOPE_ALLOWED_FIELDS = _SCOPE_STRING_FIELDS | {"key_ops", "max_effect_budget"}
_RECEIPT_OPTIONAL_STRING_FIELDS = {
    "permit_provenance_digest",
    "tenant_id",
    "purpose_id",
    "jurisdiction",
    "assurance_evidence_digest",
    "transparency_anchor_digest",
}
_CONTEXT_BOOLEAN_FIELDS = {
    "time_source_untrusted",
    "authority_profile_ambiguous",
    "jurisdiction_ambiguous",
    "jurisdiction_conflict",
    "attestation_required",
    "attestation_present",
    "attestation_stale",
    "attestation_nonce_mismatch",
    "transparency_proof_present",
    "transparency_proof_valid",
    "partitioned",
    "downstream_capability_present",
}
_POLICY_BOOLEAN_FIELDS = {
    "require_signed_revocation_list",
    "require_merkle_revocation_proof",
    "require_transparency",
    "require_purpose",
    "require_identity_binding",
    "require_permit_provenance",
    "require_assurance_evidence",
    "require_capability_token",
    "offline_constrained_mode_allowed",
}
_REVOCATION_STATUSES = {"fresh", "missing", "stale", "unknown", "conflicting", "revoked"}

_RECEIPT_ALLOWED_FIELDS = RECEIPT_CORE_REQUIRED | _RECEIPT_OPTIONAL_STRING_FIELDS | {"identity_binding"}
_POLICY_ALLOWED_FIELDS = {
    "now", "policy_digest", "current_epoch_id", "minimum_epoch_id",
    "epoch_compatibility", "canonicalization_profile_ref", "trusted_issuers",
    "revocation_authorities", "transparency_logs", "trusted_capability_issuers",
    "max_clock_drift_seconds", "revocation_max_age_seconds",
    "checkpoint_max_age_seconds", "require_signed_revocation_list",
    "require_merkle_revocation_proof", "require_transparency", "require_purpose",
    "require_identity_binding", "require_permit_provenance",
    "require_assurance_evidence", "require_capability_token",
    "offline_constrained_mode_allowed", "offline_constrained_effect_types",
    "trusted_authority_profile_ids", "trusted_assurance_level_ids",
    "trusted_permit_provenance_digests",
}
_CONTEXT_ALLOWED_FIELDS = {
    "now", "clock_drift_seconds", "time_source_untrusted",
    "authority_profile_ambiguous", "jurisdiction_ambiguous",
    "jurisdiction_conflict", "jurisdiction", "resolved_tenant_id", "purpose_id",
    "identity_binding", "attestation_required", "attestation_present",
    "attestation_stale", "attestation_nonce_mismatch",
    "transparency_proof_present", "transparency_proof_valid",
    "cross_log_coherence", "partitioned", "downstream_capability_present",
    "canonicalization_profile_ref", "epoch_sources", "used_nonces",
    "used_capability_nonces", "replay_cache", "capability_replay_cache",
    "capability_token", "expected_receipt_digest",
}
_REVOCATION_ALLOWED_FIELDS = {
    "status", "last_updated", "signed_revocation_list", "merkle",
    "revoked_receipt_digests", "revoked_issuers",
}


def _nonempty_string(
    value: Any,
    *,
    max_length: int = MAX_IDENTIFIER_LENGTH,
    forbid_nul: bool = True,
) -> bool:
    if not isinstance(value, str) or not (0 < len(value) <= max_length):
        return False
    return not (forbid_nul and "\x00" in value)


def is_sha256_hex(value: Any) -> bool:
    """Return True for one lowercase, unprefixed SHA-256 hexadecimal digest."""

    return isinstance(value, str) and _HEX_64_RE.fullmatch(value) is not None


def _is_prefixed_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


# Internal compatibility alias used throughout the validators.
_hex64 = is_sha256_hex


def _strict_nonnegative_int(value: Any, *, maximum: int = 2**63 - 1) -> bool:
    return is_strict_int(value) and 0 <= value <= maximum


def _strict_bool_if_present(obj: Mapping[str, Any], field: str) -> bool:
    return field not in obj or isinstance(obj[field], bool)


def _string_collection(value: Any, *, allow_empty: bool = True) -> bool:
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        return False
    if not isinstance(value, (Sequence, Set)):
        return False
    if len(value) > MAX_LIST_ITEMS or (not allow_empty and len(value) == 0):
        return False
    return all(_nonempty_string(item) for item in value)


def _json_safe(value: Any) -> bool:
    try:
        normalize_json_value(value)
        return True
    except (CanonicalizationError, TypeError, ValueError):
        return False


def validate_request_schema(request: Any) -> Optional[str]:
    if not isinstance(request, Mapping):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if BASE_REQUEST_REQUIRED - set(request) or set(request) - _REQUEST_ALLOWED_FIELDS:
        # Unknown request members are not authorization-neutral: rejecting them
        # prevents one implementation from signing semantics another silently
        # ignores.
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not _json_safe(request):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    for key in BASE_REQUEST_REQUIRED:
        if not _nonempty_string(request.get(key), forbid_nul=True):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    for key in (
        "representation_class_id", "artifact_id", "key_id", "key_op",
        "agent_id", "merchant_id", "currency", "cart_digest",
        "idempotency_key", "sensor_receipt_core_digest",
    ):
        if key in request and not _nonempty_string(request.get(key), forbid_nul=True):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    effect_type = request.get("effect_type")
    if effect_type == "KEY_RELEASE" and (
        not _nonempty_string(request.get("key_id")) or not _nonempty_string(request.get("key_op"))
    ):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if effect_type in {"EXTENSION_INSTALL", "EXTENSION_ENABLE", "EXTENSION_UPDATE"} and not _nonempty_string(request.get("artifact_id")):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "max_effect_budget" in request and not _strict_nonnegative_int(request["max_effect_budget"]):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    return None


def _validate_scope(scope: Any) -> bool:
    if not isinstance(scope, Mapping) or not scope:
        return False
    if set(scope) - _SCOPE_ALLOWED_FIELDS:
        # Unknown constraints must not be silently ignored by the verifier.
        return False
    for field in _SCOPE_STRING_FIELDS:
        if field in scope and not _nonempty_string(scope[field]):
            return False
    if "key_ops" in scope:
        key_ops = scope["key_ops"]
        if not isinstance(key_ops, list) or not _string_collection(key_ops, allow_empty=False):
            return False
        if len(set(key_ops)) != len(key_ops):
            return False
    if "max_effect_budget" in scope and not _strict_nonnegative_int(scope["max_effect_budget"]):
        return False
    return _json_safe(scope)


def _validate_anti_replay(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value) != {"nonce"}:
        return False
    nonce = value.get("nonce")
    return _nonempty_string(nonce, max_length=MAX_NONCE_LENGTH)


def validate_receipt_schema(receipt: Any) -> Optional[str]:
    if not isinstance(receipt, Mapping):
        return DRC["RECEIPT_MALFORMED"]
    core = receipt.get("receipt_core")
    auth = receipt.get("authenticity")
    if not isinstance(core, Mapping) or not isinstance(auth, Mapping):
        return DRC["RECEIPT_MALFORMED"]
    if (
        RECEIPT_CORE_REQUIRED - set(core)
        or set(core) - _RECEIPT_ALLOWED_FIELDS
        or set(auth) != AUTH_REQUIRED
    ):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not _json_safe(receipt):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in (
        "policy_digest",
        "canonicalization_profile_ref",
        "authority_profile_id",
        "assurance_level_id",
        "issuer_id",
    ):
        if not _nonempty_string(core.get(field)):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in _RECEIPT_OPTIONAL_STRING_FIELDS:
        if field in core and not _nonempty_string(core[field]):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "permit_provenance_digest" in core and not _is_prefixed_sha256(
        core["permit_provenance_digest"]
    ):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "identity_binding" in core and not isinstance(core["identity_binding"], Mapping):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not _strict_nonnegative_int(core.get("epoch_id")):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not _hex64(core.get("action_digest")):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not _validate_scope(core.get("scope")) or not _validate_anti_replay(core.get("anti_replay")):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    try:
        valid_from = parse_rfc3339(core.get("valid_from"))
        valid_to = parse_rfc3339(core.get("valid_to"))
    except TimeFormatError:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if valid_from > valid_to:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not _nonempty_string(auth.get("issuer_id")) or not _nonempty_string(auth.get("signature"), max_length=4096):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    return None


def validate_capability_schema(token: Any) -> Optional[str]:
    if not isinstance(token, Mapping):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    core = token.get("token_core")
    auth = token.get("authenticity")
    if not isinstance(core, Mapping) or not isinstance(auth, Mapping):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if CAPABILITY_CORE_REQUIRED - set(core) or AUTH_REQUIRED - set(auth):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if set(core) != CAPABILITY_CORE_REQUIRED:
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if set(auth) - {"issuer_id", "signature"}:
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if not _json_safe(token):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if not _hex64(core.get("action_digest")) or not _hex64(core.get("receipt_digest")):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    for field in ("policy_digest", "audience", "tenant_id"):
        if not _nonempty_string(core.get(field)):
            return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if not _strict_nonnegative_int(core.get("epoch_id")):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if not _nonempty_string(core.get("nonce"), max_length=MAX_NONCE_LENGTH):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    try:
        parse_rfc3339(core.get("valid_to"))
    except TimeFormatError:
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    if not _nonempty_string(auth.get("issuer_id")) or not _nonempty_string(auth.get("signature"), max_length=4096):
        return DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    return None


def validate_policy_state_schema(policy_state: Any) -> Optional[str]:
    if not isinstance(policy_state, Mapping):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    required = {
        "now",
        "policy_digest",
        "current_epoch_id",
        "canonicalization_profile_ref",
        "trusted_issuers",
        "trusted_authority_profile_ids",
        "trusted_assurance_level_ids",
        "trusted_permit_provenance_digests",
    }
    if required - set(policy_state) or set(policy_state) - _POLICY_ALLOWED_FIELDS:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    try:
        parse_rfc3339(policy_state.get("now"))
    except TimeFormatError:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not _nonempty_string(policy_state.get("policy_digest")) or not _nonempty_string(policy_state.get("canonicalization_profile_ref")):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in ("current_epoch_id", "minimum_epoch_id", "max_clock_drift_seconds", "revocation_max_age_seconds", "checkpoint_max_age_seconds"):
        if field in policy_state and not _strict_nonnegative_int(policy_state[field]):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "epoch_compatibility" in policy_state and policy_state["epoch_compatibility"] not in {"strict"}:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in _POLICY_BOOLEAN_FIELDS:
        if not _strict_bool_if_present(policy_state, field):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in ("trusted_issuers", "revocation_authorities", "transparency_logs", "trusted_capability_issuers"):
        if field in policy_state:
            value = policy_state[field]
            if not isinstance(value, Mapping) or not all(_nonempty_string(k) and _nonempty_string(v, max_length=4096) for k, v in value.items()):
                return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "offline_constrained_effect_types" in policy_state:
        value = policy_state["offline_constrained_effect_types"]
        if (
            not isinstance(value, list)
            or not _string_collection(value)
            or len(set(value)) != len(value)
        ):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in (
        "trusted_authority_profile_ids",
        "trusted_assurance_level_ids",
        "trusted_permit_provenance_digests",
    ):
        value = policy_state[field]
        if (
            not isinstance(value, list)
            or not _string_collection(value, allow_empty=False)
            or len(set(value)) != len(value)
        ):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not all(
        _is_prefixed_sha256(value)
        for value in policy_state["trusted_permit_provenance_digests"]
    ):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    return None


def _validate_replay_cache(value: Any) -> bool:
    if value is None:
        return True
    return all(callable(getattr(value, method, None)) for method in ("reserve", "contains"))


def validate_context_schema(context: Any) -> Optional[str]:
    if not isinstance(context, Mapping) or set(context) - _CONTEXT_ALLOWED_FIELDS:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "now" in context:
        try:
            parse_rfc3339(context["now"])
        except TimeFormatError:
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "clock_drift_seconds" in context and not is_strict_int(context["clock_drift_seconds"]):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in _CONTEXT_BOOLEAN_FIELDS:
        if not _strict_bool_if_present(context, field):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in ("used_nonces", "used_capability_nonces"):
        if field in context:
            value = context[field]
            if (
                not isinstance(value, list)
                or not _string_collection(value)
                or len(set(value)) != len(value)
            ):
                return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "epoch_sources" in context:
        sources = context["epoch_sources"]
        if (
            isinstance(sources, (str, bytes, bytearray, Mapping))
            or not isinstance(sources, (Sequence, Set))
            or len(sources) > MAX_LIST_ITEMS
            or any(
                not (_nonempty_string(item) or _strict_nonnegative_int(item))
                for item in sources
            )
        ):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in ("canonicalization_profile_ref", "jurisdiction", "resolved_tenant_id", "purpose_id"):
        if field in context and not _nonempty_string(context[field]):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "cross_log_coherence" in context and context["cross_log_coherence"] not in {"coherent", "conflict"}:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not _validate_replay_cache(context.get("replay_cache")) or not _validate_replay_cache(context.get("capability_replay_cache")):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "capability_token" in context and context["capability_token"] is not None and not isinstance(context["capability_token"], Mapping):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "identity_binding" in context and (
        not isinstance(context["identity_binding"], Mapping)
        or not _json_safe(context["identity_binding"])
    ):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "expected_receipt_digest" in context and not _hex64(context["expected_receipt_digest"]):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    return None


def validate_revocation_state_schema(revocation_state: Any) -> Optional[str]:
    if (
        not isinstance(revocation_state, Mapping)
        or "status" not in revocation_state
        or set(revocation_state) - _REVOCATION_ALLOWED_FIELDS
    ):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    status = revocation_state["status"]
    if not isinstance(status, str) or status not in _REVOCATION_STATUSES:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "last_updated" in revocation_state:
        try:
            parse_rfc3339(revocation_state["last_updated"])
        except TimeFormatError:
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    for field in ("revoked_receipt_digests", "revoked_issuers"):
        if field in revocation_state and not _string_collection(revocation_state[field]):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "revoked_receipt_digests" in revocation_state and not all(
        _hex64(item) for item in revocation_state["revoked_receipt_digests"]
    ):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    signed = revocation_state.get("signed_revocation_list")
    if signed is not None:
        if not isinstance(signed, Mapping):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        body = signed.get("body")
        auth = signed.get("authenticity")
        if not isinstance(body, Mapping) or not isinstance(auth, Mapping):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        required_body = {"issuer_id", "issued_at", "sequence", "revoked_receipt_digests", "revoked_issuers"}
        if required_body != set(body) or set(auth) != AUTH_REQUIRED:
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        if not _nonempty_string(body.get("issuer_id")) or not _strict_nonnegative_int(body.get("sequence")):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        try:
            parse_rfc3339(body.get("issued_at"))
        except TimeFormatError:
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        if not _string_collection(body.get("revoked_receipt_digests")) or not _string_collection(body.get("revoked_issuers")):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        if not all(_hex64(item) for item in body["revoked_receipt_digests"]):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        if (
            len(set(body["revoked_receipt_digests"])) != len(body["revoked_receipt_digests"])
            or len(set(body["revoked_issuers"])) != len(body["revoked_issuers"])
        ):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        if not _nonempty_string(auth.get("issuer_id")) or not _nonempty_string(auth.get("signature"), max_length=4096):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
        if not _json_safe(signed):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "merkle" in revocation_state and revocation_state["merkle"] is not None and not isinstance(revocation_state["merkle"], Mapping):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    return None
