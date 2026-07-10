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
AUTH_REF_CARRIER_PROFILE = "PermitReceipt.authorization-ref.carrier.public-eval.v1"
STANDALONE_PROFILE = "CP-JSON-2"
NOW = "2026-06-03T00:00:00Z"
VALID_FROM = "2026-06-02T00:00:00Z"
VALID_TO = "2026-06-04T00:00:00Z"
EXPIRED_TO = "2026-06-02T00:00:00Z"

# CP-JSON-2 resource and type limits. These are duplicated deliberately so the
# standalone packet does not depend on the repository package.
MAX_CANONICAL_DEPTH = 32
MAX_CONTAINER_ITEMS = 10_000
MAX_TOTAL_NODES = 50_000
MAX_STRING_UTF8_BYTES = 65_536
MAX_CANONICAL_BYTES = 1_048_576
MIN_PROFILE_INTEGER = -(2**63)
MAX_PROFILE_INTEGER = 2**63 - 1

try:  # Full-repository mode.
    from orprg_eval.canonicalization import SUPPORTED_PROFILE, canonicalize_request, compute_action_digest, digest_obj
    from orprg_eval.crypto import sign_object, verify_signature
    from orprg_eval.vector_factory import (
        ISSUER_KEY,
        base_context,
        base_policy,
        base_request,
        base_revocation,
        build_vectors,
        make_receipt,
    )
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


def _normalize_text_standalone(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("CP-JSON-2 rejects lone UTF-16 surrogate code points")
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized.encode("utf-8")) > MAX_STRING_UTF8_BYTES:
        raise ValueError("CP-JSON-2 string length limit exceeded")
    return normalized


def _normalize_standalone(
    value: Any,
    *,
    depth: int = 0,
    budget: Optional[List[int]] = None,
) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_TOTAL_NODES:
        raise ValueError("CP-JSON-2 node limit exceeded")
    if depth > MAX_CANONICAL_DEPTH:
        raise ValueError("CP-JSON-2 nesting limit exceeded")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value < MIN_PROFILE_INTEGER or value > MAX_PROFILE_INTEGER:
            raise ValueError("CP-JSON-2 integer outside signed 64-bit profile")
        return value
    if isinstance(value, float):
        raise ValueError("CP-JSON-2 rejects floating point inputs")
    if isinstance(value, str):
        return _normalize_text_standalone(value)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("CP-JSON-2 array item limit exceeded")
        return [
            _normalize_standalone(item, depth=depth + 1, budget=budget)
            for item in value
        ]
    if isinstance(value, Mapping):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("CP-JSON-2 object member limit exceeded")
        normalized: Dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("CP-JSON-2 object member names must be strings")
            normalized_key = _normalize_text_standalone(key)
            if normalized_key in normalized:
                raise ValueError(f"duplicate normalized key: {normalized_key}")
            normalized[normalized_key] = _normalize_standalone(
                item, depth=depth + 1, budget=budget
            )
        return {key: normalized[key] for key in sorted(normalized)}
    raise ValueError(f"unsupported canonicalization type: {type(value)!r}")


def canonicalize_standalone(
    obj: Mapping[str, Any], profile: str = STANDALONE_PROFILE
) -> bytes:
    if profile != STANDALONE_PROFILE:
        raise ValueError(f"unsupported canonicalization profile {profile}")
    if not isinstance(obj, Mapping):
        raise ValueError("canonicalize expects a mapping")
    encoded = json.dumps(
        _normalize_standalone(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ValueError("CP-JSON-2 canonical byte limit exceeded")
    return encoded


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
        "jurisdiction": "US",
        "canonicalization_profile_ref": profile,
        "authority_profile_id": "AP-SYNTH-AL5",
        "assurance_level_id": "AL5",
        "permit_provenance_digest": "sha256:25981c1dfe8af9109a3edaea029af66cbeca1f423ff3953b0007871a8effbf7a",
    }
    if core_overrides:
        core.update(copy.deepcopy(core_overrides))
    return {
        "receipt_core": core,
        "authenticity": {
            "issuer_id": core["issuer_id"],
            "signature": sha256_hex(("synthetic-signature:" + digest_obj_standalone(core)).encode("utf-8")),
        },
    }


def base_revocation_standalone(receipt: Optional[Dict[str, Any]] = None, *, status: str = "fresh") -> Dict[str, Any]:
    return {
        "status": status,
        "last_updated": "2026-06-02T23:59:40Z",
        "signed_revocation_list": {
            "body": {
                "issuer_id": "revocation-authority-synth",
                "issued_at": "2026-06-02T23:59:40Z",
                "sequence": 100,
                "revoked_receipt_digests": [],
                "revoked_issuers": [],
            },
            "authenticity": {
                "issuer_id": "revocation-authority-synth",
                "signature": "standalone-synthetic-signature",
            },
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
        if request.get("max_effect_budget", 0) > scope.get("max_effect_budget", 0):
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
    req_budget_omitted = copy.deepcopy(req); del req_budget_omitted["max_effect_budget"]
    add("KNEG-SCOPE-VIOLATION-BUDGET-OMITTED", "Receipt scope requires max_effect_budget but request omits it.", STANDALONE_DRC["SCOPE_VIOLATION"], request=req_budget_omitted, receipt=make_receipt_standalone(req_budget_omitted, scope=base_scope_standalone(), nonce="scope-budget-omitted"))
    add("KNEG-VALIDITY-EXPIRED", "Receipt validity window is expired.", STANDALONE_DRC["VALIDITY_WINDOW_EXPIRED"], receipt=make_receipt_standalone(req, core_overrides={"valid_to": EXPIRED_TO}, nonce="expired"))
    add("KNEG-REVOCATION-STATE-STALE", "Revocation/status evidence is stale.", STANDALONE_DRC["REVOCATION_UNKNOWN_OR_STALE"], revocation=base_revocation_standalone(base_rec, status="stale"))
    add("KNEG-ANTI-REPLAY-NONCE-REUSE", "Receipt nonce reuse is denied.", STANDALONE_DRC["ANTI_REPLAY_FAILURE"], receipt=base_rec, context={**base_context_standalone(), "used_nonces": ["nonce-standalone"]})
    add("KNEG-CANONICALIZATION-PROFILE-MISMATCH", "Unsupported canonicalization profile is denied.", STANDALONE_DRC["CANONICALIZATION_PROFILE_MISMATCH"], receipt=make_receipt_standalone(req, core_overrides={"canonicalization_profile_ref": "CP-OLD"}, nonce="canon"))
    pol_t = copy.deepcopy(pol); pol_t["require_transparency"] = True
    add("KNEG-TRANSPARENCY-PROOF-MISSING", "Required transparency proof is missing.", STANDALONE_DRC["TRANSPARENCY_PROOF_MISSING"], policy=pol_t)
    return vectors


def _sha256_commitment(text: str, *, domain: str) -> str:
    framed = domain.encode("utf-8") + b"\x00" + text.encode("utf-8")
    return "sha256:" + hashlib.sha256(framed).hexdigest()


def _prefixed_sha256(value: str) -> str:
    return value if value.startswith("sha256:") else "sha256:" + value


def crossref_decision(ref: Any, *, expected_action_commitment: str, supported_profile: str) -> Dict[str, Any]:
    """Strict public-eval checker for a signature-covered authorization reference.

    The checker validates the exact selected field model and fail-closed
    semantics.  It does not claim that a boolean marker proves a carrier
    signature; the carrying artifact still has to authenticate these fields.
    """
    if not isinstance(ref, dict):
        return {"decision": "DENY", "reason": "AUTHREF_NOT_AN_OBJECT"}
    if ("action_id" in ref or "action_type" in ref) and "action_commitment" not in ref:
        return {"decision": "DENY", "reason": "AUTHREF_NAME_ONLY_NON_AUTHORIZING"}
    required = {
        "ref_profile", "ref_kind", "ref_artifact_digest", "issuer_or_signer",
        "digest_algorithm", "canonicalization_profile_ref", "domain_sep",
        "action_commitment", "audience", "scope", "valid_from", "valid_until",
        "policy_epoch", "anti_replay", "signature_coverage", "status",
        "verifier_behavior",
    }
    allowed = required | {"ref_artifact_id", "key_id"}
    missing = sorted(required - set(ref))
    if missing:
        return {"decision": "DENY", "reason": "AUTHREF_REQUIRED_FIELD_MISSING", "missing": missing}
    unknown = sorted(set(ref) - allowed)
    if unknown:
        return {"decision": "DENY", "reason": "AUTHREF_UNKNOWN_FIELD", "unknown": unknown}
    if ref.get("ref_profile") != AUTH_REF_PROFILE:
        return {"decision": "DENY", "reason": "AUTHREF_PROFILE_UNSUPPORTED"}
    if ref.get("signature_coverage") is not True:
        return {"decision": "DENY", "reason": "AUTHREF_NOT_SIGNATURE_COVERED"}
    if ref.get("digest_algorithm") != "sha-256":
        return {"decision": "DENY", "reason": "AUTHREF_DIGEST_ALGORITHM_UNSUPPORTED"}
    if ref.get("canonicalization_profile_ref") != supported_profile:
        return {"decision": "DENY", "reason": "AUTHREF_CANONICALIZATION_PROFILE_UNSUPPORTED"}
    if ref.get("domain_sep") != "PermitReceipt.authorization_ref.public-eval.v2":
        return {"decision": "DENY", "reason": "AUTHREF_DOMAIN_SEPARATOR_MISMATCH"}
    expected = _prefixed_sha256(expected_action_commitment)
    if ref.get("action_commitment") != expected:
        return {"decision": "DENY", "reason": "AUTHREF_ACTION_COMMITMENT_MISMATCH"}
    for digest_field in ("ref_artifact_digest", "action_commitment"):
        value = ref.get(digest_field)
        if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
            return {"decision": "DENY", "reason": "AUTHREF_DIGEST_MALFORMED", "field": digest_field}
        try:
            int(value[7:], 16)
        except ValueError:
            return {"decision": "DENY", "reason": "AUTHREF_DIGEST_MALFORMED", "field": digest_field}
    if not isinstance(ref.get("issuer_or_signer"), str) or not ref["issuer_or_signer"]:
        return {"decision": "DENY", "reason": "AUTHREF_ISSUER_MALFORMED"}
    if not isinstance(ref.get("audience"), str) or not ref["audience"]:
        return {"decision": "DENY", "reason": "AUTHREF_AUDIENCE_MALFORMED"}
    if not isinstance(ref.get("policy_epoch"), int) or isinstance(ref.get("policy_epoch"), bool) or ref["policy_epoch"] < 0:
        return {"decision": "DENY", "reason": "AUTHREF_POLICY_EPOCH_MALFORMED"}
    scope = ref.get("scope")
    required_scope = {"effect_type", "interface_id", "action_type", "target_id", "tenant_id", "purpose_id"}
    if not isinstance(scope, dict) or required_scope - set(scope) or any(not isinstance(scope.get(k), str) or not scope.get(k) for k in required_scope):
        return {"decision": "DENY", "reason": "AUTHREF_SCOPE_MALFORMED"}
    anti_replay = ref.get("anti_replay")
    nonce_commitment = anti_replay.get("nonce_commitment") if isinstance(anti_replay, dict) else None
    if set(anti_replay or {}) != {"nonce_commitment"} or not isinstance(nonce_commitment, str) or len(nonce_commitment) != 71 or not nonce_commitment.startswith("sha256:"):
        return {"decision": "DENY", "reason": "AUTHREF_ANTI_REPLAY_MALFORMED"}
    if ref.get("status") != "valid":
        return {"decision": "DENY", "reason": "AUTHREF_STATUS_NOT_VALID"}
    behavior = ref.get("verifier_behavior")
    expected_behavior = {
        "on_unsupported_profile": "DENY",
        "on_mismatch": "DENY",
        "on_unverifiable": "DENY",
    }
    if behavior != expected_behavior:
        return {"decision": "DENY", "reason": "AUTHREF_FAILURE_BEHAVIOR_NOT_FAIL_CLOSED"}
    return {"decision": "BOUND", "reason": None}


def make_authorization_ref(receipt: Dict[str, Any], action_digest: str, *, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    core = receipt["receipt_core"]
    if HAVE_ORPRG_EVAL:
        artifact_digest = digest_obj(core)
    else:
        artifact_digest = digest_obj_standalone(core)
    scope = core.get("scope", {})
    nonce = (core.get("anti_replay") or {}).get("nonce", "")
    ref: Dict[str, Any] = {
        "ref_profile": AUTH_REF_PROFILE,
        "ref_kind": "PermitReceipt",
        "ref_artifact_digest": _prefixed_sha256(artifact_digest),
        "issuer_or_signer": receipt["authenticity"]["issuer_id"],
        "digest_algorithm": "sha-256",
        "canonicalization_profile_ref": core.get("canonicalization_profile_ref", SUPPORTED_PROFILE),
        "domain_sep": "PermitReceipt.authorization_ref.public-eval.v2",
        "action_commitment": _prefixed_sha256(action_digest),
        "audience": scope.get("interface_id"),
        "scope": {
            key: scope[key]
            for key in (
                "effect_type", "interface_id", "action_type", "target_id",
                "tenant_id", "purpose_id", "representation_class_id",
                "artifact_id", "key_id", "key_op", "key_ops", "max_effect_budget",
            )
            if key in scope
        },
        "valid_from": core.get("valid_from"),
        "valid_until": core.get("valid_to"),
        "policy_epoch": core.get("epoch_id"),
        "anti_replay": {
            "nonce_commitment": _sha256_commitment(
                str(nonce), domain="PermitReceipt.authorization_ref.nonce.public-eval.v2"
            )
        },
        "signature_coverage": True,
        "status": "valid",
        "verifier_behavior": {
            "on_unsupported_profile": "DENY",
            "on_mismatch": "DENY",
            "on_unverifiable": "DENY",
        },
    }
    if overrides:
        ref.update(overrides)
    return ref


def make_authorization_ref_carrier(authorization_ref: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Create an actually signed carrier in full-repository mode.

    Standalone packet mode intentionally returns ``None`` because the standard
    library does not provide Ed25519. It never fabricates cryptographic proof.
    """

    if not HAVE_ORPRG_EVAL:
        return None
    body = {
        "carrier_profile": AUTH_REF_CARRIER_PROFILE,
        "authorization_ref": dict(authorization_ref),
    }
    return {
        "carrier": body,
        "authenticity": {
            "issuer_id": authorization_ref["issuer_or_signer"],
            "signature_algorithm": "ed25519",
            "signature": sign_object(ISSUER_KEY, body),
        },
    }


def crossref_carrier_decision(
    carrier: Any,
    *,
    expected_action_commitment: str,
    supported_profile: str,
    trusted_issuers: Mapping[str, str],
) -> Dict[str, Any]:
    """Authenticate the carrier before interpreting its authorization_ref."""

    if not HAVE_ORPRG_EVAL:
        return {"decision": "DENY", "reason": "AUTHREF_CRYPTO_UNAVAILABLE_IN_STANDALONE_MODE"}
    if not isinstance(carrier, dict) or set(carrier) != {"carrier", "authenticity"}:
        return {"decision": "DENY", "reason": "AUTHREF_CARRIER_MALFORMED"}
    body = carrier.get("carrier")
    authenticity = carrier.get("authenticity")
    if not isinstance(body, dict) or set(body) != {"carrier_profile", "authorization_ref"}:
        return {"decision": "DENY", "reason": "AUTHREF_CARRIER_BODY_MALFORMED"}
    if body.get("carrier_profile") != AUTH_REF_CARRIER_PROFILE:
        return {"decision": "DENY", "reason": "AUTHREF_CARRIER_PROFILE_UNSUPPORTED"}
    if not isinstance(authenticity, dict) or set(authenticity) != {
        "issuer_id", "signature_algorithm", "signature"
    }:
        return {"decision": "DENY", "reason": "AUTHREF_CARRIER_AUTHENTICITY_MALFORMED"}
    if authenticity.get("signature_algorithm") != "ed25519":
        return {"decision": "DENY", "reason": "AUTHREF_CARRIER_SIGNATURE_ALGORITHM_UNSUPPORTED"}
    authorization_ref = body.get("authorization_ref")
    issuer_id = authenticity.get("issuer_id")
    if not isinstance(authorization_ref, dict) or issuer_id != authorization_ref.get("issuer_or_signer"):
        return {"decision": "DENY", "reason": "AUTHREF_CARRIER_ISSUER_MISMATCH"}
    public_key = trusted_issuers.get(issuer_id) if isinstance(issuer_id, str) else None
    if not isinstance(public_key, str):
        return {"decision": "DENY", "reason": "AUTHREF_CARRIER_ISSUER_UNTRUSTED"}
    if not verify_signature(public_key, authenticity.get("signature"), body):
        return {"decision": "DENY", "reason": "AUTHREF_CARRIER_SIGNATURE_INVALID"}
    return crossref_decision(
        authorization_ref,
        expected_action_commitment=expected_action_commitment,
        supported_profile=supported_profile,
    )


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
    authorization_ref_carrier = make_authorization_ref_carrier(authorization_ref)
    authorization_ref_carrier_result = (
        crossref_carrier_decision(
            authorization_ref_carrier,
            expected_action_commitment=action_digest,
            supported_profile=SUPPORTED_PROFILE,
            trusted_issuers=policy_state.get("trusted_issuers", {}),
        )
        if authorization_ref_carrier is not None
        else {"decision": "NOT_RUN", "reason": "standalone_mode_has_no_ed25519"}
    )

    one_action: Dict[str, Any] = {
        "packet": "IETF126-ORPRG-one-protected-action-v2",
        "runner_mode": runner_mode,
        "synthetic": True,
        "public_boundary": "Synthetic public artifact only; no production credentials, no live payment, no customer data, no regulated data.",
        "canonicalization_profile_ref": SUPPORTED_PROFILE,
        "digest_algorithm": "sha-256",
        "domain_sep": "PermitReceipt.action.public-eval.v2",
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
            "trusted_issuers": policy_state.get("trusted_issuers", {}),
            "revocation_authorities": policy_state.get("revocation_authorities", {}),
        },
        "revocation_state_public_subset": {
            "status": revocation_state["status"],
            "last_updated": revocation_state["last_updated"],
            "signed_revocation_list_digest": signed_revocation_list_digest,
            "signed_revocation_list": revocation_state.get("signed_revocation_list"),
        },
        "verifier_result": verifier_result,
        "authorization_ref_sample": authorization_ref,
        "authorization_ref_sample_result": authorization_ref_result,
        "authorization_ref_carrier": authorization_ref_carrier,
        "authorization_ref_carrier_result": authorization_ref_carrier_result,
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
            "ref": make_authorization_ref(receipt, "de" * 32, overrides={}),
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
    if authorization_ref_carrier is not None:
        tampered_signature = copy.deepcopy(authorization_ref_carrier)
        tampered_signature["authenticity"]["signature"] = (
            "A" + tampered_signature["authenticity"]["signature"][1:]
        )
        tampered_ref = copy.deepcopy(authorization_ref_carrier)
        tampered_ref["carrier"]["authorization_ref"]["action_commitment"] = "sha256:" + ("00" * 32)
        carrier_cases = [
            {
                "case_id": "AUTHREF-CARRIER-POS-VALID-SIGNATURE",
                "description": "Ed25519-authenticated carrier covers the selected authorization_ref.",
                "carrier": authorization_ref_carrier,
                "expected_decision": "BOUND",
            },
            {
                "case_id": "AUTHREF-CARRIER-NEG-SIGNATURE-TAMPER",
                "description": "A changed carrier signature fails closed.",
                "carrier": tampered_signature,
                "expected_decision": "DENY",
            },
            {
                "case_id": "AUTHREF-CARRIER-NEG-REF-TAMPER",
                "description": "Changing a signed authorization_ref commitment invalidates the carrier.",
                "carrier": tampered_ref,
                "expected_decision": "DENY",
            },
        ]
    else:
        carrier_cases = []

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
    for case in carrier_cases:
        observed = crossref_carrier_decision(
            case["carrier"],
            expected_action_commitment=action_digest,
            supported_profile=SUPPORTED_PROFILE,
            trusted_issuers=policy_state.get("trusted_issuers", {}),
        )
        crossref_results.append({
            "case_id": case["case_id"],
            "description": case["description"],
            "expected_decision": case["expected_decision"],
            "observed": observed,
            "pass": observed["decision"] == case["expected_decision"],
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
        "domain_sep": "PermitReceipt.action.public-eval.v2",
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
        "- action domain separator: `PermitReceipt.action.public-eval.v2`; authorization_ref domain separator: `PermitReceipt.authorization_ref.public-eval.v2`",
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
