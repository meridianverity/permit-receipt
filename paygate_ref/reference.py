from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

from orprg_eval.canonicalization import canonicalize_request, compute_action_digest, digest_obj
from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.replay import ReplayCache
from orprg_eval.verifier import verify_permit_receipt
from orprg_eval.vector_factory import (
    base_context,
    base_policy,
    base_revocation,
    make_receipt,
    make_revocation_state,
)


def payment_request(*, amount_cents: int = 2499, merchant_id: str = "merchant-alpha", agent_id: str = "agent:demo:001", audience: str = "paygate-ref-psp-adapter", purpose: str = "agentic_purchase", cart_digest: str = "cart:sha256:demo-001") -> Dict[str, Any]:
    """Create a deterministic, synthetic payment-adjacent external-effect request.

    The request intentionally contains no PAN, SAD, network token, live customer data, or live
    merchant secrets. It is shaped as an external-effect request so the ORPRG verifier can bind
    authorization to exact effect fields before a fake PSP adapter is allowed to proceed.
    """
    return {
        "effect_type": "PAYMENT_ATTEMPT",
        "interface_id": audience,
        "action_type": "AUTHORIZE_SANDBOX",
        "target_id": merchant_id,
        "tenant_id": "tenant-A",
        "purpose_id": purpose,
        "representation_class_id": "json-v1",
        "max_effect_budget": amount_cents,
        "payload_digest": cart_digest,
        "agent_id": agent_id,
        "merchant_id": merchant_id,
        "currency": "USD",
        "cart_digest": cart_digest,
    }


def payment_scope(req: Dict[str, Any], *, max_amount_cents: Optional[int] = None) -> Dict[str, Any]:
    return {
        "effect_type": req["effect_type"],
        "interface_id": req["interface_id"],
        "action_type": req["action_type"],
        "target_id": req["target_id"],
        "tenant_id": req["tenant_id"],
        "purpose_id": req["purpose_id"],
        "representation_class_id": req["representation_class_id"],
        "max_effect_budget": int(max_amount_cents if max_amount_cents is not None else req["max_effect_budget"]),
    }


def policy_state(*, require_capability_token: bool = False) -> Dict[str, Any]:
    policy = base_policy()
    policy.update({
        "policy_digest": "policy-digest-paygate-ref-v0.1",
        "current_epoch_id": 72,
        "minimum_epoch_id": 72,
        "require_capability_token": require_capability_token,
        "require_purpose": True,
        "require_identity_binding": False,
        "require_permit_provenance": True,
        "require_assurance_evidence": False,
    })
    return policy


def context_state(*, replay_cache: Optional[ReplayCache] = None) -> Dict[str, Any]:
    ctx = base_context()
    ctx.update({
        "now": "2026-06-03T00:00:00Z",
        "jurisdiction": "US",
        "resolved_tenant_id": "tenant-A",
        "purpose_id": "agentic_purchase",
    })
    if replay_cache is not None:
        ctx["replay_cache"] = replay_cache
    return ctx


def issue_payment_permit(req: Dict[str, Any], *, scope: Optional[Dict[str, Any]] = None, nonce: str = "paygate-nonce-001", policy: Optional[Dict[str, Any]] = None, valid_to: Optional[str] = None, permit_provenance_digest: Optional[str] = "permit-paygate-ref-001") -> Dict[str, Any]:
    pol = policy or policy_state()
    overrides: Dict[str, Any] = {}
    if valid_to is not None:
        overrides["valid_to"] = valid_to
    return make_receipt(
        req,
        pol,
        scope=scope or payment_scope(req),
        nonce=nonce,
        permit_provenance_digest=permit_provenance_digest,
        core_overrides=overrides or None,
    )


def verify_payment_attempt(req: Dict[str, Any], receipt: Optional[Dict[str, Any]], *, policy: Optional[Dict[str, Any]] = None, revocation_state: Optional[Dict[str, Any]] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    pol = policy or policy_state()
    rev = revocation_state if revocation_state is not None else base_revocation(receipt if isinstance(receipt, dict) else None)
    ctx = context if context is not None else context_state()
    result = verify_permit_receipt(req, receipt, pol, rev, ctx)
    return result.to_dict()


def fake_psp_adapter(req: Dict[str, Any], verification_result: Dict[str, Any]) -> Dict[str, Any]:
    """Synthetic PSP adapter: no PAN, no real auth, no settlement.

    The adapter only records whether the payment-adjacent effect would be allowed to cross the
    sandbox boundary. This is the safe PAYGATE-Ref demonstration of fail-closed behavior.
    """
    action_digest = compute_action_digest(canonicalize_request(req))
    if verification_result["decision"] == ALLOW:
        status = "AUTHORIZED_SANDBOX"
        psp_status = 202
    else:
        status = "BLOCKED_FAIL_CLOSED"
        psp_status = 403
    return {
        "adapter": "fake_psp_adapter_v0_1",
        "status": status,
        "http_status": psp_status,
        "action_digest": action_digest,
        "payment_attempt_digest": digest_obj({
            "adapter": "fake_psp_adapter_v0_1",
            "request_action_digest": action_digest,
            "decision": verification_result["decision"],
            "denial_reason_code": verification_result.get("denial_reason_code"),
        }),
        "live_pan_used": False,
        "live_network_settlement": False,
    }


def build_execution_receipt(req: Dict[str, Any], permit_receipt: Optional[Dict[str, Any]], verification_result: Dict[str, Any], adapter_result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "receipt_type": "AgenticCommerceExecutionReceipt",
        "version": "0.1",
        "receipt_id": "acr_" + digest_obj({"req": req, "permit": permit_receipt, "adapter": adapter_result})[:24],
        "intent_ref": {
            "intent_protocol": "AP2|VerifiableIntent|TAP|Other",
            "intent_digest": "sha256:intent-demo-001",
            "delegation_scope": "merchant|category|amount|time|item",
        },
        "agent_ref": {
            "agent_id": req.get("agent_id"),
            "proof_of_possession": "synthetic-pop-bound-to-request-digest",
        },
        "merchant_request": {
            "merchant_id": req.get("merchant_id"),
            "request_digest": compute_action_digest(canonicalize_request(req)),
            "cart_or_order_digest": req.get("cart_digest"),
            "recipient_endpoint": req.get("interface_id"),
        },
        "execution_authorization": {
            "policy_profile": "paygate-ref-profile-v0.1",
            "policy_epoch": verification_result.get("evidence_digests", {}).get("epoch_id"),
            "scope_result": "PASS" if verification_result["decision"] == ALLOW else "FAIL",
            "reason_codes": [] if verification_result["decision"] == ALLOW else [verification_result.get("denial_reason_code")],
            "revocation_status": "CLEAR" if verification_result["decision"] == ALLOW else "UNKNOWN_OR_FAILED",
            "freshness_window_ms": 300000,
        },
        "payment_attempt": {
            "payment_attempt_digest": adapter_result["payment_attempt_digest"],
            "network_token_ref": "token_ref_redacted_sandbox_only",
            "authorization_trace_digest": adapter_result["payment_attempt_digest"],
            "settlement_state": "NOT_ATTEMPTED_LIVE_SANDBOX",
            "live_pan_used": False,
            "live_network_settlement": False,
        },
        "verification": {
            "verifier_id": "did:paygate-ref:verifier:001",
            "decision": verification_result["decision"],
            "denial_reason_code": verification_result.get("denial_reason_code"),
            "evidence_digests": verification_result.get("evidence_digests", {}),
        },
        "disclosure_views": ["merchant_view", "issuer_view", "consumer_view", "dispute_view", "audit_view"],
    }


def build_dispute_packet(execution_receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Build a selective-disclosure packet for simulated recourse/dispute review."""
    return {
        "packet_type": "AgenticCommerceDisputeRecoursePacket",
        "version": "0.1",
        "packet_id": "drp_" + digest_obj(execution_receipt)[:24],
        "summary": {
            "receipt_id": execution_receipt["receipt_id"],
            "merchant_id": execution_receipt["merchant_request"].get("merchant_id"),
            "agent_id": execution_receipt["agent_ref"].get("agent_id"),
            "decision": execution_receipt["verification"]["decision"],
            "denial_reason_code": execution_receipt["verification"].get("denial_reason_code"),
        },
        "selective_disclosure_views": {
            "merchant_view": {
                "request_digest": execution_receipt["merchant_request"]["request_digest"],
                "scope_result": execution_receipt["execution_authorization"]["scope_result"],
                "reason_codes": execution_receipt["execution_authorization"]["reason_codes"],
            },
            "issuer_or_acquirer_view": {
                "intent_digest": execution_receipt["intent_ref"]["intent_digest"],
                "authorization_trace_digest": execution_receipt["payment_attempt"]["authorization_trace_digest"],
                "verification": execution_receipt["verification"],
            },
            "consumer_view": {
                "merchant_id": execution_receipt["merchant_request"].get("merchant_id"),
                "cart_or_order_digest": execution_receipt["merchant_request"].get("cart_or_order_digest"),
                "decision": execution_receipt["verification"]["decision"],
            },
            "audit_view": execution_receipt,
        },
        "raw_pan_or_sad_present": False,
    }


def scenario_in_scope_purchase() -> Dict[str, Any]:
    req = payment_request()
    pol = policy_state()
    receipt = issue_payment_permit(req, policy=pol, nonce="nonce-in-scope-001")
    vr = verify_payment_attempt(req, receipt, policy=pol)
    adapter = fake_psp_adapter(req, vr)
    execution_receipt = build_execution_receipt(req, receipt, vr, adapter)
    return {
        "scenario": "A_IN_SCOPE_AGENT_PURCHASE",
        "request": req,
        "permit_receipt": receipt,
        "verification_result": vr,
        "adapter_result": adapter,
        "execution_receipt": execution_receipt,
    }


def scenario_out_of_scope_or_stale_request() -> Dict[str, Any]:
    req = payment_request(amount_cents=9999)
    pol = policy_state()
    # Permit scope authorizes only up to 2500 cents, but request is for 9999 cents.
    receipt = issue_payment_permit(req, policy=pol, scope=payment_scope(req, max_amount_cents=2500), nonce="nonce-out-of-scope-001")
    vr = verify_payment_attempt(req, receipt, policy=pol)
    adapter = fake_psp_adapter(req, vr)
    execution_receipt = build_execution_receipt(req, receipt, vr, adapter)
    return {
        "scenario": "B_OUT_OF_SCOPE_HOLD_OR_FAIL",
        "request": req,
        "permit_receipt": receipt,
        "verification_result": vr,
        "adapter_result": adapter,
        "execution_receipt": execution_receipt,
    }


def scenario_revoked_request() -> Dict[str, Any]:
    req = payment_request(merchant_id="merchant-beta", cart_digest="cart:sha256:demo-revoked")
    pol = policy_state()
    receipt = issue_payment_permit(req, policy=pol, nonce="nonce-revoked-001")
    receipt_digest = digest_obj(receipt["receipt_core"])
    rev = make_revocation_state(revoked_receipts=[receipt_digest])
    vr = verify_payment_attempt(req, receipt, policy=pol, revocation_state=rev)
    adapter = fake_psp_adapter(req, vr)
    execution_receipt = build_execution_receipt(req, receipt, vr, adapter)
    return {
        "scenario": "B2_REVOKED_DELEGATION_FAIL_CLOSED",
        "request": req,
        "permit_receipt": receipt,
        "verification_result": vr,
        "adapter_result": adapter,
        "execution_receipt": execution_receipt,
    }


def scenario_replay_attempt() -> Dict[str, Any]:
    req = payment_request(merchant_id="merchant-gamma", cart_digest="cart:sha256:demo-replay")
    pol = policy_state()
    receipt = issue_payment_permit(req, policy=pol, nonce="nonce-replay-001")
    cache = ReplayCache()
    ctx = context_state(replay_cache=cache)
    first = verify_payment_attempt(req, receipt, policy=pol, context=ctx)
    second = verify_payment_attempt(req, receipt, policy=pol, context=ctx)
    adapter = fake_psp_adapter(req, second)
    execution_receipt = build_execution_receipt(req, receipt, second, adapter)
    return {
        "scenario": "B3_REPLAY_ATTEMPT_FAIL_CLOSED",
        "request": req,
        "permit_receipt": receipt,
        "first_verification_result": first,
        "second_verification_result": second,
        "adapter_result": adapter,
        "execution_receipt": execution_receipt,
    }


def scenario_dispute_packet() -> Dict[str, Any]:
    base = scenario_in_scope_purchase()
    dispute = build_dispute_packet(base["execution_receipt"])
    return {
        "scenario": "C_DISPUTED_TRANSACTION_SELECTIVE_DISCLOSURE",
        "base_execution_receipt": base["execution_receipt"],
        "dispute_packet": dispute,
    }


def run_all_scenarios() -> Dict[str, Any]:
    scenarios = [
        scenario_in_scope_purchase(),
        scenario_out_of_scope_or_stale_request(),
        scenario_revoked_request(),
        scenario_replay_attempt(),
        scenario_dispute_packet(),
    ]
    summary_rows: List[Dict[str, Any]] = []
    for s in scenarios:
        if "verification_result" in s:
            result = s["verification_result"]
        elif "second_verification_result" in s:
            result = s["second_verification_result"]
        else:
            result = {"decision": s["dispute_packet"]["summary"]["decision"], "denial_reason_code": s["dispute_packet"]["summary"].get("denial_reason_code")}
        summary_rows.append({
            "scenario": s["scenario"],
            "decision": result.get("decision"),
            "denial_reason_code": result.get("denial_reason_code"),
            "live_pan_used": False,
            "live_network_settlement": False,
        })
    return {
        "package": "PAYGATE-Ref ORPRG Agentic Commerce Demo",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "synthetic_reference_only": True,
        "no_live_pan": True,
        "no_live_network_settlement": True,
        "scenarios": scenarios,
        "summary": summary_rows,
    }
