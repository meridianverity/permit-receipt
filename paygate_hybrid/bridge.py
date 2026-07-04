from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from orprg_eval.canonicalization import canonicalize_request, compute_action_digest, digest_obj
from paygate_poc.canonical import digest as paygate_digest
from paygate_poc.tsil import sensor_core_digest


def payment_action_to_orprg_effect(action: Mapping[str, Any], *, interface_id: str = "paygate-provider-neutral-effect-boundary") -> dict[str, Any]:
    """Translate a domain PaymentAction into an ORPRG external-effect request.

    The provider adapter ID is intentionally not included. The ORPRG effect is the exact
    semantic payment-attempt boundary: tenant, agent, purpose, merchant, currency, total,
    cart digest, idempotency key, and TSIL evidence digest. Provider choice is enforced as
    a domain scope constraint after the generic ORPRG predicate passes.
    """
    cart_digest = paygate_digest(action.get("cart", []))
    semantic_payload_digest = paygate_digest({
        "payment_action_type": action.get("type"),
        "payment_action_version": action.get("version"),
        "tenant_id": action.get("tenant_id"),
        "agent_id": action.get("agent_id"),
        "purpose_id": action.get("purpose_id"),
        "merchant_id": action.get("merchant", {}).get("merchant_id"),
        "cart_digest": cart_digest,
        "totals": action.get("totals"),
        "capture_mode": action.get("payment", {}).get("capture_mode"),
        "idempotency_key": action.get("payment", {}).get("idempotency_key"),
        "sensor_receipt_core_digest": action.get("context", {}).get("sensor_receipt_core_digest"),
    })
    return {
        "effect_type": "PAYMENT_ATTEMPT",
        "interface_id": interface_id,
        "action_type": "AUTHORIZE_SANDBOX",
        "target_id": action.get("merchant", {}).get("merchant_id"),
        "tenant_id": action.get("tenant_id"),
        "purpose_id": action.get("purpose_id"),
        "representation_class_id": "json-v1",
        "max_effect_budget": int(action.get("totals", {}).get("total_minor", 0)),
        "payload_digest": semantic_payload_digest,
        "agent_id": action.get("agent_id"),
        "merchant_id": action.get("merchant", {}).get("merchant_id"),
        "currency": action.get("totals", {}).get("currency"),
        "cart_digest": cart_digest,
        "idempotency_key": action.get("payment", {}).get("idempotency_key"),
        "sensor_receipt_core_digest": action.get("context", {}).get("sensor_receipt_core_digest"),
    }


def orprg_action_digest(orprg_request: Mapping[str, Any]) -> str:
    return compute_action_digest(canonicalize_request(orprg_request))


def make_tetpay(
    *,
    payment_action: Mapping[str, Any],
    sensor_receipt: Mapping[str, Any] | None,
    orprg_request: Mapping[str, Any],
    orprg_result: Mapping[str, Any],
    paygate_result: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Build an evidence-only PAYGATE Transaction Evidence Tuple.

    TETpay is not the gate. It is the portable audit object tying ORPRG, TSIL,
    PayGate decision receipt, and provider-commit evidence together.
    """
    decision_receipt = (paygate_result or {}).get("decision_receipt")
    provider_result = (paygate_result or {}).get("provider_result")
    return {
        "type": "TETpay",
        "version": "2.0-hybrid",
        "evidence_only": True,
        "semantics": "cross-rail references do not alter ORPRG, TSIL, or PayGate gate predicates",
        "refs": {
            "payment_action_digest": paygate_digest(payment_action),
            "cart_digest": paygate_digest(payment_action.get("cart", [])),
            "sensor_receipt_core_digest": sensor_core_digest(sensor_receipt) if sensor_receipt else None,
            "orprg_action_digest": orprg_action_digest(orprg_request),
            "orprg_verifier_result_digest": digest_obj(orprg_result),
            "paygate_decision_receipt_digest": paygate_digest(decision_receipt) if decision_receipt else None,
            "provider_commit_digest": paygate_digest(provider_result) if provider_result else None,
        },
        "decision": {
            "orprg": orprg_result.get("decision"),
            "paygate": (paygate_result or {}).get("outcome"),
            "provider": (provider_result or {}).get("provider_status") if provider_result else None,
        },
    }


def validate_tetpay(tetpay: Mapping[str, Any], *, payment_action: Mapping[str, Any], sensor_receipt: Mapping[str, Any] | None, orprg_request: Mapping[str, Any], orprg_result: Mapping[str, Any], paygate_result: Mapping[str, Any] | None) -> dict[str, Any]:
    expected = make_tetpay(payment_action=payment_action, sensor_receipt=sensor_receipt, orprg_request=orprg_request, orprg_result=orprg_result, paygate_result=paygate_result)
    mismatches = []
    for key, expected_value in expected["refs"].items():
        actual_value = tetpay.get("refs", {}).get(key)
        if actual_value != expected_value:
            mismatches.append({"field": key, "expected": expected_value, "actual": actual_value})
    return {"status": "PASS" if not mismatches else "FAIL", "mismatches": mismatches}


def tamper_tetpay(tetpay: Mapping[str, Any], *, field: str = "cart_digest") -> dict[str, Any]:
    out = deepcopy(tetpay)
    out.setdefault("refs", {})[field] = "sha256:tampered"
    return out
