from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import digest, parse_utc, utc_now_iso, without_signature
from .keys import verify_signature

DECISION_CONTEXT = "PAYGATE/DECISION/v1"


class SimulatedPaymentProvider:
    """Provider-neutral adapter boundary.

    The provider simulator refuses commits unless a valid PayGate decision
    receipt is presented. This models dual enforcement: even if an agent tries
    to bypass the PayGate service and call the adapter directly, the adapter
    cannot commit the payment without the gate-issued token.
    """

    def __init__(self, adapter_id: str, provider_class: str, supported_merchants: set[str]):
        self.adapter_id = adapter_id
        self.provider_class = provider_class
        self.supported_merchants = set(supported_merchants)
        self.used_decision_ids: set[str] = set()

    def supports_merchant(self, merchant_id: str) -> bool:
        return merchant_id in self.supported_merchants

    def commit(self, action: dict[str, Any], decision_receipt: dict[str, Any] | None, gate_public_key: Ed25519PublicKey, now: str | None = None) -> dict[str, Any]:
        now = now or utc_now_iso()
        if not decision_receipt:
            return {"provider_status": "DENIED", "reason_codes": ["PROVIDER_DECISION_TOKEN_REQUIRED"], "adapter_id": self.adapter_id}
        unsigned = without_signature(decision_receipt)
        if not verify_signature(gate_public_key, DECISION_CONTEXT, unsigned, decision_receipt.get("signature", {})):
            return {"provider_status": "DENIED", "reason_codes": ["PROVIDER_DECISION_TOKEN_INVALID"], "adapter_id": self.adapter_id}
        core = decision_receipt.get("decision_core", {})
        codes: list[str] = []
        if core.get("outcome") != "ALLOW":
            codes.append("PROVIDER_DECISION_NOT_ALLOW")
        if core.get("provider_adapter_id") != self.adapter_id:
            codes.append("PROVIDER_ADAPTER_BINDING_MISMATCH")
        if core.get("action_digest") != digest(action):
            codes.append("PROVIDER_ACTION_DIGEST_MISMATCH")
        if parse_utc(core.get("expires_at")) < parse_utc(now):
            codes.append("PROVIDER_DECISION_TOKEN_EXPIRED")
        decision_id = core.get("decision_id")
        if decision_id in self.used_decision_ids:
            codes.append("PROVIDER_DECISION_TOKEN_REPLAY")
        if not self.supports_merchant(action["merchant"]["merchant_id"]):
            codes.append("PROVIDER_MERCHANT_UNSUPPORTED")
        if codes:
            return {"provider_status": "DENIED", "reason_codes": codes, "adapter_id": self.adapter_id}
        self.used_decision_ids.add(decision_id)
        provider_charge_id = "chg_" + hashlib.sha256((self.adapter_id + core["action_digest"] + decision_id).encode("utf-8")).hexdigest()[:18]
        return {
            "provider_status": "AUTHORIZED",
            "adapter_id": self.adapter_id,
            "provider_class": self.provider_class,
            "merchant_id": action["merchant"]["merchant_id"],
            "amount": action["totals"],
            "provider_charge_id": provider_charge_id,
            "decision_id": decision_id,
        }
