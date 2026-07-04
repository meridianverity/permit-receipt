from __future__ import annotations

from typing import Any

from .ledger import AppendOnlyLedger
from .providers import SimulatedPaymentProvider
from .verifier import PayGateVerifier


class PayGate:
    def __init__(self, verifier: PayGateVerifier, ledger: AppendOnlyLedger):
        self.verifier = verifier
        self.ledger = ledger

    def authorize_and_commit(
        self,
        action: dict[str, Any],
        permit_receipt: dict[str, Any] | None,
        provider: SimulatedPaymentProvider,
        *,
        sensor_receipt: dict[str, Any] | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        verification = self.verifier.verify_precommit(action, permit_receipt, provider, sensor_receipt=sensor_receipt, now=now)
        decision_log = self.ledger.append("PAYGATE_DECISION", {
            "outcome": verification["outcome"],
            "reason_codes": verification["reason_codes"],
            "action_digest": verification.get("evidence", {}).get("action_digest"),
            "permit_receipt_digest": verification.get("evidence", {}).get("permit_receipt_digest"),
            "provider_adapter_id": provider.adapter_id,
        })
        if verification["outcome"] != "ALLOW":
            return {**verification, "ledger_ref": {"seq": decision_log["seq"], "chain_hash": decision_log["chain_hash"]}}
        provider_result = provider.commit(action, verification["decision_receipt"], self.verifier.gate_public_key, now=now)
        provider_log = self.ledger.append("PROVIDER_COMMIT", provider_result)
        if provider_result.get("provider_status") != "AUTHORIZED":
            return {
                "outcome": "DENY",
                "reason_codes": provider_result.get("reason_codes", ["PROVIDER_REJECTED"]),
                "decision_receipt": verification["decision_receipt"],
                "provider_result": provider_result,
                "ledger_ref": {"seq": provider_log["seq"], "chain_hash": provider_log["chain_hash"]},
            }
        return {
            "outcome": "ALLOW",
            "reason_codes": [],
            "decision_receipt": verification["decision_receipt"],
            "provider_result": provider_result,
            "ledger_ref": {"seq": provider_log["seq"], "chain_hash": provider_log["chain_hash"]},
        }
