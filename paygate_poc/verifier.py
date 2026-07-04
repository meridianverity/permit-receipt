from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authority import PERMIT_CONTEXT
from .canonical import digest, parse_utc, utc_now_iso, without_signature
from .keys import KeyPair, verify_signature
from .policy import PolicyState
from .providers import DECISION_CONTEXT, SimulatedPaymentProvider
from .tsil import sensor_core_digest, verify_sensor_receipt


class ReplayStore:
    def __init__(self):
        self.used_receipt_ids: set[str] = set()
        self.used_nonces: set[str] = set()
        self.highest_counter_by_audience: dict[str, int] = {}

    def check(self, receipt: dict[str, Any]) -> list[str]:
        core = receipt["receipt_core"]
        anti = core["anti_replay"]
        audience = core["scope"]["tenant_id"] + "|" + core["scope"]["agent_id"]
        counter = int(anti["monotonic_counter"])
        codes: list[str] = []
        if receipt["receipt_id"] in self.used_receipt_ids:
            codes.append("REPLAY_RECEIPT_ID_USED")
        if anti["nonce"] in self.used_nonces:
            codes.append("REPLAY_NONCE_USED")
        if counter <= self.highest_counter_by_audience.get(audience, 0):
            codes.append("REPLAY_MONOTONIC_COUNTER_NOT_ADVANCED")
        return codes

    def mark(self, receipt: dict[str, Any]) -> None:
        core = receipt["receipt_core"]
        anti = core["anti_replay"]
        audience = core["scope"]["tenant_id"] + "|" + core["scope"]["agent_id"]
        counter = int(anti["monotonic_counter"])
        self.used_receipt_ids.add(receipt["receipt_id"])
        self.used_nonces.add(anti["nonce"])
        self.highest_counter_by_audience[audience] = max(counter, self.highest_counter_by_audience.get(audience, 0))


class PayGateVerifier:
    def __init__(
        self,
        *,
        policy_state: PolicyState,
        permit_public_key: Ed25519PublicKey,
        tsil_public_key: Ed25519PublicKey,
        gate_keypair: KeyPair,
        replay_store: ReplayStore | None = None,
        revoked_receipts: set[str] | None = None,
    ):
        self.policy_state = policy_state
        self.permit_public_key = permit_public_key
        self.tsil_public_key = tsil_public_key
        self.gate_keypair = gate_keypair
        self.replay_store = replay_store or ReplayStore()
        self.revoked_receipts = revoked_receipts or set()

    @property
    def gate_public_key(self) -> Ed25519PublicKey:
        return self.gate_keypair.public_key

    def verify_precommit(
        self,
        action: dict[str, Any],
        permit_receipt: dict[str, Any] | None,
        provider: SimulatedPaymentProvider,
        *,
        sensor_receipt: dict[str, Any] | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        now = now or utc_now_iso()
        codes: list[str] = []
        evidence: dict[str, Any] = {"action_digest": None, "permit_receipt_digest": None}
        try:
            action_digest = digest(action)
            evidence["action_digest"] = action_digest
        except Exception as exc:
            return self._deny(["ACTION_CANONICALIZATION_FAILED"], evidence={"error": str(exc)})

        if not permit_receipt:
            return self._deny(["PERMIT_RECEIPT_REQUIRED"], evidence=evidence)
        evidence["permit_receipt_digest"] = digest(without_signature(permit_receipt))

        if permit_receipt.get("type") != "PermitReceipt":
            codes.append("PERMIT_TYPE_INVALID")
        if not verify_signature(self.permit_public_key, PERMIT_CONTEXT, without_signature(permit_receipt), permit_receipt.get("signature", {})):
            codes.append("PERMIT_SIGNATURE_INVALID")
        if permit_receipt.get("receipt_id") in self.revoked_receipts:
            codes.append("PERMIT_REVOKED")

        core = permit_receipt.get("receipt_core", {})
        if core.get("policy_digest") != self.policy_state.policy_digest:
            codes.append("POLICY_DIGEST_MISMATCH")
        if core.get("epoch_id") != self.policy_state.epoch_id:
            codes.append("EPOCH_MISMATCH")
        try:
            if parse_utc(core.get("not_before")) > parse_utc(now):
                codes.append("PERMIT_NOT_YET_VALID")
            if parse_utc(core.get("not_after")) < parse_utc(now):
                codes.append("PERMIT_EXPIRED")
        except Exception:
            codes.append("PERMIT_TIME_INVALID")

        if core.get("action_digest") != action_digest:
            codes.append("ACTION_DIGEST_MISMATCH")

        scope = core.get("scope", {})
        comparisons = [
            ("TENANT_MISMATCH", scope.get("tenant_id"), action.get("tenant_id")),
            ("AGENT_MISMATCH", scope.get("agent_id"), action.get("agent_id")),
            ("PURPOSE_MISMATCH", scope.get("purpose_id"), action.get("purpose_id")),
            ("MERCHANT_MISMATCH", scope.get("merchant_id"), action.get("merchant", {}).get("merchant_id")),
            ("CURRENCY_MISMATCH", scope.get("currency"), action.get("totals", {}).get("currency")),
            ("AMOUNT_MISMATCH", scope.get("total_minor"), action.get("totals", {}).get("total_minor")),
            ("CAPTURE_MODE_MISMATCH", scope.get("capture_mode"), action.get("payment", {}).get("capture_mode")),
        ]
        for code, expected, actual in comparisons:
            if expected != actual:
                codes.append(code)
        if scope.get("cart_digest") != digest(action.get("cart", [])):
            codes.append("CART_DIGEST_MISMATCH")
        if action.get("totals", {}).get("total_minor", 0) > scope.get("max_total_minor", -1):
            codes.append("AMOUNT_EXCEEDS_MAX_SCOPE")
        if action.get("totals", {}).get("currency") not in self.policy_state.policy["limits"]["allowed_currencies"]:
            codes.append("CURRENCY_NOT_ALLOWED")
        if provider.provider_class not in scope.get("allowed_provider_classes", []):
            codes.append("PROVIDER_CLASS_NOT_ALLOWED_BY_RECEIPT")
        if not self.policy_state.allows_provider_class(provider.provider_class):
            codes.append("PROVIDER_CLASS_NOT_ALLOWED_BY_POLICY")
        if not provider.supports_merchant(action.get("merchant", {}).get("merchant_id")):
            codes.append("PROVIDER_MERCHANT_UNSUPPORTED")

        anti = core.get("anti_replay", {})
        if anti.get("idempotency_key") != action.get("payment", {}).get("idempotency_key"):
            codes.append("IDEMPOTENCY_KEY_MISMATCH")
        if not isinstance(anti.get("monotonic_counter"), int):
            codes.append("MONOTONIC_COUNTER_INVALID")
        if not anti.get("nonce"):
            codes.append("NONCE_MISSING")

        if self.policy_state.policy["requirements"].get("require_tsil_evidence"):
            expected_s2 = core.get("evidence", {}).get("sensor_receipt_core_digest")
            actual_s2 = action.get("context", {}).get("sensor_receipt_core_digest")
            if not expected_s2 or not actual_s2:
                codes.append("TSIL_EVIDENCE_REQUIRED")
            elif expected_s2 != actual_s2:
                codes.append("TSIL_EVIDENCE_DIGEST_MISMATCH")
            if not sensor_receipt:
                codes.append("TSIL_SENSOR_RECEIPT_OBJECT_REQUIRED")
            else:
                ok, s2_codes = verify_sensor_receipt(sensor_receipt, self.tsil_public_key)
                if not ok:
                    codes.extend(s2_codes)
                elif sensor_core_digest(sensor_receipt) != expected_s2:
                    codes.append("TSIL_SENSOR_RECEIPT_CORE_DIGEST_MISMATCH")

        if not codes:
            codes.extend(self.replay_store.check(permit_receipt))

        if codes:
            return self._deny(codes, evidence=evidence)

        self.replay_store.mark(permit_receipt)
        decision_receipt = self._mint_decision_receipt(action_digest, permit_receipt, provider, now)
        return {
            "outcome": "ALLOW",
            "reason_codes": [],
            "decision_receipt": decision_receipt,
            "evidence": evidence,
        }

    def _mint_decision_receipt(self, action_digest: str, permit_receipt: dict[str, Any], provider: SimulatedPaymentProvider, now: str) -> dict[str, Any]:
        ttl = int(self.policy_state.policy["limits"]["decision_token_ttl_seconds"])
        expires = (parse_utc(now) + timedelta(seconds=ttl)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        permit_digest = digest(without_signature(permit_receipt))
        decision_id = "urn:paygate:decision:" + hashlib.sha256((action_digest + permit_digest + provider.adapter_id + now).encode("utf-8")).hexdigest()[:24]
        unsigned = {
            "type": "PaymentDecisionReceipt",
            "version": "paygate-poc/1.0",
            "issuer_id": "paygate:demo:verifier",
            "issued_at": now,
            "decision_core": {
                "decision_id": decision_id,
                "outcome": "ALLOW",
                "action_digest": action_digest,
                "permit_receipt_digest": permit_digest,
                "policy_digest": self.policy_state.policy_digest,
                "epoch_id": self.policy_state.epoch_id,
                "provider_adapter_id": provider.adapter_id,
                "provider_class": provider.provider_class,
                "expires_at": expires,
            },
        }
        unsigned["signature"] = self.gate_keypair.sign(DECISION_CONTEXT, unsigned)
        return unsigned

    def _deny(self, codes: list[str], *, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"outcome": "DENY", "reason_codes": sorted(set(codes)), "decision_receipt": None, "evidence": evidence or {}}
