from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import digest


DEFAULT_POLICY: dict[str, Any] = {
    "type": "PayGatePolicy",
    "version": "1.0",
    "policy_id": "paygate-core-provider-neutral-demo",
    "epoch_id": "epoch:paygate:2026-06-05:001",
    "decision_mode": "STRICT_DENY",
    "canonicalization_profile": "urn:paygate-ref:canon:jcs-no-float-v1",
    "requirements": {
        "require_exact_action_digest": True,
        "require_cart_digest": True,
        "require_tsil_evidence": True,
        "require_decision_token_at_provider": True,
        "deny_on_unknown_or_ambiguous": True,
        "money_representation": "integer_minor_units_only",
        "anti_replay": "nonce+monotonic_counter+idempotency_key",
    },
    "scope_rules": {
        "merchant_exact_match": True,
        "amount_exact_match": True,
        "currency_exact_match": True,
        "tenant_exact_match": True,
        "agent_exact_match": True,
        "purpose_exact_match": True,
        "provider_neutral_semantics": True,
        "provider_adapter_must_be_allowed": True,
    },
    "limits": {
        "max_total_minor": 250000,
        "allowed_currencies": ["USD", "KRW"],
        "allowed_provider_classes": ["card_processor", "wallet_processor", "bank_transfer_sim"],
        "permit_ttl_seconds_default": 300,
        "decision_token_ttl_seconds": 60,
    },
    "denial": {
        "default": "DENY",
        "emit_structured_reason_codes": True,
        "write_append_only_audit_record": True,
    },
}


@dataclass(frozen=True)
class PolicyState:
    policy: dict[str, Any]

    @property
    def epoch_id(self) -> str:
        return self.policy["epoch_id"]

    @property
    def policy_digest(self) -> str:
        return digest(self.policy)

    def allows_provider_class(self, provider_class: str) -> bool:
        return provider_class in self.policy["limits"]["allowed_provider_classes"]
