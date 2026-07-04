from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from .canonical import digest, parse_utc, utc_now_iso
from .keys import KeyPair
from .policy import PolicyState

PERMIT_CONTEXT = "PAYGATE/PERMIT/v1"


class PermitAuthority:
    def __init__(self, issuer_id: str, keypair: KeyPair):
        self.issuer_id = issuer_id
        self.keypair = keypair

    def issue(
        self,
        action: dict[str, Any],
        policy_state: PolicyState,
        *,
        monotonic_counter: int,
        ttl_seconds: int | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        now = now or utc_now_iso()
        ttl = ttl_seconds or policy_state.policy["limits"]["permit_ttl_seconds_default"]
        not_after = (parse_utc(now) + timedelta(seconds=ttl)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        action_digest = digest(action)
        cart_digest = digest(action["cart"])
        scope = {
            "tenant_id": action["tenant_id"],
            "agent_id": action["agent_id"],
            "purpose_id": action["purpose_id"],
            "merchant_id": action["merchant"]["merchant_id"],
            "cart_digest": cart_digest,
            "currency": action["totals"]["currency"],
            "total_minor": action["totals"]["total_minor"],
            "capture_mode": action["payment"]["capture_mode"],
            "allowed_provider_classes": policy_state.policy["limits"]["allowed_provider_classes"],
            "max_total_minor": policy_state.policy["limits"]["max_total_minor"],
        }
        nonce_material = {"action_digest": action_digest, "counter": monotonic_counter, "issued_at": now}
        receipt_id = "urn:paygate:permit:" + hashlib.sha256((action_digest + str(monotonic_counter) + now).encode("utf-8")).hexdigest()[:24]
        core = {
            "policy_digest": policy_state.policy_digest,
            "epoch_id": policy_state.epoch_id,
            "not_before": now,
            "not_after": not_after,
            "action_digest": action_digest,
            "action_commitment": {"canonicalization_profile": policy_state.policy["canonicalization_profile"], "hash_alg": "sha256"},
            "scope": scope,
            "anti_replay": {
                "nonce": digest(nonce_material),
                "monotonic_counter": monotonic_counter,
                "idempotency_key": action["payment"]["idempotency_key"],
            },
            "evidence": {
                "sensor_receipt_core_digest": action.get("context", {}).get("sensor_receipt_core_digest"),
                "tetpay_context_digest": digest({
                    "action_digest": action_digest,
                    "sensor_receipt_core_digest": action.get("context", {}).get("sensor_receipt_core_digest"),
                    "merchant_id": action["merchant"]["merchant_id"],
                    "total_minor": action["totals"]["total_minor"],
                    "currency": action["totals"]["currency"],
                }),
                "cross_rail_semantics": "evidence-only: TSIL evidence is referenced for PAYGATE audit continuity; TSIL ingress predicates are not modified",
            },
        }
        unsigned = {
            "type": "PermitReceipt",
            "version": "paygate-poc/1.0",
            "receipt_id": receipt_id,
            "issuer_id": self.issuer_id,
            "issued_at": now,
            "receipt_core": core,
        }
        unsigned["signature"] = self.keypair.sign(PERMIT_CONTEXT, unsigned)
        return unsigned
