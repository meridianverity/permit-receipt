from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import digest, utc_now_iso, without_signature
from .keys import KeyPair, verify_signature

TSIL_CONTEXT = "TSIL/S2/v1"


class SensorReceiptAuthority:
    def __init__(self, issuer_id: str, keypair: KeyPair):
        self.issuer_id = issuer_id
        self.keypair = keypair

    def issue(self, event: dict[str, Any], tenant_id: str, profile_id: str, monotonic_counter: int, now: str | None = None) -> dict[str, Any]:
        now = now or utc_now_iso()
        event_digest = digest(event)
        core = {
            "type": "SensorReceiptCore",
            "version": "1.0",
            "tenant_id": tenant_id,
            "canon": {"format": "JCS-like", "hash_alg": "sha256"},
            "boundary_measurement": "sha256:demo-tsil-boundary-measurement",
            "input_digest": event_digest,
            "trusted_event_time": now,
            "monotonic_counter": monotonic_counter,
            "anti_replay": {
                "nonce": digest({"event_digest": event_digest, "counter": monotonic_counter})[:32],
                "profile_id": profile_id,
                "policy_epoch": "epoch:tsil-demo:001",
            },
            "anchor": {"log_id": "log:demo:tsil", "head_id": "sth:demo:tsil:head:001"},
            "proofs": {
                "inclusion": "proof:demo:included",
                "append_only_evolution": "proof:demo:consistent",
                "freshness_policy": {"mmd_s": 600},
                "proof_profile": "TSIL-Core-Demo/1.0",
            },
        }
        unsigned = {
            "type": "SensorReceipt",
            "version": "1.0",
            "issuer_id": self.issuer_id,
            "issued_at": now,
            "s2_core": core,
        }
        unsigned["signature"] = self.keypair.sign(TSIL_CONTEXT, unsigned)
        return unsigned


def sensor_core_digest(receipt: dict[str, Any]) -> str:
    return digest(receipt["s2_core"])


def verify_sensor_receipt(receipt: dict[str, Any], public_key: Ed25519PublicKey) -> tuple[bool, list[str]]:
    codes: list[str] = []
    if not isinstance(receipt, dict):
        return False, ["TSIL_RECEIPT_NOT_OBJECT"]
    for field in ["type", "version", "issuer_id", "issued_at", "s2_core", "signature"]:
        if field not in receipt:
            codes.append(f"TSIL_MISSING_FIELD:{field}")
    if codes:
        return False, codes
    if receipt.get("type") != "SensorReceipt":
        codes.append("TSIL_TYPE_INVALID")
    if not verify_signature(public_key, TSIL_CONTEXT, without_signature(receipt), receipt["signature"]):
        codes.append("TSIL_SIGNATURE_INVALID")
    core = receipt.get("s2_core", {})
    if core.get("proofs", {}).get("inclusion") is None:
        codes.append("TSIL_INCLUSION_PROOF_MISSING")
    if core.get("proofs", {}).get("append_only_evolution") is None:
        codes.append("TSIL_CONSISTENCY_PROOF_MISSING")
    return not codes, codes
