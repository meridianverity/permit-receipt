from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .authority import PermitAuthority
from .canonical import digest
from .fixtures import make_payment_action, sample_cart
from .keys import deterministic_demo_key
from .ledger import AppendOnlyLedger
from .paygate import PayGate
from .policy import DEFAULT_POLICY, PolicyState
from .providers import SimulatedPaymentProvider
from .tsil import SensorReceiptAuthority, sensor_core_digest
from .verifier import PayGateVerifier

FIXED_NOW = "2026-06-05T00:00:00Z"
LATER_NOW = "2026-06-05T00:10:00Z"


def build_environment(ledger_path: str | Path | None = None) -> dict[str, Any]:
    policy_state = PolicyState(copy.deepcopy(DEFAULT_POLICY))
    permit_kp = deterministic_demo_key("permit-authority")
    tsil_kp = deterministic_demo_key("tsil-authority")
    gate_kp = deterministic_demo_key("paygate-verifier")
    permit_authority = PermitAuthority("paygate:demo:permit-authority", permit_kp)
    tsil_authority = SensorReceiptAuthority("tsil:demo:sensor-authority", tsil_kp)
    verifier = PayGateVerifier(
        policy_state=policy_state,
        permit_public_key=permit_kp.public_key,
        tsil_public_key=tsil_kp.public_key,
        gate_keypair=gate_kp,
    )
    ledger = AppendOnlyLedger(ledger_path)
    gate = PayGate(verifier, ledger)
    providers = {
        "provider_card_sim": SimulatedPaymentProvider("provider-card-sim", "card_processor", {"merchant:demo-books"}),
        "provider_wallet_sim": SimulatedPaymentProvider("provider-wallet-sim", "wallet_processor", {"merchant:demo-books"}),
        "rogue_sim": SimulatedPaymentProvider("rogue-sim", "untrusted_processor", {"merchant:demo-books"}),
    }
    sensor_event = {
        "event_type": "checkout_context",
        "device_id": "device:demo-wallet-phone-001",
        "wallet_presence": "present",
        "risk_signal": "normal",
        "commerce_session_id": "session:demo-checkout-001",
    }
    sensor_receipt = tsil_authority.issue(sensor_event, tenant_id="tenant:acme-demo", profile_id="TSIL-PAYGATE-DEMO", monotonic_counter=1, now=FIXED_NOW)
    action = make_payment_action(sensor_core_digest(sensor_receipt))
    return {
        "policy_state": policy_state,
        "permit_authority": permit_authority,
        "tsil_authority": tsil_authority,
        "gate": gate,
        "providers": providers,
        "sensor_receipt": sensor_receipt,
        "action": action,
        "keys": {
            "permit_authority_public": permit_kp.public_jwkish(),
            "tsil_authority_public": tsil_kp.public_jwkish(),
            "paygate_verifier_public": gate_kp.public_jwkish(),
        },
        "ledger": ledger,
    }


def summarize(name: str, result: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "scenario": name,
        "outcome": result["outcome"],
        "reason_codes": result.get("reason_codes", []),
        "ledger_ref": result.get("ledger_ref"),
    }
    if result.get("provider_result"):
        summary["provider_status"] = result["provider_result"].get("provider_status")
        summary["provider_adapter_id"] = result["provider_result"].get("adapter_id")
        summary["provider_charge_id"] = result["provider_result"].get("provider_charge_id")
    if result.get("decision_receipt"):
        summary["decision_id"] = result["decision_receipt"]["decision_core"]["decision_id"]
    return summary


def run_scenarios(ledger_path: str | Path | None = None) -> dict[str, Any]:
    env = build_environment(ledger_path)
    pa = env["permit_authority"]
    ps = env["policy_state"]
    gate: PayGate = env["gate"]
    providers = env["providers"]
    s2 = env["sensor_receipt"]
    base_action = env["action"]

    scenarios: list[dict[str, Any]] = []

    # 1. Exact cart, exact amount, exact merchant: ALLOW through a card provider.
    p1 = pa.issue(base_action, ps, monotonic_counter=1, now=FIXED_NOW)
    r1 = gate.authorize_and_commit(base_action, p1, providers["provider_card_sim"], sensor_receipt=s2, now=FIXED_NOW)
    scenarios.append(summarize("01_ALLOW_exact_cart_card_provider", r1))

    # 2. Provider-neutral: same semantic action can use a different allowed provider with a fresh permit.
    p2 = pa.issue(base_action, ps, monotonic_counter=2, now=FIXED_NOW)
    r2 = gate.authorize_and_commit(base_action, p2, providers["provider_wallet_sim"], sensor_receipt=s2, now=FIXED_NOW)
    scenarios.append(summarize("02_ALLOW_provider_neutral_wallet_provider", r2))

    # 3. Amount tamper: permit is for exact total, request tries +$1.00.
    p3 = pa.issue(base_action, ps, monotonic_counter=3, now=FIXED_NOW)
    tampered_amount = copy.deepcopy(base_action)
    tampered_amount["totals"]["total_minor"] += 100
    r3 = gate.authorize_and_commit(tampered_amount, p3, providers["provider_card_sim"], sensor_receipt=s2, now=FIXED_NOW)
    scenarios.append(summarize("03_DENY_amount_tamper", r3))

    # 4. Cart tamper with same total: action digest and cart digest must still fail.
    p4 = pa.issue(base_action, ps, monotonic_counter=4, now=FIXED_NOW)
    tampered_cart = copy.deepcopy(base_action)
    tampered_cart["cart"][0]["sku"] = "sku:substituted-item"
    r4 = gate.authorize_and_commit(tampered_cart, p4, providers["provider_card_sim"], sensor_receipt=s2, now=FIXED_NOW)
    scenarios.append(summarize("04_DENY_cart_tamper_same_total", r4))

    # 5. Replay: a successfully consumed permit cannot authorize a second charge.
    p5 = pa.issue(base_action, ps, monotonic_counter=5, now=FIXED_NOW)
    r5a = gate.authorize_and_commit(base_action, p5, providers["provider_card_sim"], sensor_receipt=s2, now=FIXED_NOW)
    r5b = gate.authorize_and_commit(base_action, p5, providers["provider_card_sim"], sensor_receipt=s2, now=FIXED_NOW)
    scenarios.append(summarize("05A_ALLOW_first_use_before_replay", r5a))
    scenarios.append(summarize("05B_DENY_replay_second_use", r5b))

    # 6. Expired receipt: valid for one second, checked later.
    p6 = pa.issue(base_action, ps, monotonic_counter=6, ttl_seconds=1, now=FIXED_NOW)
    r6 = gate.authorize_and_commit(base_action, p6, providers["provider_card_sim"], sensor_receipt=s2, now=LATER_NOW)
    scenarios.append(summarize("06_DENY_expired_receipt", r6))

    # 7. Epoch mismatch: old policy epoch receipt.
    old_policy = PolicyState({**copy.deepcopy(ps.policy), "epoch_id": "epoch:paygate:OLD"})
    p7 = pa.issue(base_action, old_policy, monotonic_counter=7, now=FIXED_NOW)
    r7 = gate.authorize_and_commit(base_action, p7, providers["provider_card_sim"], sensor_receipt=s2, now=FIXED_NOW)
    scenarios.append(summarize("07_DENY_epoch_mismatch", r7))

    # 8. Missing TSIL object: digest may be in action/permit, but verifier requires actual S2 object.
    p8 = pa.issue(base_action, ps, monotonic_counter=8, now=FIXED_NOW)
    r8 = gate.authorize_and_commit(base_action, p8, providers["provider_card_sim"], sensor_receipt=None, now=FIXED_NOW)
    scenarios.append(summarize("08_DENY_missing_tsil_sensor_receipt", r8))

    # 9. Provider class not allowed by receipt/policy.
    p9 = pa.issue(base_action, ps, monotonic_counter=9, now=FIXED_NOW)
    r9 = gate.authorize_and_commit(base_action, p9, providers["rogue_sim"], sensor_receipt=s2, now=FIXED_NOW)
    scenarios.append(summarize("09_DENY_untrusted_provider_class", r9))

    # 10. Direct provider bypass attempt without a PayGate decision token.
    direct = providers["provider_card_sim"].commit(base_action, None, gate.verifier.gate_public_key, now=FIXED_NOW)
    env["ledger"].append("DIRECT_PROVIDER_BYPASS_ATTEMPT", direct)
    scenarios.append({
        "scenario": "10_DENY_direct_provider_bypass_without_decision_token",
        "outcome": "DENY" if direct["provider_status"] == "DENIED" else "ALLOW",
        "reason_codes": direct.get("reason_codes", []),
        "provider_status": direct["provider_status"],
    })

    ok, chain_tip = env["ledger"].verify_chain()
    return {
        "packet": "PAYGATE_PROVIDER_NEUTRAL_POC_v1_0",
        "fixed_now": FIXED_NOW,
        "policy_digest": ps.policy_digest,
        "policy_epoch": ps.epoch_id,
        "base_action_digest": digest(base_action),
        "base_cart_digest": digest(base_action["cart"]),
        "sensor_receipt_core_digest": sensor_core_digest(s2),
        "provider_neutral_property": "provider adapter is not part of the semantic action digest; provider class and merchant support are checked as scope constraints",
        "scenarios": scenarios,
        "ledger_verified": ok,
        "ledger_chain_tip": chain_tip,
        "public_keys": env["keys"],
    }


def write_demo_outputs(out_dir: str | Path) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    result = run_scenarios(out / "demo_ledger.jsonl")
    (out / "demo_results.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result
