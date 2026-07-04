from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.replay import ReplayCache
from orprg_eval.canonicalization import digest_obj
from paygate_ref.reference import issue_payment_permit, payment_scope, policy_state as ref_policy_state, context_state as ref_context_state, verify_payment_attempt
from paygate_poc.scenario import FIXED_NOW, build_environment, run_scenarios as run_provider_neutral_scenarios

from .bridge import make_tetpay, orprg_action_digest, payment_action_to_orprg_effect, tamper_tetpay, validate_tetpay


def _orprg_policy_and_context(req: dict[str, Any], *, replay_cache: ReplayCache | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    policy = ref_policy_state()
    ctx = ref_context_state(replay_cache=replay_cache)
    ctx.update({
        "resolved_tenant_id": req["tenant_id"],
        "purpose_id": req["purpose_id"],
        "jurisdiction": "US",
    })
    return policy, ctx


def _verify_orprg(req: dict[str, Any], *, nonce: str, max_amount_cents: int | None = None, replay_cache: ReplayCache | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    policy, ctx = _orprg_policy_and_context(req, replay_cache=replay_cache)
    receipt = issue_payment_permit(req, policy=policy, scope=payment_scope(req, max_amount_cents=max_amount_cents), nonce=nonce)
    result = verify_payment_attempt(req, receipt, policy=policy, context=ctx)
    return receipt, result


def scenario_allow_joint_gate() -> dict[str, Any]:
    env = build_environment()
    action = deepcopy(env["action"])
    provider = env["providers"]["provider_card_sim"]
    sensor_receipt = env["sensor_receipt"]
    or_req = payment_action_to_orprg_effect(action)
    or_receipt, or_result = _verify_orprg(or_req, nonce="hybrid-orprg-allow-001", replay_cache=ReplayCache())
    if or_result["decision"] != ALLOW:
        return {"scenario": "H01_ALLOW_joint_orprg_paygate_provider", "final_outcome": DENY, "orprg_result": or_result, "reason_codes": [or_result.get("denial_reason_code")], "stage": "ORPRG"}
    domain_permit = env["permit_authority"].issue(action, env["policy_state"], monotonic_counter=101, now=FIXED_NOW)
    paygate_result = env["gate"].authorize_and_commit(action, domain_permit, provider, sensor_receipt=sensor_receipt, now=FIXED_NOW)
    tetpay = make_tetpay(payment_action=action, sensor_receipt=sensor_receipt, orprg_request=or_req, orprg_result=or_result, paygate_result=paygate_result)
    audit = validate_tetpay(tetpay, payment_action=action, sensor_receipt=sensor_receipt, orprg_request=or_req, orprg_result=or_result, paygate_result=paygate_result)
    return {
        "scenario": "H01_ALLOW_joint_orprg_paygate_provider",
        "final_outcome": "ALLOW" if paygate_result.get("outcome") == "ALLOW" and audit["status"] == "PASS" else "DENY",
        "stage": "COMMIT",
        "orprg_action_digest": orprg_action_digest(or_req),
        "orprg_receipt_digest": digest_obj(or_receipt["receipt_core"]),
        "orprg_result": or_result,
        "paygate_outcome": paygate_result.get("outcome"),
        "provider_status": paygate_result.get("provider_result", {}).get("provider_status"),
        "tetpay_audit": audit,
        "tetpay": tetpay,
    }


def scenario_orprg_scope_denies_before_domain() -> dict[str, Any]:
    env = build_environment()
    action = deepcopy(env["action"])
    or_req = payment_action_to_orprg_effect(action)
    # Permit scope is intentionally one cent lower than the effect. ORPRG must stop before domain/provider commit.
    _, or_result = _verify_orprg(or_req, nonce="hybrid-orprg-scope-deny-001", max_amount_cents=max(0, int(or_req["max_effect_budget"]) - 1), replay_cache=ReplayCache())
    return {
        "scenario": "H02_DENY_orprg_scope_before_paygate",
        "final_outcome": "DENY" if or_result["decision"] == DENY else "ALLOW",
        "stage": "ORPRG",
        "orprg_result": or_result,
        "paygate_invoked": False,
        "expected_reason": DRC["SCOPE_VIOLATION"],
    }


def scenario_domain_tsil_denies_after_orprg_allow() -> dict[str, Any]:
    env = build_environment()
    action = deepcopy(env["action"])
    provider = env["providers"]["provider_card_sim"]
    or_req = payment_action_to_orprg_effect(action)
    _, or_result = _verify_orprg(or_req, nonce="hybrid-orprg-domain-deny-001", replay_cache=ReplayCache())
    if or_result["decision"] != ALLOW:
        return {"scenario": "H03_DENY_paygate_tsil_missing_after_orprg_allow", "final_outcome": "DENY", "stage": "ORPRG", "orprg_result": or_result}
    domain_permit = env["permit_authority"].issue(action, env["policy_state"], monotonic_counter=102, now=FIXED_NOW)
    # Missing actual S2 object: digest alone is insufficient in the provider-neutral domain rail.
    paygate_result = env["gate"].authorize_and_commit(action, domain_permit, provider, sensor_receipt=None, now=FIXED_NOW)
    return {
        "scenario": "H03_DENY_paygate_tsil_missing_after_orprg_allow",
        "final_outcome": "DENY" if paygate_result.get("outcome") != "ALLOW" else "ALLOW",
        "stage": "PAYGATE_DOMAIN",
        "orprg_result": or_result,
        "paygate_outcome": paygate_result.get("outcome"),
        "paygate_reason_codes": paygate_result.get("reason_codes", []),
    }


def scenario_provider_bypass_denies() -> dict[str, Any]:
    env = build_environment()
    action = deepcopy(env["action"])
    direct = env["providers"]["provider_card_sim"].commit(action, None, env["gate"].verifier.gate_public_key, now=FIXED_NOW)
    return {
        "scenario": "H04_DENY_direct_provider_bypass_without_gate_token",
        "final_outcome": "DENY" if direct.get("provider_status") == "DENIED" else "ALLOW",
        "stage": "PROVIDER_ADAPTER",
        "provider_result": direct,
    }


def scenario_tetpay_audit_tamper_detected() -> dict[str, Any]:
    allow = scenario_allow_joint_gate()
    tetpay = allow["tetpay"]
    env = build_environment()
    action = deepcopy(env["action"])
    sensor_receipt = env["sensor_receipt"]
    or_req = payment_action_to_orprg_effect(action)
    _, or_result = _verify_orprg(or_req, nonce="hybrid-orprg-tetpay-audit-001", replay_cache=ReplayCache())
    domain_permit = env["permit_authority"].issue(action, env["policy_state"], monotonic_counter=103, now=FIXED_NOW)
    paygate_result = env["gate"].authorize_and_commit(action, domain_permit, env["providers"]["provider_card_sim"], sensor_receipt=sensor_receipt, now=FIXED_NOW)
    bad = tamper_tetpay(tetpay, field="cart_digest")
    audit = validate_tetpay(bad, payment_action=action, sensor_receipt=sensor_receipt, orprg_request=or_req, orprg_result=or_result, paygate_result=paygate_result)
    return {
        "scenario": "H05_DETECT_tetpay_evidence_tamper",
        "final_outcome": "DENY" if audit["status"] == "FAIL" else "ALLOW",
        "stage": "AUDIT_ONLY_EVIDENCE_VALIDATION",
        "tetpay_audit": audit,
    }


def run_hybrid_scenarios() -> dict[str, Any]:
    scenarios = [
        scenario_allow_joint_gate(),
        scenario_orprg_scope_denies_before_domain(),
        scenario_domain_tsil_denies_after_orprg_allow(),
        scenario_provider_bypass_denies(),
        scenario_tetpay_audit_tamper_detected(),
    ]
    provider_neutral = run_provider_neutral_scenarios()
    ok = all(s["final_outcome"] == ("ALLOW" if s["scenario"].startswith("H01") else "DENY") for s in scenarios)
    return {
        "packet": "permit-receipt-ref-eval-v2_2_4",
        "thesis": "ORPRG-style evaluation core + provider-neutral synthetic profile + optional TSIL-shaped evidence + deterministic public evaluation vector corpus",
        "hybrid_scenarios": scenarios,
        "hybrid_ok": ok,
        "provider_neutral_baseline": {
            "scenarios": provider_neutral["scenarios"],
            "ledger_verified": provider_neutral["ledger_verified"],
            "provider_neutral_property": provider_neutral["provider_neutral_property"],
        },
    }


def write_outputs(out_dir: str | Path) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    result = run_hybrid_scenarios()
    (out / "hybrid_demo_results.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    lines = ["# Hybrid Demo Summary", "", f"hybrid_ok: `{result['hybrid_ok']}`", "", "| Scenario | Final | Stage |", "|---|---:|---|"]
    for s in result["hybrid_scenarios"]:
        lines.append(f"| {s['scenario']} | {s['final_outcome']} | {s.get('stage','-')} |")
    (out / "hybrid_demo_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the PAYGATE-Ref ORPRG agentic-commerce hybrid demo.")
    parser.add_argument("--out", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = write_outputs(args.out) if args.out else run_hybrid_scenarios()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("PermitReceipt Public Evaluation Slice for AI-Agent External Effects v2.2.4")
    print(f"hybrid_ok: {result['hybrid_ok']}")
    print("")
    for s in result["hybrid_scenarios"]:
        print(f"{s['scenario']:<58} {s['final_outcome']:<5} stage={s.get('stage','-')}")


if __name__ == "__main__":
    main()
