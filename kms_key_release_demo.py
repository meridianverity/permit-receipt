#!/usr/bin/env python3
"""KMS/HSM-shaped key-release gate demo for ORPRG-Eval v3.2.

This is a production-adjacent, synthetic integration shape. It does not contact a
real cloud KMS or HSM. It models the decision contract a key custodian would
enforce: a key operation is released only if the PermitReceipt verifies for the
exact KEY_RELEASE action, attestation requirements are satisfied when selected by
policy, revocation/epoch checks are fresh, and a single-use key-release token is
not replayed.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional

from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.vector_factory import base_context, base_policy, make_receipt, make_revocation_state
from orprg_eval.verifier import verify_permit_receipt
from orprg_eval.replay import ReplayCache

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def key_request(op: str = "DECRYPT", key_id: str = "kms:key/tenant-A/reporting", nonce: str = "kms-nonce-1") -> Dict[str, Any]:
    return {
        "effect_type": "KEY_RELEASE",
        "interface_id": "kms-gate-1",
        "action_type": "KEY_OP",
        "target_id": key_id,
        "key_id": key_id,
        "key_op": op,
        "tenant_id": "tenant-A",
        "purpose_id": "support",
        "representation_class_id": "key-release-v1",
        "max_effect_budget": 1,
        "payload_digest": "key-release-payload-synth",
        "nonce": nonce,
    }


def key_scope(req: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "effect_type": "KEY_RELEASE",
        "interface_id": req["interface_id"],
        "action_type": req["action_type"],
        "target_id": req["target_id"],
        "tenant_id": req["tenant_id"],
        "purpose_id": req["purpose_id"],
        "representation_class_id": req["representation_class_id"],
        "key_id": req["key_id"],
        "key_ops": ["DECRYPT"],
        "max_effect_budget": 1,
    }


class SyntheticKMSGate:
    """Small key-custodian gate with independent replay cache."""

    def __init__(self) -> None:
        self.replay_cache = ReplayCache()

    def release(self, req: Dict[str, Any], receipt: Optional[Dict[str, Any]], policy: Dict[str, Any], revocation: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        ctx = dict(context)
        ctx["replay_cache"] = self.replay_cache
        ctx.setdefault("attestation_required", True)
        ctx.setdefault("attestation_present", True)
        result = verify_permit_receipt(req, receipt, policy, revocation, ctx)
        if result.decision != ALLOW:
            return {"decision": DENY, "denial_reason_code": result.denial_reason_code, "key_released": False, "verifier": result.to_dict()}
        # The gate does not disclose key material in the synthetic artifact. It
        # returns a digest-like handle to show that release would be authorized.
        return {"decision": ALLOW, "denial_reason_code": None, "key_released": True, "key_handle": "synthetic-wrapped-key-handle", "verifier": result.to_dict()}


def run_case(name: str, req: Dict[str, Any], receipt: Optional[Dict[str, Any]], policy: Dict[str, Any], revocation: Dict[str, Any], context: Dict[str, Any], expected_decision: str, expected_code: Optional[str]) -> Dict[str, Any]:
    gate = context.pop("_gate", SyntheticKMSGate())
    observed = gate.release(req, receipt, policy, revocation, context)
    ok = observed["decision"] == expected_decision and observed["denial_reason_code"] == expected_code
    return {"scenario": name, "expected": {"decision": expected_decision, "denial_reason_code": expected_code}, "observed": observed, "pass": ok}


def main() -> int:
    policy = base_policy()
    policy["require_identity_binding"] = False
    policy["require_purpose"] = True
    policy["require_permit_provenance"] = True
    req = key_request()
    receipt = make_receipt(req, policy=policy, scope=key_scope(req), nonce="kms-receipt-1", permit_provenance_digest="permit-prov-kms-synth")
    rev = make_revocation_state()
    base_ctx = {**base_context(), "purpose_id": "support", "attestation_required": True, "attestation_present": True}

    rows = []
    rows.append(run_case("valid key-release receipt", deepcopy(req), deepcopy(receipt), policy, rev, deepcopy(base_ctx), ALLOW, None))
    rows.append(run_case("missing receipt", deepcopy(req), None, policy, rev, deepcopy(base_ctx), DENY, DRC["MISSING_RECEIPT"]))
    tampered_req = deepcopy(req); tampered_req["key_op"] = "SIGN"
    rows.append(run_case("key operation out of scope", tampered_req, deepcopy(receipt), policy, rev, deepcopy(base_ctx), DENY, DRC["ACTION_DIGEST_MISMATCH"]))
    stale_rev = make_revocation_state(status="stale")
    rows.append(run_case("stale revocation blocks key release", deepcopy(req), deepcopy(receipt), policy, stale_rev, deepcopy(base_ctx), DENY, DRC["REVOCATION_UNKNOWN_OR_STALE"]))
    no_attest = deepcopy(base_ctx); no_attest["attestation_present"] = False
    rows.append(run_case("required attestation missing", deepcopy(req), deepcopy(receipt), policy, rev, no_attest, DENY, DRC["KEY_RELEASE_DENIED"]))
    no_prov_policy = dict(policy); no_prov_policy["require_permit_provenance"] = True
    no_prov_receipt = make_receipt(req, policy=no_prov_policy, scope=key_scope(req), nonce="kms-no-prov", permit_provenance_digest=None)
    rows.append(run_case("permit provenance missing", deepcopy(req), no_prov_receipt, no_prov_policy, rev, deepcopy(base_ctx), DENY, DRC["PERMIT_PROVENANCE_INVALID_OR_MISSING"]))
    # Replay with the same gate instance to model a persistent key custodian replay cache.
    gate = SyntheticKMSGate()
    replay_ctx = {**deepcopy(base_ctx), "_gate": gate}
    first = run_case("single-use key receipt first use", deepcopy(req), deepcopy(receipt), policy, rev, replay_ctx, ALLOW, None)
    replay_ctx2 = {**deepcopy(base_ctx), "_gate": gate}
    second = run_case("single-use key receipt replay denied", deepcopy(req), deepcopy(receipt), policy, rev, replay_ctx2, DENY, DRC["ANTI_REPLAY_FAILURE"])
    rows.extend([first, second])

    summary = {"synthetic": True, "cases": len(rows), "passed": sum(1 for r in rows if r["pass"]), "failed": sum(1 for r in rows if not r["pass"]), "rows": rows}
    (RESULTS / "kms_key_release_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8")
    md = ["# KMS/HSM-Shaped Key-Release Gate Summary", "", "Synthetic production-adjacent key-custodian contract. No real KMS/HSM or production keys are used.", "", "| Scenario | Expected | Observed | Reason | Pass |", "|---|---|---|---|---:|"]
    for r in rows:
        md.append(f"| {r['scenario']} | {r['expected']['decision']} | {r['observed']['decision']} | {r['observed']['denial_reason_code'] or ''} | {r['pass']} |")
    (RESULTS / "kms_key_release_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("cases", "passed", "failed", "synthetic")}, indent=2, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
