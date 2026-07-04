#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
from orprg_eval.vector_factory import base_policy, base_context, base_request, base_scope, make_receipt, make_revocation_state
from orprg_eval.verifier import verify_permit_receipt
from orprg_eval.models import ALLOW, DENY, DRC

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

def scenario(name, request, receipt, policy, revocation, context, expected_decision, expected_code=None):
    r = verify_permit_receipt(request, receipt, policy, revocation, context)
    return {"scenario": name, "expected": {"decision": expected_decision, "denial_reason_code": expected_code}, "observed": r.to_dict(), "pass": r.decision == expected_decision and r.denial_reason_code == expected_code}

def main():
    pol = base_policy()
    req = base_request()
    rec = make_receipt(req, policy=pol, nonce="partition-base")
    rows = []
    rows.append(scenario("fresh revocation", req, rec, pol, make_revocation_state(), base_context(), ALLOW))
    rows.append(scenario("stale revocation", req, rec, pol, {"status":"stale"}, base_context(), DENY, DRC["REVOCATION_UNKNOWN_OR_STALE"]))
    rows.append(scenario("missing revocation", req, rec, pol, {"status":"missing"}, base_context(), DENY, DRC["REVOCATION_UNKNOWN_OR_STALE"]))
    rows.append(scenario("split-brain epoch", req, rec, pol, make_revocation_state(), {**base_context(), "epoch_sources":[47, 46]}, DENY, DRC["EPOCH_ROLLBACK_ATTEMPT"]))
    rows.append(scenario("cross-log conflict", req, rec, pol, {"status":"conflicting"}, base_context(), DENY, DRC["CROSS_LOG_COHERENCE_NOT_SATISFIED"]))
    pol_off = base_policy(); pol_off["offline_constrained_mode_allowed"] = True; pol_off["offline_constrained_effect_types"] = ["SAFETY_HEARTBEAT"]
    req_safe = {**base_request(), "effect_type":"SAFETY_HEARTBEAT", "interface_id":"safety-bus-1", "action_type":"PUBLISH", "target_id":"heartbeat"}
    scope_safe = {**base_scope(), "effect_type":"SAFETY_HEARTBEAT", "interface_id":"safety-bus-1", "action_type":"PUBLISH", "target_id":"heartbeat"}
    rec_safe = make_receipt(req_safe, policy=pol_off, scope=scope_safe, nonce="partition-safe")
    rows.append(scenario("offline constrained safety effect", req_safe, rec_safe, pol_off, {"status":"missing"}, {**base_context(), "partitioned":True}, ALLOW))
    rows.append(scenario("offline non-constrained egress", req, make_receipt(req, policy=pol_off, nonce="partition-deny"), pol_off, {"status":"missing"}, {**base_context(), "partitioned":True}, DENY, DRC["CONSTRAINED_MODE_DENIAL"]))
    summary = {"total": len(rows), "passed": sum(1 for r in rows if r["pass"]), "failed": sum(1 for r in rows if not r["pass"]), "rows": rows, "synthetic": True}
    (RESULTS / "partition_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# Partition/Freshness Simulation", "", "Synthetic reference scenarios.", "", "| Scenario | Expected | Observed | Reason | Pass |", "|---|---|---|---|---:|"]
    for r in rows:
        md.append(f"| {r['scenario']} | {r['expected']['decision']} | {r['observed']['decision']} | {r['observed']['denial_reason_code'] or ''} | {r['pass']} |")
    (RESULTS / "partition_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("total","passed","failed","synthetic")}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
