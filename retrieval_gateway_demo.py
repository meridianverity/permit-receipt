#!/usr/bin/env python3
"""Run an actual local HTTP retrieval-gateway boundary demo."""
from __future__ import annotations
import copy
import json
import urllib.request
from pathlib import Path
from typing import Any, Dict

from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.retrieval_gateway_adapter import start_server
from orprg_eval.vector_factory import base_context, base_policy, base_revocation, make_capability, make_receipt, make_revocation_state

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def retrieval_request(target: str = "case-record-001") -> Dict[str, Any]:
    return {
        "effect_type": "DATA_ACCESS",
        "interface_id": "retrieval-gateway-1",
        "action_type": "READ",
        "target_id": target,
        "tenant_id": "tenant-A",
        "purpose_id": "support",
        "representation_class_id": "json-v1",
        "max_effect_budget": 1,
        "payload_digest": "query-shape-digest-synth-001",
    }


def retrieval_scope(target: str = "case-record-001") -> Dict[str, Any]:
    return {
        "effect_type": "DATA_ACCESS",
        "interface_id": "retrieval-gateway-1",
        "action_type": "READ",
        "target_id": target,
        "tenant_id": "tenant-A",
        "purpose_id": "support",
        "representation_class_id": "json-v1",
        "max_effect_budget": 1,
    }


def post_json(url: str, payload: Dict[str, Any]) -> tuple[int, Dict[str, Any]]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


MISSING = object()

def scenario_envelope(policy=None, request=None, receipt=MISSING, revocation=None, context=None):
    req = copy.deepcopy(request or retrieval_request())
    pol = copy.deepcopy(policy or base_policy())
    if receipt is MISSING:
        rec = make_receipt(req, policy=pol, scope=retrieval_scope(req["target_id"]), nonce="nonce-retrieval-base")
    else:
        rec = copy.deepcopy(receipt)
    rev = copy.deepcopy(revocation if revocation is not None else base_revocation(rec))
    ctx = copy.deepcopy(context or base_context())
    return {"request": req, "permit_receipt": rec, "policy_state": pol, "revocation_state": rev, "context": ctx}


def main() -> None:
    httpd, _thread = start_server()
    base = f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"
    rows = []

    # 1. Valid retrieval through the HTTP gateway.
    env = scenario_envelope()
    status, payload = post_json(base + "/v1/retrieve", env)
    rows.append({"case": "valid_retrieval_allow", "expected_status": 200, "observed_status": status, "expected_decision": ALLOW, "observed_decision": payload.get("decision"), "expected_reason": None, "observed_reason": payload.get("denial_reason_code"), "pass": status == 200 and payload.get("decision") == ALLOW})

    # 2. Direct bypass route is explicitly refused by the adapter.
    status, payload = post_json(base + "/v1/direct-bypass", {})
    rows.append({"case": "direct_bypass_route_denied", "expected_status": 403, "observed_status": status, "expected_decision": DENY, "observed_decision": payload.get("decision"), "expected_reason": DRC["GATEWAY_BYPASS_DENIED"], "observed_reason": payload.get("denial_reason_code"), "pass": status == 403 and payload.get("denial_reason_code") == DRC["GATEWAY_BYPASS_DENIED"]})

    # 3. Missing receipt reaches actual HTTP boundary but fails permit-before-commit.
    env = scenario_envelope(receipt=None)
    status, payload = post_json(base + "/v1/retrieve", env)
    rows.append({"case": "missing_receipt_denied", "expected_status": 403, "observed_status": status, "expected_decision": DENY, "observed_decision": payload.get("decision"), "expected_reason": DRC["MISSING_RECEIPT"], "observed_reason": payload.get("denial_reason_code"), "pass": status == 403 and payload.get("denial_reason_code") == DRC["MISSING_RECEIPT"]})

    # 4. Receipt authorizes case-record-001; request attempts case-record-002.
    rec_for_001 = make_receipt(retrieval_request("case-record-001"), scope=retrieval_scope("case-record-001"), nonce="nonce-substitution")
    env = scenario_envelope(request=retrieval_request("case-record-002"), receipt=rec_for_001, revocation=base_revocation(rec_for_001))
    status, payload = post_json(base + "/v1/retrieve", env)
    rows.append({"case": "action_substitution_denied", "expected_status": 403, "observed_status": status, "expected_decision": DENY, "observed_decision": payload.get("decision"), "expected_reason": DRC["ACTION_DIGEST_MISMATCH"], "observed_reason": payload.get("denial_reason_code"), "pass": status == 403 and payload.get("denial_reason_code") == DRC["ACTION_DIGEST_MISMATCH"]})

    # 5. Stale revocation state denies even at real HTTP boundary.
    env = scenario_envelope(revocation=make_revocation_state(issued_at="2026-06-01T00:00:00Z"))
    status, payload = post_json(base + "/v1/retrieve", env)
    rows.append({"case": "stale_revocation_denied", "expected_status": 403, "observed_status": status, "expected_decision": DENY, "observed_decision": payload.get("decision"), "expected_reason": DRC["REVOCATION_UNKNOWN_OR_STALE"], "observed_reason": payload.get("denial_reason_code"), "pass": status == 403 and payload.get("denial_reason_code") == DRC["REVOCATION_UNKNOWN_OR_STALE"]})

    # 6. Capability-required retrieval: valid capability token allows.
    pol = base_policy(); pol["require_capability_token"] = True
    req = retrieval_request()
    rec = make_receipt(req, policy=pol, scope=retrieval_scope(), nonce="nonce-cap-retrieval")
    cap = make_capability(req, rec, pol, nonce="cap-retrieval-allow")
    ctx = base_context(); ctx["capability_token"] = cap
    env = scenario_envelope(policy=pol, request=req, receipt=rec, revocation=base_revocation(rec), context=ctx)
    status, payload = post_json(base + "/v1/retrieve", env)
    rows.append({"case": "capability_required_valid_allow", "expected_status": 200, "observed_status": status, "expected_decision": ALLOW, "observed_decision": payload.get("decision"), "expected_reason": None, "observed_reason": payload.get("denial_reason_code"), "pass": status == 200 and payload.get("decision") == ALLOW})

    # 7. Capability-required retrieval: absent capability token denies.
    ctx = base_context()
    env = scenario_envelope(policy=pol, request=req, receipt=rec, revocation=base_revocation(rec), context=ctx)
    status, payload = post_json(base + "/v1/retrieve", env)
    rows.append({"case": "capability_required_absent_denied", "expected_status": 403, "observed_status": status, "expected_decision": DENY, "observed_decision": payload.get("decision"), "expected_reason": DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"], "observed_reason": payload.get("denial_reason_code"), "pass": status == 403 and payload.get("denial_reason_code") == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]})

    httpd.shutdown(); _thread.join(timeout=2); httpd.server_close()
    summary = {"package": "ORPRG-Eval v3.2 retrieval gateway adapter", "synthetic": True, "cases": len(rows), "passed": sum(1 for r in rows if r["pass"]), "failed": sum(1 for r in rows if not r["pass"]), "rows": rows}
    (RESULTS / "retrieval_gateway_adapter_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# Retrieval Gateway Adapter Results", "", "Synthetic local HTTP boundary. No production secrets; see license/access terms.", "", f"- Cases: **{summary['cases']}**", f"- Passed: **{summary['passed']}**", f"- Failed: **{summary['failed']}**", "", "| Case | Status | Decision | Reason | Pass |", "|---|---:|---|---|---:|"]
    for r in rows:
        md.append(f"| {r['case']} | {r['observed_status']} | {r['observed_decision']} | {r['observed_reason'] or ''} | {r['pass']} |")
    (RESULTS / "retrieval_gateway_adapter_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
