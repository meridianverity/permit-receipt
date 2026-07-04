#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
from copy import deepcopy
from orprg_eval.gateway import MockEgressGateway
from orprg_eval.vector_factory import base_policy, base_context, base_request, make_receipt, make_capability, CAP_KEY, CAP_ID
from orprg_eval.verifier import verify_permit_receipt
from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.replay import ReplayCache

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

def row(name, req, cap, policy, context, expected_decision, expected_code=None):
    gw = MockEgressGateway(req["interface_id"])
    out = gw.commit(req, cap, policy, context)
    ok = out["decision"] == expected_decision and out["denial_reason_code"] == expected_code
    return {"scenario": name, "expected": {"decision": expected_decision, "denial_reason_code": expected_code}, "observed": out, "pass": ok}

def main():
    pol = base_policy(); pol["require_capability_token"] = False
    req = base_request()
    rec = make_receipt(req, policy=pol, nonce="gw-receipt")
    vr = verify_permit_receipt(req, rec, pol, __import__('orprg_eval.vector_factory', fromlist=['make_revocation_state']).make_revocation_state(), base_context())
    assert vr.decision == ALLOW
    cap = make_capability(req, rec, pol, nonce="gw-cap")
    rows = []
    rows.append(row("valid downstream capability", req, cap, pol, base_context(), ALLOW))
    rows.append(row("direct bypass without capability", req, None, pol, base_context(), DENY, DRC["GATEWAY_BYPASS_DENIED"]))
    bad = deepcopy(cap); bad["token_core"]["audience"] = "other-gateway"  # signature now invalid because token core changed.
    rows.append(row("tampered capability", req, bad, pol, base_context(), DENY, DRC["CAPABILITY_SIGNATURE_INVALID"]))
    cap2 = make_capability(req, rec, pol, nonce="gw-replay")
    cache = ReplayCache()
    first = row("capability first use", req, cap2, pol, {**base_context(), "capability_replay_cache": cache}, ALLOW)
    second = row("capability replay second use", req, cap2, pol, {**base_context(), "capability_replay_cache": cache}, DENY, DRC["CAPABILITY_REPLAY"])
    rows.extend([first, second])
    reqB = deepcopy(req); reqB["tenant_id"] = "tenant-B"
    rows.append(row("tenant replay blocked", reqB, cap, pol, base_context(), DENY, DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]))
    summary = {"total": len(rows), "passed": sum(1 for r in rows if r["pass"]), "failed": sum(1 for r in rows if not r["pass"]), "rows": rows, "synthetic": True}
    (RESULTS / "gateway_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8")
    md = ["# Mock Egress Gateway Dual-Enforcement Summary", "", "Synthetic downstream capability-token verification scenarios.", "", "| Scenario | Expected | Observed | Reason | Pass |", "|---|---|---|---|---:|"]
    for r in rows:
        md.append(f"| {r['scenario']} | {r['expected']['decision']} | {r['observed']['decision']} | {r['observed']['denial_reason_code'] or ''} | {r['pass']} |")
    (RESULTS / "gateway_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("total","passed","failed","synthetic")}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
