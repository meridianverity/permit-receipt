#!/usr/bin/env python3
"""Static production-adjacent integration contract checks for ORPRG-Eval v3.2.

This script validates that review-only Envoy/OPA/Cedar-shaped integration
contract examples are present and fail-closed in their stated posture. It does
not execute production Envoy, OPA, or Cedar and makes no claims about those
systems' production behavior.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
ROOT=Path(__file__).resolve().parent
OUT=ROOT/'results'; OUT.mkdir(exist_ok=True)
FILES={
    'envoy_ext_authz':'integrations/envoy_ext_authz_bootstrap_fragment.yaml',
    'opa_style_baseline':'integrations/opa_style_policy_baseline.rego',
    'cedar_like_policy':'integrations/cedar_like_policy.cedar',
}
REQUIRED={
    'envoy_ext_authz':['envoy.filters.http.ext_authz','failure_mode_allow: false','orprg_ext_authz'],
    'opa_style_baseline':['default allow := false','input.session_token_valid','not input.revocation_confirmed'],
    'cedar_like_policy':['context.has_receipt == true','context.action_digest_match == true','context.revocation_fresh == true'],
}
rows=[]
for name, rel in FILES.items():
    p=ROOT/rel
    text=p.read_text(encoding='utf-8') if p.exists() else ''
    missing=[needle for needle in REQUIRED[name] if needle not in text]
    digest=hashlib.sha256(text.encode('utf-8')).hexdigest() if p.exists() else None
    rows.append({'name':name,'path':rel,'exists':p.exists(),'sha256':digest,'required_terms_present':not missing,'missing_terms':missing,'pass':p.exists() and not missing})
summary={'package':'ORPRG-Eval v3.2 integration contract check','synthetic':True,'cases':len(rows),'passed':sum(1 for r in rows if r['pass']),'failed':sum(1 for r in rows if not r['pass']),'rows':rows,'caveat':'Static contract check only; not a production Envoy/OPA/Cedar execution claim.'}
(OUT/'integration_contract_summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True),encoding='utf-8')
md=['# Integration Contract Check','','Synthetic review-only validation of production-adjacent contract examples.','','| Contract | Pass | SHA-256 |','|---|---:|---|']
for r in rows:
    md.append(f"| {r['name']} | {r['pass']} | {r['sha256'] or ''} |")
(OUT/'integration_contract_summary.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
print(json.dumps(summary,indent=2,sort_keys=True))
raise SystemExit(0 if summary['failed']==0 else 1)
