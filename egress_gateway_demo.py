#!/usr/bin/env python3
"""Executable localhost egress-gateway adapter for ORPRG-Eval v3.2."""
from __future__ import annotations
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.verifier import verify_permit_receipt
from orprg_eval.vector_factory import base_context, base_policy, base_request, base_revocation, make_receipt, make_revocation_state, make_capability
ROOT = Path(__file__).resolve().parent; RESULTS = ROOT / 'results'; RESULTS.mkdir(exist_ok=True)
class Handler(BaseHTTPRequestHandler):
    server_version = 'ORPRG-EgressGateway/0.2'
    def log_message(self, fmt, *args): return
    def do_POST(self):
        if self.path != '/v1/egress': self.send_response(404); self.end_headers(); return
        try:
            env = json.loads(self.rfile.read(int(self.headers.get('content-length','0'))).decode('utf-8'))
            result = verify_permit_receipt(env['request'], env.get('permit_receipt'), env['policy_state'], env['revocation_state'], env.get('context', {}))
            payload = result.to_dict(); payload['gateway_commit']={'committed': result.decision==ALLOW, 'boundary':'localhost-egress'}
            status = 202 if result.decision==ALLOW else 403
        except Exception as exc:
            status=400; payload={'decision':DENY,'denial_reason_code':'ADAPTER_ERROR','error':type(exc).__name__}
        data=json.dumps(payload, sort_keys=True).encode('utf-8')
        self.send_response(status); self.send_header('content-type','application/json'); self.send_header('content-length',str(len(data))); self.end_headers(); self.wfile.write(data)
def post(url,obj):
    req=Request(url,data=json.dumps(obj).encode('utf-8'),headers={'content-type':'application/json'},method='POST')
    try:
        with urlopen(req,timeout=5) as resp: return resp.status, json.loads(resp.read().decode('utf-8'))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))
def env(request=None, receipt='DEFAULT', policy=None, revocation=None, context=None):
    req=request or base_request(); pol=policy or base_policy(); rec=make_receipt(req, policy=pol, nonce='egress-default') if receipt=='DEFAULT' else receipt; rev=base_revocation(rec) if revocation is None else revocation
    return {'request':req,'permit_receipt':rec,'policy_state':pol,'revocation_state':rev,'context':context or base_context()}
def row(case, exp_status, exp_decision, exp_reason, status, payload):
    return {'case':case,'expected_status':exp_status,'observed_status':status,'expected_decision':exp_decision,'observed_decision':payload.get('decision'),'expected_reason':exp_reason,'observed_reason':payload.get('denial_reason_code'),'pass':status==exp_status and payload.get('decision')==exp_decision and payload.get('denial_reason_code')==exp_reason}
def main():
    httpd=ThreadingHTTPServer(('127.0.0.1',0),Handler); port=httpd.server_address[1]; t=threading.Thread(target=httpd.serve_forever,daemon=True); t.start(); url=f'http://127.0.0.1:{port}/v1/egress'; rows=[]
    status,payload=post(url,env()); rows.append(row('valid_egress_allow',202,ALLOW,None,status,payload))
    status,payload=post(url,env(receipt=None)); rows.append(row('missing_receipt_denied',403,DENY,DRC['MISSING_RECEIPT'],status,payload))
    req_authorized=base_request(); req_attempt=base_request(); req_attempt['target_id']='attacker-exfil-api'; rec=make_receipt(req_authorized,nonce='egress-substitution')
    status,payload=post(url,env(request=req_attempt,receipt=rec,revocation=base_revocation(rec))); rows.append(row('action_substitution_denied',403,DENY,DRC['ACTION_DIGEST_MISMATCH'],status,payload))
    rec=make_receipt(base_request(),nonce='egress-stale'); status,payload=post(url,env(receipt=rec,revocation=make_revocation_state(issued_at='2026-06-01T00:00:00Z'))); rows.append(row('stale_revocation_denied',403,DENY,DRC['REVOCATION_UNKNOWN_OR_STALE'],status,payload))
    pol=base_policy(); pol['require_capability_token']=True; req=base_request(); rec=make_receipt(req,policy=pol,nonce='egress-cap-ok'); cap=make_capability(req,rec,pol,nonce='egress-cap-ok'); ctx=base_context(); ctx['capability_token']=cap
    status,payload=post(url,env(request=req,receipt=rec,policy=pol,revocation=base_revocation(rec),context=ctx)); rows.append(row('capability_valid_allow',202,ALLOW,None,status,payload))
    status,payload=post(url,env(request=req,receipt=rec,policy=pol,revocation=base_revocation(rec),context=base_context())); rows.append(row('capability_absent_denied',403,DENY,DRC['CAPABILITY_TOKEN_INVALID_OR_MISSING'],status,payload))
    badcap=make_capability(req,rec,pol,nonce='egress-cap-bad-aud',core_overrides={'audience':'other-gateway'}); ctx=base_context(); ctx['capability_token']=badcap
    status,payload=post(url,env(request=req,receipt=rec,policy=pol,revocation=base_revocation(rec),context=ctx)); rows.append(row('capability_audience_mismatch_denied',403,DENY,DRC['CAPABILITY_AUDIENCE_MISMATCH'],status,payload))
    rec=make_receipt(base_request(),core_overrides={'epoch_id':46},nonce='egress-rollback'); status,payload=post(url,env(receipt=rec,revocation=base_revocation(rec))); rows.append(row('epoch_rollback_denied',403,DENY,DRC['EPOCH_ROLLBACK_ATTEMPT'],status,payload))
    httpd.shutdown(); t.join(timeout=2); httpd.server_close()
    summary={'package':'ORPRG-Eval v3.2 egress gateway adapter','synthetic':True,'cases':len(rows),'passed':sum(1 for r in rows if r['pass']),'failed':sum(1 for r in rows if not r['pass']),'rows':rows}
    (RESULTS/'egress_gateway_summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True),encoding='utf-8')
    md=['# Egress Gateway Adapter Results','','Synthetic localhost HTTP egress boundary. No production claims.','',f"- Cases: **{summary['cases']}**",f"- Passed: **{summary['passed']}**",f"- Failed: **{summary['failed']}**",'','| Case | Status | Decision | Reason | Pass |','|---|---:|---|---|---:|']
    for r in rows: md.append(f"| {r['case']} | {r['observed_status']} | {r['observed_decision']} | {r['observed_reason'] or ''} | {r['pass']} |")
    (RESULTS/'egress_gateway_summary.md').write_text('\n'.join(md)+'\n',encoding='utf-8'); print(json.dumps(summary,indent=2,sort_keys=True))
if __name__=='__main__':
    main()
