#!/usr/bin/env python3
"""Envoy ext_authz-style localhost adapter for ORPRG-Eval v3.2.

This script does not require Envoy. It uses an ext_authz-shaped JSON envelope to
show how the verifier can be wrapped by a production-adjacent authorization
service while remaining synthetic and self-contained.
"""
from __future__ import annotations
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from orprg_eval.models import DRC
from orprg_eval.verifier import verify_permit_receipt
from orprg_eval.vector_factory import base_context, base_policy, base_request, base_revocation, make_receipt, make_revocation_state
ROOT=Path(__file__).resolve().parent; RESULTS=ROOT/'results'; RESULTS.mkdir(exist_ok=True)
class Handler(BaseHTTPRequestHandler):
    server_version='ORPRG-ExtAuthzAdapter/0.2'
    def log_message(self, fmt, *args): return
    def do_POST(self):
        if self.path != '/v3/ext_authz/check': self.send_response(404); self.end_headers(); return
        try:
            env=json.loads(self.rfile.read(int(self.headers.get('content-length','0'))).decode('utf-8')); attrs=env.get('attributes',{})
            result=verify_permit_receipt(attrs['request'], attrs.get('permit_receipt'), attrs['policy_state'], attrs['revocation_state'], attrs.get('context',{}))
            ok=result.decision=='ALLOW'; payload={'ok':ok,'status':{'code':0 if ok else 7},'dynamic_metadata':{'orprg_decision':result.decision,'denial_reason_code':result.denial_reason_code,'evidence_digests':result.evidence_digests}}
            status=200
        except Exception as exc:
            status=400; payload={'ok':False,'status':{'code':13},'dynamic_metadata':{'error':type(exc).__name__}}
        data=json.dumps(payload,sort_keys=True).encode('utf-8'); self.send_response(status); self.send_header('content-type','application/json'); self.send_header('content-length',str(len(data))); self.end_headers(); self.wfile.write(data)
def post(url,obj):
    req=Request(url,data=json.dumps(obj).encode('utf-8'),headers={'content-type':'application/json'},method='POST')
    try:
        with urlopen(req,timeout=5) as resp: return resp.status,json.loads(resp.read().decode('utf-8'))
    except HTTPError as e:
        return e.code,json.loads(e.read().decode('utf-8'))
def envelope(request=None, receipt='DEFAULT', policy=None, revocation=None, context=None):
    req=request or base_request(); pol=policy or base_policy(); rec=make_receipt(req,policy=pol,nonce='extauthz-default') if receipt=='DEFAULT' else receipt; rev=base_revocation(rec) if revocation is None else revocation
    return {'attributes':{'request':req,'permit_receipt':rec,'policy_state':pol,'revocation_state':rev,'context':context or base_context()}}
def token_only_baseline(env): return bool(env.get('headers',{}).get('authorization'))
def row(case, expected_ok, expected_reason, payload):
    md=payload.get('dynamic_metadata',{}); return {'case':case,'expected_ok':expected_ok,'observed_ok':payload.get('ok'),'expected_reason':expected_reason,'observed_reason':md.get('denial_reason_code'),'pass':payload.get('ok')==expected_ok and md.get('denial_reason_code')==expected_reason}
def main():
    httpd=ThreadingHTTPServer(('127.0.0.1',0),Handler); port=httpd.server_address[1]; t=threading.Thread(target=httpd.serve_forever,daemon=True); t.start(); url=f'http://127.0.0.1:{port}/v3/ext_authz/check'; rows=[]
    status,payload=post(url,envelope()); rows.append(row('ext_authz_orprg_valid_allow',True,None,payload))
    status,payload=post(url,envelope(receipt=None)); rows.append(row('ext_authz_missing_receipt_deny',False,DRC['MISSING_RECEIPT'],payload))
    rec=make_receipt(nonce='extauthz-invalid-sig'); rec['authenticity']['signature']=rec['authenticity']['signature'][:-8]+'AAAAAAAA'; status,payload=post(url,envelope(receipt=rec,revocation=base_revocation(rec))); rows.append(row('ext_authz_invalid_signature_deny',False,DRC['SIGNATURE_INVALID'],payload))
    req=base_request(); req['target_id']='attacker-exfil-api'; rec=make_receipt(base_request(),nonce='extauthz-substitution'); status,payload=post(url,envelope(request=req,receipt=rec,revocation=base_revocation(rec))); rows.append(row('ext_authz_action_substitution_deny',False,DRC['ACTION_DIGEST_MISMATCH'],payload))
    rec=make_receipt(nonce='extauthz-stale'); status,payload=post(url,envelope(receipt=rec,revocation=make_revocation_state(issued_at='2026-06-01T00:00:00Z'))); rows.append(row('ext_authz_stale_revocation_deny',False,DRC['REVOCATION_UNKNOWN_OR_STALE'],payload))
    attack=envelope(receipt=None); attack['headers']={'authorization':'Bearer synthetic-session-token'}; baseline_allows=token_only_baseline(attack)
    rows.append({'case':'token_only_ext_authz_baseline_false_allow_exposure','expected_ok':True,'observed_ok':baseline_allows,'expected_reason':'BASELINE_EXPECTED_FALSE_ALLOW_FOR_ABLATION','observed_reason':'BASELINE_EXPECTED_FALSE_ALLOW_FOR_ABLATION','pass':baseline_allows is True})
    httpd.shutdown(); t.join(timeout=2); httpd.server_close()
    summary={'package':'ORPRG-Eval v3.2 ext_authz-style adapter','synthetic':True,'cases':len(rows),'passed':sum(1 for r in rows if r['pass']),'failed':sum(1 for r in rows if not r['pass']),'rows':rows,'baseline_warning':'token_only_ext_authz is a synthetic ablation, not a production Envoy claim.'}
    (RESULTS/'ext_authz_adapter_summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True),encoding='utf-8')
    md=['# ext_authz-Style Adapter Results','',summary['baseline_warning'],'',f"- Cases: **{summary['cases']}**",f"- Passed: **{summary['passed']}**",f"- Failed: **{summary['failed']}**",'','| Case | OK | Reason | Pass |','|---|---:|---|---:|']
    for r in rows: md.append(f"| {r['case']} | {r['observed_ok']} | {r['observed_reason'] or ''} | {r['pass']} |")
    (RESULTS/'ext_authz_adapter_summary.md').write_text('\n'.join(md)+'\n',encoding='utf-8'); print(json.dumps(summary,indent=2,sort_keys=True))
if __name__=='__main__':
    main()
