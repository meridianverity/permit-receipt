#!/usr/bin/env python3
"""Envoy ext_authz-shaped localhost adapter for ORPRG-Eval v3.2.

This synthetic demo does not require Envoy. It exercises a strict HTTP/JSON
boundary around the PermitReceipt verifier and is not production software.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from orprg_eval.httpio import HTTPIngressError, read_strict_json_body, send_json
from orprg_eval.models import DRC
from orprg_eval.replay import ReplayCache
from orprg_eval.vector_factory import (
    base_context,
    base_policy,
    base_request,
    base_revocation,
    make_receipt,
    make_revocation_state,
)
from orprg_eval.verifier import verify_permit_receipt

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "ORPRG-ExtAuthzAdapter/0.3"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802 - stdlib API name
        if self.path != "/v3/ext_authz/check":
            send_json(self, 404, {"ok": False, "status": {"code": 5}})
            return
        try:
            envelope = read_strict_json_body(self)
        except HTTPIngressError as exc:
            status = 413 if exc.denial_reason_code == DRC["RESOURCE_LIMIT_EXCEEDED"] else 400
            send_json(
                self,
                status,
                {
                    "ok": False,
                    "status": {"code": 13},
                    "dynamic_metadata": {"denial_reason_code": exc.denial_reason_code},
                },
            )
            return
        if not isinstance(envelope, Mapping) or not isinstance(envelope.get("attributes"), Mapping):
            send_json(
                self,
                400,
                {
                    "ok": False,
                    "status": {"code": 13},
                    "dynamic_metadata": {"denial_reason_code": DRC["SCHEMA_VALIDATION_FAILURE"]},
                },
            )
            return
        attributes = envelope["attributes"]
        try:
            wire_context = attributes.get("context", {})
            if not isinstance(wire_context, Mapping):
                raise TypeError("context must be an object")
            context = dict(wire_context)
            for replay_field in (
                "replay_cache",
                "capability_replay_cache",
                "used_nonces",
                "used_capability_nonces",
            ):
                context.pop(replay_field, None)
            context["replay_cache"] = self.server.replay_cache  # type: ignore[attr-defined]
            context["capability_replay_cache"] = self.server.capability_replay_cache  # type: ignore[attr-defined]
            result = verify_permit_receipt(
                attributes["request"],
                attributes.get("permit_receipt"),
                attributes["policy_state"],
                attributes["revocation_state"],
                context,
            )
        except (KeyError, TypeError):
            send_json(
                self,
                400,
                {
                    "ok": False,
                    "status": {"code": 13},
                    "dynamic_metadata": {"denial_reason_code": DRC["SCHEMA_VALIDATION_FAILURE"]},
                },
            )
            return
        ok = result.decision == "ALLOW"
        send_json(
            self,
            200,
            {
                "ok": ok,
                "status": {"code": 0 if ok else 7},
                "dynamic_metadata": {
                    "orprg_decision": result.decision,
                    "denial_reason_code": result.denial_reason_code,
                    "evidence_digests": result.evidence_digests,
                },
            },
        )


def _require_loopback_http_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("demo HTTP client only permits loopback http:// URLs")


def post(url: str, obj: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
    _require_loopback_http_url(url)
    request = Request(
        url,
        data=json.dumps(obj, allow_nan=False).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:  # nosec B310
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def envelope(
    request: Mapping[str, Any] | None = None,
    receipt: Mapping[str, Any] | None | str = "DEFAULT",
    policy: Mapping[str, Any] | None = None,
    revocation: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    req = dict(request or base_request())
    pol = dict(policy or base_policy())
    rec = make_receipt(req, policy=pol, nonce="extauthz-default") if receipt == "DEFAULT" else receipt
    rev = base_revocation(rec) if revocation is None else dict(revocation)
    return {
        "attributes": {
            "request": req,
            "permit_receipt": rec,
            "policy_state": pol,
            "revocation_state": rev,
            "context": dict(context or base_context()),
        }
    }


def token_only_baseline(envelope_value: Mapping[str, Any]) -> bool:
    headers = envelope_value.get("headers", {})
    return isinstance(headers, Mapping) and bool(headers.get("authorization"))


def row(
    case: str,
    expected_ok: bool,
    expected_reason: str | None,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    metadata = payload.get("dynamic_metadata", {})
    observed_reason = metadata.get("denial_reason_code") if isinstance(metadata, Mapping) else None
    return {
        "case": case,
        "expected_ok": expected_ok,
        "observed_ok": payload.get("ok"),
        "expected_reason": expected_reason,
        "observed_reason": observed_reason,
        "pass": payload.get("ok") == expected_ok and observed_reason == expected_reason,
    }


def main() -> int:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.replay_cache = ReplayCache()  # type: ignore[attr-defined]
    httpd.capability_replay_cache = ReplayCache()  # type: ignore[attr-defined]
    port = int(httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/v3/ext_authz/check"
    rows: list[dict[str, Any]] = []

    _, payload = post(url, envelope())
    rows.append(row("ext_authz_orprg_valid_allow", True, None, payload))

    _, payload = post(url, envelope(receipt=None))
    rows.append(row("ext_authz_missing_receipt_deny", False, DRC["MISSING_RECEIPT"], payload))

    receipt = make_receipt(nonce="extauthz-invalid-sig")
    receipt["authenticity"]["signature"] = receipt["authenticity"]["signature"][:-8] + "AAAAAAAA"
    _, payload = post(url, envelope(receipt=receipt, revocation=base_revocation(receipt)))
    rows.append(row("ext_authz_invalid_signature_deny", False, DRC["SIGNATURE_INVALID"], payload))

    attempted_request = base_request()
    attempted_request["target_id"] = "attacker-exfil-api"
    receipt = make_receipt(base_request(), nonce="extauthz-substitution")
    _, payload = post(
        url,
        envelope(request=attempted_request, receipt=receipt, revocation=base_revocation(receipt)),
    )
    rows.append(row("ext_authz_action_substitution_deny", False, DRC["ACTION_DIGEST_MISMATCH"], payload))

    receipt = make_receipt(nonce="extauthz-stale")
    _, payload = post(
        url,
        envelope(receipt=receipt, revocation=make_revocation_state(issued_at="2026-06-01T00:00:00Z")),
    )
    rows.append(row("ext_authz_stale_revocation_deny", False, DRC["REVOCATION_UNKNOWN_OR_STALE"], payload))

    attack = envelope(receipt=None)
    attack["headers"] = {"authorization": "Bearer synthetic-session-token"}
    baseline_allows = token_only_baseline(attack)
    rows.append(
        {
            "case": "token_only_ext_authz_baseline_false_allow_exposure",
            "expected_ok": True,
            "observed_ok": baseline_allows,
            "expected_reason": "BASELINE_EXPECTED_FALSE_ALLOW_FOR_ABLATION",
            "observed_reason": "BASELINE_EXPECTED_FALSE_ALLOW_FOR_ABLATION",
            "pass": baseline_allows is True,
        }
    )

    httpd.shutdown()
    thread.join(timeout=2)
    httpd.server_close()

    summary = {
        "package": "ORPRG-Eval v3.2 ext_authz-style adapter",
        "synthetic": True,
        "cases": len(rows),
        "passed": sum(1 for item in rows if item["pass"]),
        "failed": sum(1 for item in rows if not item["pass"]),
        "rows": rows,
        "baseline_warning": "token_only_ext_authz is a synthetic ablation, not a production Envoy claim.",
    }
    (RESULTS / "ext_authz_adapter_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown = [
        "# ext_authz-Style Adapter Results",
        "",
        summary["baseline_warning"],
        "",
        f"- Cases: **{summary['cases']}**",
        f"- Passed: **{summary['passed']}**",
        f"- Failed: **{summary['failed']}**",
        "",
        "| Case | OK | Reason | Pass |",
        "|---|---:|---|---:|",
    ]
    for item in rows:
        markdown.append(
            f"| {item['case']} | {item['observed_ok']} | {item['observed_reason'] or ''} | {item['pass']} |"
        )
    (RESULTS / "ext_authz_adapter_summary.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
