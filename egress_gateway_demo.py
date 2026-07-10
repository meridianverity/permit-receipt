#!/usr/bin/env python3
"""Executable localhost egress-gateway adapter for ORPRG-Eval v3.2.

Synthetic-only research artifact. The HTTP ingress is strict and bounded, but
this local demo is not a production gateway or a non-bypassability claim.
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
from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.replay import ReplayCache
from orprg_eval.vector_factory import (
    base_context,
    base_policy,
    base_request,
    base_revocation,
    make_capability,
    make_receipt,
    make_revocation_state,
)
from orprg_eval.verifier import verify_permit_receipt

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "ORPRG-EgressGateway/0.3"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802 - stdlib API name
        if self.path != "/v1/egress":
            send_json(self, 404, {"decision": DENY, "denial_reason_code": "GATEWAY_ROUTE_NOT_FOUND"})
            return
        try:
            envelope = read_strict_json_body(self)
        except HTTPIngressError as exc:
            status = 413 if exc.denial_reason_code == DRC["RESOURCE_LIMIT_EXCEEDED"] else 400
            send_json(self, status, {"decision": DENY, "denial_reason_code": exc.denial_reason_code})
            return
        if not isinstance(envelope, Mapping):
            send_json(self, 400, {"decision": DENY, "denial_reason_code": DRC["SCHEMA_VALIDATION_FAILURE"]})
            return
        try:
            wire_context = envelope.get("context", {})
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
                envelope["request"],
                envelope.get("permit_receipt"),
                envelope["policy_state"],
                envelope["revocation_state"],
                context,
            )
        except (KeyError, TypeError):
            send_json(self, 400, {"decision": DENY, "denial_reason_code": DRC["SCHEMA_VALIDATION_FAILURE"]})
            return
        payload = result.to_dict()
        payload["gateway_commit"] = {
            "committed": result.decision == ALLOW,
            "boundary": "localhost-egress",
        }
        send_json(self, 202 if result.decision == ALLOW else 403, payload)


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
    rec = make_receipt(req, policy=pol, nonce="egress-default") if receipt == "DEFAULT" else receipt
    rev = base_revocation(rec) if revocation is None else dict(revocation)
    return {
        "request": req,
        "permit_receipt": rec,
        "policy_state": pol,
        "revocation_state": rev,
        "context": dict(context or base_context()),
    }


def row(
    case: str,
    expected_status: int,
    expected_decision: str,
    expected_reason: str | None,
    status: int,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "case": case,
        "expected_status": expected_status,
        "observed_status": status,
        "expected_decision": expected_decision,
        "observed_decision": payload.get("decision"),
        "expected_reason": expected_reason,
        "observed_reason": payload.get("denial_reason_code"),
        "pass": status == expected_status
        and payload.get("decision") == expected_decision
        and payload.get("denial_reason_code") == expected_reason,
    }


def main() -> int:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.replay_cache = ReplayCache()  # type: ignore[attr-defined]
    httpd.capability_replay_cache = ReplayCache()  # type: ignore[attr-defined]
    port = int(httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/v1/egress"
    rows: list[dict[str, Any]] = []

    status, payload = post(url, envelope())
    rows.append(row("valid_egress_allow", 202, ALLOW, None, status, payload))

    status, payload = post(url, envelope(receipt=None))
    rows.append(row("missing_receipt_denied", 403, DENY, DRC["MISSING_RECEIPT"], status, payload))

    authorized_request = base_request()
    attempted_request = base_request()
    attempted_request["target_id"] = "attacker-exfil-api"
    receipt = make_receipt(authorized_request, nonce="egress-substitution")
    status, payload = post(
        url,
        envelope(request=attempted_request, receipt=receipt, revocation=base_revocation(receipt)),
    )
    rows.append(
        row(
            "action_substitution_denied",
            403,
            DENY,
            DRC["ACTION_DIGEST_MISMATCH"],
            status,
            payload,
        )
    )

    receipt = make_receipt(base_request(), nonce="egress-stale")
    status, payload = post(
        url,
        envelope(receipt=receipt, revocation=make_revocation_state(issued_at="2026-06-01T00:00:00Z")),
    )
    rows.append(
        row(
            "stale_revocation_denied",
            403,
            DENY,
            DRC["REVOCATION_UNKNOWN_OR_STALE"],
            status,
            payload,
        )
    )

    policy = base_policy()
    policy["require_capability_token"] = True
    request_value = base_request()
    receipt = make_receipt(request_value, policy=policy, nonce="egress-cap-ok")
    capability = make_capability(request_value, receipt, policy, nonce="egress-cap-ok")
    context = base_context()
    context["capability_token"] = capability
    status, payload = post(
        url,
        envelope(
            request=request_value,
            receipt=receipt,
            policy=policy,
            revocation=base_revocation(receipt),
            context=context,
        ),
    )
    rows.append(row("capability_valid_allow", 202, ALLOW, None, status, payload))

    status, payload = post(
        url,
        envelope(
            request=request_value,
            receipt=receipt,
            policy=policy,
            revocation=base_revocation(receipt),
            context=base_context(),
        ),
    )
    rows.append(
        row(
            "capability_absent_denied",
            403,
            DENY,
            DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"],
            status,
            payload,
        )
    )

    bad_capability = make_capability(
        request_value,
        receipt,
        policy,
        nonce="egress-cap-bad-aud",
        core_overrides={"audience": "other-gateway"},
    )
    context = base_context()
    context["capability_token"] = bad_capability
    status, payload = post(
        url,
        envelope(
            request=request_value,
            receipt=receipt,
            policy=policy,
            revocation=base_revocation(receipt),
            context=context,
        ),
    )
    rows.append(
        row(
            "capability_audience_mismatch_denied",
            403,
            DENY,
            DRC["CAPABILITY_AUDIENCE_MISMATCH"],
            status,
            payload,
        )
    )

    receipt = make_receipt(base_request(), core_overrides={"epoch_id": 46}, nonce="egress-rollback")
    status, payload = post(url, envelope(receipt=receipt, revocation=base_revocation(receipt)))
    rows.append(
        row(
            "epoch_rollback_denied",
            403,
            DENY,
            DRC["EPOCH_ROLLBACK_ATTEMPT"],
            status,
            payload,
        )
    )

    httpd.shutdown()
    thread.join(timeout=2)
    httpd.server_close()

    summary = {
        "package": "ORPRG-Eval v3.2 egress gateway adapter",
        "synthetic": True,
        "cases": len(rows),
        "passed": sum(1 for item in rows if item["pass"]),
        "failed": sum(1 for item in rows if not item["pass"]),
        "rows": rows,
    }
    (RESULTS / "egress_gateway_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown = [
        "# Egress Gateway Adapter Results",
        "",
        "Synthetic localhost HTTP egress boundary. No production claims.",
        "",
        f"- Cases: **{summary['cases']}**",
        f"- Passed: **{summary['passed']}**",
        f"- Failed: **{summary['failed']}**",
        "",
        "| Case | Status | Decision | Reason | Pass |",
        "|---|---:|---|---|---:|",
    ]
    for item in rows:
        markdown.append(
            f"| {item['case']} | {item['observed_status']} | {item['observed_decision']} | "
            f"{item['observed_reason'] or ''} | {item['pass']} |"
        )
    (RESULTS / "egress_gateway_summary.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
