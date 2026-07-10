"""Executable HTTP retrieval-gateway adapter for ORPRG-Eval v3.2.

Synthetic-only research artifact. The adapter is intentionally small: it exposes
an actual HTTP boundary and refuses release of synthetic records unless the
reference verifier returns ALLOW. This is not a production gateway and it does
not claim non-bypassability outside the local demo process.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Mapping, Tuple

from .httpio import HTTPIngressError, read_strict_json_body, send_json
from .models import ALLOW, DRC
from .replay import ReplayCache
from .verifier import verify_permit_receipt


SYNTHETIC_RECORDS: Dict[str, Dict[str, Any]] = {
    "case-record-001": {
        "record_id": "case-record-001",
        "record_digest": "sha256:synthetic-record-001",
        "class": "support-case",
        "payload": "REDACTED_SYNTHETIC_PAYLOAD_001",
    },
    "case-record-002": {
        "record_id": "case-record-002",
        "record_digest": "sha256:synthetic-record-002",
        "class": "support-case",
        "payload": "REDACTED_SYNTHETIC_PAYLOAD_002",
    },
}


class RetrievalGatewayAdapter:
    """A concrete local HTTP boundary adapter around verify_permit_receipt."""

    def __init__(self, records: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self.records = {k: dict(v) for k, v in (records or SYNTHETIC_RECORDS).items()}
        # Replay state belongs to the enforcement boundary.  Never accept a
        # caller-supplied cache or used-nonce list as the source of truth.
        self.replay_cache = ReplayCache()
        self.capability_replay_cache = ReplayCache()

    def handle_retrieve(self, envelope: Mapping[str, Any]) -> Tuple[int, Dict[str, Any]]:
        request = envelope.get("request")
        receipt = envelope.get("permit_receipt")
        policy_state = envelope.get("policy_state")
        revocation_state = envelope.get("revocation_state")
        wire_context = envelope.get("context", {})
        if not isinstance(request, Mapping) or not isinstance(policy_state, Mapping) or not isinstance(revocation_state, Mapping):
            return 400, {"decision": "DENY", "denial_reason_code": DRC["SCHEMA_VALIDATION_FAILURE"]}
        if not isinstance(wire_context, Mapping):
            return 400, {"decision": "DENY", "denial_reason_code": DRC["SCHEMA_VALIDATION_FAILURE"]}
        context = dict(wire_context)
        for replay_field in (
            "replay_cache",
            "capability_replay_cache",
            "used_nonces",
            "used_capability_nonces",
        ):
            context.pop(replay_field, None)
        context["replay_cache"] = self.replay_cache
        context["capability_replay_cache"] = self.capability_replay_cache
        result = verify_permit_receipt(request, receipt, policy_state, revocation_state, context)
        if result.decision != ALLOW:
            return 403, {"decision": result.decision, "denial_reason_code": result.denial_reason_code, "evidence_digests": result.evidence_digests}
        target = str(request.get("target_id", ""))
        if target not in self.records:
            # Unknown target after a valid verifier pass is modeled as a gateway-side scope/resource denial.
            return 404, {"decision": "DENY", "denial_reason_code": "GATEWAY_RECORD_NOT_FOUND"}
        return 200, {
            "decision": "ALLOW",
            "record": self.records[target],
            "evidence_digests": result.evidence_digests,
            "recency_observations": result.recency_observations,
        }


def make_handler(adapter: RetrievalGatewayAdapter):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ORPRG-Eval-RetrievalGateway/3.0"

        def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
            send_json(self, status, payload)

        def log_message(self, fmt: str, *args: Any) -> None:  # keep demos deterministic and quiet
            return

        def do_POST(self) -> None:  # noqa: N802 - stdlib API name
            try:
                envelope = read_strict_json_body(self)
            except HTTPIngressError as exc:
                self._send_json(400 if exc.denial_reason_code != DRC["RESOURCE_LIMIT_EXCEEDED"] else 413, {"decision": "DENY", "denial_reason_code": exc.denial_reason_code})
                return
            if not isinstance(envelope, Mapping):
                self._send_json(400, {"decision": "DENY", "denial_reason_code": DRC["SCHEMA_VALIDATION_FAILURE"]})
                return
            if self.path == "/v1/retrieve":
                status, payload = adapter.handle_retrieve(envelope)
                self._send_json(status, payload)
            elif self.path == "/v1/direct-bypass":
                # This endpoint intentionally represents a direct path that is refused.
                self._send_json(403, {"decision": "DENY", "denial_reason_code": DRC["GATEWAY_BYPASS_DENIED"]})
            else:
                self._send_json(404, {"decision": "DENY", "denial_reason_code": "GATEWAY_ROUTE_NOT_FOUND"})

    return Handler


def start_server(host: str = "127.0.0.1", port: int = 0, adapter: RetrievalGatewayAdapter | None = None):
    adapter = adapter or RetrievalGatewayAdapter()
    httpd = ThreadingHTTPServer((host, port), make_handler(adapter))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread
