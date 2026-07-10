from __future__ import annotations

import http.client
import json

from orprg_eval.httpio import MAX_HTTP_BODY_BYTES
from orprg_eval.models import DRC
from orprg_eval.retrieval_gateway_adapter import start_server


def _post_raw(port: int, body: bytes, *, content_type: str = "application/json") -> tuple[int, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            "/v1/retrieve",
            body=body,
            headers={"content-type": content_type, "content-length": str(len(body))},
        )
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        return response.status, payload
    finally:
        connection.close()


def test_http_ingress_rejects_duplicate_json_members() -> None:
    server, thread = start_server()
    try:
        status, payload = _post_raw(int(server.server_address[1]), b'{"request":{},"request":{}}')
        assert status == 400
        assert payload["decision"] == "DENY"
        assert payload["denial_reason_code"] == DRC["DUPLICATE_JSON_KEY"]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_http_ingress_rejects_oversized_body_before_parsing() -> None:
    server, thread = start_server()
    connection = http.client.HTTPConnection("127.0.0.1", int(server.server_address[1]), timeout=5)
    try:
        # Advertise an oversized body without transmitting it. The adapter must
        # reject from framing metadata before attempting a body read.
        connection.putrequest("POST", "/v1/retrieve")
        connection.putheader("content-type", "application/json")
        connection.putheader("content-length", str(MAX_HTTP_BODY_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        assert response.status == 413
        assert payload["decision"] == "DENY"
        assert payload["denial_reason_code"] == DRC["RESOURCE_LIMIT_EXCEEDED"]
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_http_ingress_rejects_wrong_content_type() -> None:
    server, thread = start_server()
    try:
        status, payload = _post_raw(int(server.server_address[1]), b"{}", content_type="text/plain")
        assert status == 400
        assert payload["decision"] == "DENY"
        assert payload["denial_reason_code"] == DRC["SCHEMA_VALIDATION_FAILURE"]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
