from __future__ import annotations

import base64
import io
import json
import sqlite3
from copy import deepcopy
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import orprg_eval.canonicalization as canon
import orprg_eval.crypto as crypto
import orprg_eval.verifier as verifier
from orprg_eval.canonicalization import CanonicalizationError
from orprg_eval.crypto import (
    deterministic_private_key,
    public_key_b64,
    sign_envelope,
    sign_object,
    unb64,
    verify_signature,
)
from orprg_eval.httpio import HTTPIngressError, read_strict_json_body, send_json
from orprg_eval.jsonio import StrictJSONError, load_strict_json, loads_strict_json
from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.persistent_replay import SQLiteReplayCache
from orprg_eval.replay import MutableNonceListReplayCache, ReplayCache
from orprg_eval.schema import (
    validate_capability_schema,
    validate_context_schema,
    validate_policy_state_schema,
    validate_receipt_schema,
    validate_request_schema,
    validate_revocation_state_schema,
)
from orprg_eval.timeutil import TimeFormatError, is_strict_int, parse_rfc3339
from orprg_eval.vector_factory import (
    CAP_KEY,
    ISSUER_ID,
    ISSUER_KEY,
    REVOCATION_KEY,
    base_context,
    base_policy,
    base_request,
    base_revocation,
    base_scope,
    make_capability,
    make_receipt,
)


class _MultiValueHeaders(dict[str, str]):
    """Minimal case-insensitive header facade with duplicate field exposure."""

    def get_all(self, name: str):
        if name.lower() == "content-length":
            return ["2", "3"]
        value = self.get(name.lower())
        return None if value is None else [value]


class _FakeHTTPHandler:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.headers = headers or {
            "content-type": "application/json",
            "content-length": str(len(body)),
        }
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.status: int | None = None
        self.out_headers: list[tuple[str, str]] = []
        self.ended = False

    def send_response(self, status: int) -> None:
        self.status = status

    def send_header(self, key: str, value: str) -> None:
        self.out_headers.append((key.lower(), value))

    def end_headers(self) -> None:
        self.ended = True


# ---------------------------------------------------------------------------
# CP-JSON-2 canonicalization and strict JSON ingress boundaries.
# ---------------------------------------------------------------------------


def test_canonicalization_normalizes_sorts_and_hashes() -> None:
    obj = {"z": [None, True, 3], "e\u0301": "Cafe\u0301"}
    encoded = canon.canonicalize(obj)
    assert encoded == '{"z":[null,true,3],"é":"Café"}'.encode()
    assert canon.canonicalize_request(obj) == encoded
    assert canon.compute_action_digest(encoded) == canon.sha256_hex(encoded)
    assert canon.digest_obj(obj) == canon.sha256_hex(encoded)


@pytest.mark.parametrize(
    "value,match",
    [
        (2**63, "signed 64-bit"),
        (-(2**63) - 1, "signed 64-bit"),
        (1.25, "floating point"),
        ("\ud800", "surrogate"),
        ({1: "x"}, "member names"),
        ({"é": 1, "e\u0301": 2}, "duplicate normalized"),
        ({"x": object()}, "unsupported canonicalization type"),
    ],
)
def test_canonicalization_rejects_nonprofile_values(value, match: str) -> None:
    with pytest.raises(CanonicalizationError, match=match):
        canon.normalize_json_value(value)


def test_canonicalization_limit_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(canon, "MAX_STRING_UTF8_BYTES", 2)
    with pytest.raises(CanonicalizationError, match="string length"):
        canon.normalize_json_value("abc")

    monkeypatch.setattr(canon, "MAX_STRING_UTF8_BYTES", 65_536)
    monkeypatch.setattr(canon, "MAX_CONTAINER_ITEMS", 1)
    with pytest.raises(CanonicalizationError, match="array item"):
        canon.normalize_json_value([1, 2])
    with pytest.raises(CanonicalizationError, match="object member"):
        canon.normalize_json_value({"a": 1, "b": 2})

    monkeypatch.setattr(canon, "MAX_CONTAINER_ITEMS", 10_000)
    monkeypatch.setattr(canon, "MAX_CANONICAL_DEPTH", 1)
    with pytest.raises(CanonicalizationError, match="nesting"):
        canon.normalize_json_value({"a": {"b": 1}})

    monkeypatch.setattr(canon, "MAX_CANONICAL_DEPTH", 32)
    monkeypatch.setattr(canon, "MAX_TOTAL_NODES", 2)
    with pytest.raises(CanonicalizationError, match="node limit"):
        canon.normalize_json_value({"a": [1]})

    monkeypatch.setattr(canon, "MAX_TOTAL_NODES", 50_000)
    monkeypatch.setattr(canon, "MAX_CANONICAL_BYTES", 4)
    with pytest.raises(CanonicalizationError, match="canonical byte"):
        canon.canonicalize({"a": 1})


def test_canonicalize_rejects_profile_and_nonmapping() -> None:
    with pytest.raises(CanonicalizationError, match="unsupported canonicalization profile"):
        canon.canonicalize({}, "CP-JSON-1")
    with pytest.raises(CanonicalizationError, match="expects a mapping"):
        canon.canonicalize([])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "data,max_bytes,match",
    [
        (b"{\xff}", 100, "valid UTF-8"),
        (b"{}", 1, "exceeds maximum"),
        ("{}", 1, "exceeds maximum"),
        (123, 100, "text or bytes"),
        ('{"x":', 100, "strict public profile"),
        ('{"x":1.0}', 100, "floating point"),
        ('{"x":Infinity}', 100, "non-finite"),
        ('{"x":9223372036854775808}', 100, "signed 64-bit"),
        ('{"x":"\\ud800"}', 100, "strict public profile"),
    ],
)
def test_strict_json_rejects_invalid_ingress(data, max_bytes: int, match: str) -> None:
    with pytest.raises(StrictJSONError, match=match):
        loads_strict_json(data, max_bytes=max_bytes)  # type: ignore[arg-type]


def test_strict_json_loads_bytes_text_and_file(tmp_path: Path) -> None:
    expected = {"a": [1, True, None]}
    raw = b'{"a":[1,true,null]}'
    assert loads_strict_json(raw) == expected
    assert loads_strict_json(raw.decode()) == expected
    path = tmp_path / "strict.json"
    path.write_bytes(raw)
    assert load_strict_json(path) == expected


# ---------------------------------------------------------------------------
# Cryptographic envelope type/length/error handling.
# ---------------------------------------------------------------------------


def test_crypto_determinism_signing_envelope_and_cache() -> None:
    key_a = deterministic_private_key("unit")
    key_b = deterministic_private_key("unit")
    pub = public_key_b64(key_a)
    assert pub == public_key_b64(key_b)
    body = {"x": 1}
    sig = sign_object(key_a, body)
    assert verify_signature(pub, sig, body)
    # Second call exercises the bounded signature-result cache.
    assert verify_signature(pub, sig, body)
    envelope = sign_envelope(key_a, body, "issuer", sig_field="sig")
    assert envelope["body"] == body
    assert envelope["authenticity"]["issuer_id"] == "issuer"
    assert verify_signature(pub, envelope["authenticity"]["sig"], body)


@pytest.mark.parametrize("value", [None, "", 7, "***", "é"])
def test_unb64_strict(value) -> None:
    with pytest.raises(ValueError):
        unb64(value)  # type: ignore[arg-type]


def test_crypto_rejects_bad_key_signature_and_types() -> None:
    body = {"x": 1}
    key = deterministic_private_key("crypto-bad")
    pub = public_key_b64(key)
    sig = sign_object(key, body)
    assert not verify_signature(1, sig, body)  # type: ignore[arg-type]
    assert not verify_signature(pub, 1, body)  # type: ignore[arg-type]
    assert not verify_signature(base64.b64encode(b"short").decode(), sig, body)
    assert not verify_signature(pub, base64.b64encode(b"short").decode(), body)
    assert not verify_signature(pub, sig, {"x": 2})
    assert not verify_signature(pub, sig, {"x": 1.5})


def test_crypto_bounded_cache_eviction(monkeypatch: pytest.MonkeyPatch) -> None:
    crypto._PUB_CACHE.clear()
    crypto._SIG_CACHE.clear()
    monkeypatch.setattr(crypto, "_PUB_CACHE_MAX", 1)
    monkeypatch.setattr(crypto, "_SIG_CACHE_MAX", 1)
    for label in ("cache-a", "cache-b"):
        key = deterministic_private_key(label)
        assert verify_signature(public_key_b64(key), sign_object(key, {"k": label}), {"k": label})
    assert len(crypto._PUB_CACHE) == 1
    assert len(crypto._SIG_CACHE) == 1


# ---------------------------------------------------------------------------
# Time profile and HTTP framing.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,hour",
    [
        ("2026-07-10T12:34:56Z", 12),
        ("2026-07-10T12:34:56.123456Z", 12),
        ("2026-07-10T14:34:56+02:00", 12),
    ],
)
def test_parse_rfc3339_is_explicit_zone_and_utc(text: str, hour: int) -> None:
    parsed = parse_rfc3339(text)
    assert parsed.tzinfo == timezone.utc
    assert parsed.hour == hour


@pytest.mark.parametrize(
    "value",
    [None, "", 7, False, "x" * 41, "2026-07-10 12:34:56Z", "2026-07-10T12:34Z", "2026-02-30T12:00:00Z", "2026-07-10T12:00:00+99:00", "2026-07-10T12:00:00-00:00"],
)
def test_parse_rfc3339_rejects_nonprofile_inputs(value) -> None:
    with pytest.raises(TimeFormatError):
        parse_rfc3339(value)


def test_is_strict_int_excludes_bool() -> None:
    assert is_strict_int(0)
    assert is_strict_int(-1)
    assert not is_strict_int(True)
    assert not is_strict_int(1.0)


@pytest.mark.parametrize(
    "headers,body,expected_code",
    [
        ({"transfer-encoding": "chunked", "content-type": "application/json", "content-length": "2"}, b"{}", DRC["SCHEMA_VALIDATION_FAILURE"]),
        ({"content-type": "text/plain", "content-length": "2"}, b"{}", DRC["SCHEMA_VALIDATION_FAILURE"]),
        ({"content-type": "application/json"}, b"{}", DRC["SCHEMA_VALIDATION_FAILURE"]),
        ({"content-type": "application/json", "content-length": "+2"}, b"{}", DRC["SCHEMA_VALIDATION_FAILURE"]),
        ({"content-type": "application/json", "content-length": "0"}, b"", DRC["SCHEMA_VALIDATION_FAILURE"]),
        ({"content-type": "application/json", "content-length": "4"}, b"{}", DRC["SCHEMA_VALIDATION_FAILURE"]),
        ({"content-type": "application/json", "content-length": "7"}, b'{"x":1,', DRC["SCHEMA_VALIDATION_FAILURE"]),
        ({"content-type": "application/json", "content-length": "13"}, b'{"x":1,"x":2}', DRC["DUPLICATE_JSON_KEY"]),
        (_MultiValueHeaders({"content-type": "application/json"}), b"{}", DRC["SCHEMA_VALIDATION_FAILURE"]),
    ],
)
def test_http_reader_denies_ambiguous_or_invalid_inputs(headers, body: bytes, expected_code: str) -> None:
    handler = _FakeHTTPHandler(body, headers)
    with pytest.raises(HTTPIngressError) as exc:
        read_strict_json_body(handler, max_bytes=100)
    assert exc.value.denial_reason_code == expected_code


def test_http_reader_enforces_size_and_accepts_valid_json() -> None:
    oversized = _FakeHTTPHandler(b"", {"content-type": "application/json", "content-length": "101"})
    with pytest.raises(HTTPIngressError) as exc:
        read_strict_json_body(oversized, max_bytes=100)
    assert exc.value.denial_reason_code == DRC["RESOURCE_LIMIT_EXCEEDED"]

    good = _FakeHTTPHandler(b'{"x":1}', {"content-type": "application/json; charset=utf-8", "content-length": "7"})
    assert read_strict_json_body(good) == {"x": 1}


def test_send_json_sets_security_headers_and_canonical_body() -> None:
    handler = _FakeHTTPHandler(b"")
    send_json(handler, 403, {"z": 1, "a": "é"})
    assert handler.status == 403 and handler.ended
    headers = dict(handler.out_headers)
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert int(headers["content-length"]) == len(handler.wfile.getvalue())
    assert handler.wfile.getvalue() == '{"a":"é","z":1}'.encode()


# ---------------------------------------------------------------------------
# Transactional replay semantics, including persistent migration.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("domain,nonce", [("", "n"), (1, "n"), ("d" * 513, "n"), ("d", ""), ("d", 1), ("d", "n" * 257)])
def test_memory_replay_validates_namespaces(domain, nonce) -> None:
    with pytest.raises(ValueError):
        ReplayCache().reserve(domain, nonce)  # type: ignore[arg-type]


def test_memory_replay_full_transaction_lifecycle() -> None:
    cache = ReplayCache()
    reservation = cache.reserve("domain", "nonce")
    assert reservation is not None
    assert reservation.active and not reservation.committed
    assert cache.contains("domain", "nonce")
    assert cache.reserve("domain", "nonce") is None
    assert reservation.commit()
    assert not reservation.active and reservation.committed
    assert reservation.commit()  # idempotent
    reservation.release()  # no-op after commit
    assert cache.count() == 1
    assert cache.check_and_mark("domain", "nonce") is False

    released = cache.reserve("domain", "released")
    assert released is not None
    released.release()
    assert not released.active and not released.committed
    assert not cache.contains("domain", "released")


def test_memory_replay_context_manager_commit_and_release() -> None:
    cache = ReplayCache()
    with cache.reserve("d", "commit") as reservation:  # type: ignore[union-attr]
        assert reservation.active
    assert cache.contains("d", "commit")
    with pytest.raises(RuntimeError):
        with cache.reserve("d", "release") as reservation:  # type: ignore[union-attr]
            assert reservation.active
            raise RuntimeError("abort")
    assert not cache.contains("d", "release")


def test_memory_replay_rejects_wrong_reservation_tokens() -> None:
    cache = ReplayCache()
    reservation = cache.reserve("d", "n")
    assert reservation is not None
    assert cache._commit("d", "n", "wrong") is False
    cache._release("d", "n", "wrong")
    assert cache.contains("d", "n")
    reservation.release()


@pytest.mark.parametrize("domain,nonce", [("", "n"), ("d", ""), (False, "n"), ("d", False), ("d" * 513, "n"), ("d", "n" * 257)])
def test_sqlite_replay_validates_namespaces(tmp_path: Path, domain, nonce) -> None:
    cache = SQLiteReplayCache(tmp_path / "valid.sqlite3")
    with pytest.raises(ValueError):
        cache.reserve(domain, nonce)  # type: ignore[arg-type]


def test_sqlite_replay_lifecycle_idempotency_and_wrong_token(tmp_path: Path) -> None:
    cache = SQLiteReplayCache(tmp_path / "life.sqlite3")
    reservation = cache.reserve("d", "n")
    assert reservation is not None
    assert reservation.active and not reservation.committed
    assert cache._commit("d", "n", "wrong") is False
    cache._release("d", "n", "wrong")
    assert cache.contains("d", "n")
    assert reservation.commit()
    assert reservation.commit()
    assert not reservation.active and reservation.committed
    reservation.release()
    assert cache.count() == 1
    assert cache.check_and_mark("d", "n") is False


def test_sqlite_replay_migrates_v225_schema(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    db = sqlite3.connect(path)
    try:
        db.execute(
            "CREATE TABLE used_nonces (domain TEXT NOT NULL, nonce TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(domain, nonce))"
        )
        db.execute("INSERT INTO used_nonces(domain, nonce) VALUES (?, ?)", ("legacy", "used"))
        db.commit()
    finally:
        db.close()
    cache = SQLiteReplayCache(path)
    assert cache.contains("legacy", "used")
    assert cache.count() == 1
    assert cache.reserve("legacy", "used") is None


# ---------------------------------------------------------------------------
# Runtime schema totality and exact-profile branches.
# ---------------------------------------------------------------------------


def _assert_schema_failure(fn, value, expected: str = DRC["SCHEMA_VALIDATION_FAILURE"]) -> None:
    assert fn(value) == expected


@pytest.mark.parametrize(
    "request_value",
    [
        None,
        {},
        {**base_request(), "effect_type": ""},
        {**base_request(), "representation_class_id": ""},
        {**base_request(), "max_effect_budget": True},
        {**base_request(), "bad": 1},
        {**base_request(), "nested": 1.5},
        {**base_request(), "effect_type": "KEY_RELEASE", "key_id": "", "key_op": "decrypt"},
        {**base_request(), "effect_type": "EXTENSION_INSTALL"},
    ],
)
def test_request_schema_failure_matrix(request_value) -> None:
    _assert_schema_failure(validate_request_schema, request_value)


def test_request_schema_accepts_key_and_extension_profiles() -> None:
    key_request = {**base_request(), "effect_type": "KEY_RELEASE", "key_id": "k", "key_op": "decrypt"}
    extension_request = {**base_request(), "effect_type": "EXTENSION_INSTALL", "artifact_id": "artifact"}
    assert validate_request_schema(key_request) is None
    assert validate_request_schema(extension_request) is None


@pytest.mark.parametrize(
    "mutator",
    [
        lambda r: r.pop("receipt_core"),
        lambda r: r["receipt_core"].pop("scope"),
        lambda r: r["receipt_core"].__setitem__("unknown", 1),
        lambda r: r["authenticity"].__setitem__("unknown", 1),
        lambda r: r["receipt_core"].__setitem__("policy_digest", ""),
        lambda r: r["receipt_core"].__setitem__("purpose_id", ""),
        lambda r: r["receipt_core"].__setitem__("identity_binding", []),
        lambda r: r["receipt_core"].__setitem__("epoch_id", True),
        lambda r: r["receipt_core"].__setitem__("action_digest", "0"),
        lambda r: r["receipt_core"].__setitem__("scope", {}),
        lambda r: r["receipt_core"].__setitem__("anti_replay", {"nonce": "n", "extra": 1}),
        lambda r: r["receipt_core"].__setitem__("valid_from", "2026-07-11T00:00:00Z"),
        lambda r: r["authenticity"].__setitem__("issuer_id", ""),
        lambda r: r["receipt_core"].__setitem__("scope", {"key_ops": ["x", "x"]}),
        lambda r: r["receipt_core"].__setitem__("scope", {"unknown": "x"}),
        lambda r: r["receipt_core"].__setitem__("scope", {"max_effect_budget": False}),
    ],
)
def test_receipt_schema_failure_matrix(mutator) -> None:
    receipt = make_receipt(nonce="schema-receipt")
    mutator(receipt)
    assert validate_receipt_schema(receipt) in {DRC["RECEIPT_MALFORMED"], DRC["SCHEMA_VALIDATION_FAILURE"]}


@pytest.mark.parametrize(
    "mutator",
    [
        lambda t: t.pop("token_core"),
        lambda t: t["token_core"].pop("nonce"),
        lambda t: t["token_core"].__setitem__("extra", 1),
        lambda t: t["authenticity"].__setitem__("extra", 1),
        lambda t: t["token_core"].__setitem__("action_digest", "0"),
        lambda t: t["token_core"].__setitem__("receipt_digest", "0"),
        lambda t: t["token_core"].__setitem__("audience", ""),
        lambda t: t["token_core"].__setitem__("epoch_id", True),
        lambda t: t["token_core"].__setitem__("nonce", ""),
        lambda t: t["token_core"].__setitem__("valid_to", "naive"),
        lambda t: t["authenticity"].__setitem__("signature", ""),
    ],
)
def test_capability_schema_failure_matrix(mutator) -> None:
    request = base_request()
    receipt = make_receipt(request, nonce="cap-schema-receipt")
    token = make_capability(request, receipt, nonce="cap-schema")
    mutator(token)
    assert validate_capability_schema(token) == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]


@pytest.mark.parametrize(
    "mutator",
    [
        lambda p: p.pop("now"),
        lambda p: p.__setitem__("unknown", 1),
        lambda p: p.__setitem__("now", "naive"),
        lambda p: p.__setitem__("policy_digest", ""),
        lambda p: p.__setitem__("current_epoch_id", True),
        lambda p: p.__setitem__("epoch_compatibility", "loose"),
        lambda p: p.__setitem__("require_transparency", 1),
        lambda p: p.__setitem__("trusted_issuers", []),
        lambda p: p.__setitem__("trusted_issuers", {"": "key"}),
        lambda p: p.__setitem__("offline_constrained_effect_types", "X"),
        lambda p: p.__setitem__("offline_constrained_effect_types", ["X", "X"]),
    ],
)
def test_policy_schema_failure_matrix(mutator) -> None:
    policy = base_policy()
    mutator(policy)
    _assert_schema_failure(validate_policy_state_schema, policy)


class _BadReplayCache:
    reserve = None


@pytest.mark.parametrize(
    "context",
    [
        {"unknown": True},
        {"now": "naive"},
        {"clock_drift_seconds": True},
        {"partitioned": 1},
        {"used_nonces": "nonce"},
        {"epoch_sources": {"x": 1}},
        {"epoch_sources": [object()]},
        {"jurisdiction": ""},
        {"replay_cache": _BadReplayCache()},
        {"capability_token": []},
        {"identity_binding": []},
        {"identity_binding": {"score": 1.5}},
        {"cross_log_coherence": "unknown"},
        {"expected_receipt_digest": "0"},
    ],
)
def test_context_schema_failure_matrix(context) -> None:
    _assert_schema_failure(validate_context_schema, context)


@pytest.mark.parametrize(
    "state",
    [
        {"unknown": 1},
        {"status": "invalid"},
        {"status": True},
        {"last_updated": "naive"},
        {"revoked_receipt_digests": "digest"},
        {"status": "fresh", "revoked_receipt_digests": ["not-a-sha256"]},
        {"signed_revocation_list": []},
        {"signed_revocation_list": {"body": [], "authenticity": {}}},
        {"signed_revocation_list": {"body": {}, "authenticity": {}}},
        {"merkle": []},
    ],
)
def test_revocation_schema_failure_matrix(state) -> None:
    _assert_schema_failure(validate_revocation_state_schema, state)


def test_revocation_signed_body_failure_matrix() -> None:
    baseline = base_revocation(make_receipt(nonce="rev-schema"))
    mutations = [
        ("body", "issuer_id", ""),
        ("body", "sequence", True),
        ("body", "issued_at", "naive"),
        ("body", "revoked_receipt_digests", "x"),
        ("body", "revoked_receipt_digests", ["not-a-sha256"]),
        ("authenticity", "issuer_id", ""),
        ("authenticity", "signature", ""),
    ]
    for section, field, value in mutations:
        state = deepcopy(baseline)
        state["signed_revocation_list"][section][field] = value
        _assert_schema_failure(validate_revocation_state_schema, state)


# ---------------------------------------------------------------------------
# Direct capability enforcement and verifier fault containment.
# ---------------------------------------------------------------------------


def _capability_case(*, cache=None):
    request = base_request()
    policy = base_policy()
    policy["require_capability_token"] = True
    receipt = make_receipt(request, policy=policy, nonce="direct-cap-receipt")
    token = make_capability(request, receipt, policy, nonce="direct-cap-nonce")
    context = base_context()
    context["expected_receipt_digest"] = canon.digest_obj(receipt["receipt_core"])
    if cache is not None:
        context["capability_replay_cache"] = cache
    return request, receipt, token, policy, context


def test_standalone_capability_validation_and_replay() -> None:
    cache = ReplayCache()
    request, receipt, token, policy, context = _capability_case(cache=cache)
    evidence: dict = {}
    assert verifier.verify_capability_token(
        request, token, policy, context, {}, expected_receipt_digest="g" * 64
    ) == DRC["CAPABILITY_RECEIPT_BINDING_MISMATCH"]
    assert verifier.verify_capability_token(request, token, policy, context, evidence) is None
    assert "capability_token_digest" in evidence
    assert verifier.verify_capability_token(request, token, policy, context, {}) == DRC["CAPABILITY_REPLAY"]


@pytest.mark.parametrize(
    "mutation,expected",
    [
        (lambda r, t, p, c: c.pop("expected_receipt_digest"), DRC["CAPABILITY_RECEIPT_BINDING_MISMATCH"]),
        (lambda r, t, p, c: r.__setitem__("effect_type", ""), DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]),
        (lambda r, t, p, c: p.__setitem__("now", "naive"), DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]),
        (lambda r, t, p, c: c.__setitem__("partitioned", 1), DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]),
        (lambda r, t, p, c: p.__setitem__("trusted_capability_issuers", {}), DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]),
        (lambda r, t, p, c: t["authenticity"].__setitem__("signature", "AAAA"), DRC["CAPABILITY_SIGNATURE_INVALID"]),
        (lambda r, t, p, c: t["token_core"].__setitem__("valid_to", "2026-06-02T00:00:00Z"), DRC["CAPABILITY_EXPIRED"]),
        (lambda r, t, p, c: t["token_core"].__setitem__("action_digest", "0" * 64), DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]),
        (lambda r, t, p, c: t["token_core"].__setitem__("receipt_digest", "0" * 64), DRC["CAPABILITY_RECEIPT_BINDING_MISMATCH"]),
        (lambda r, t, p, c: t["token_core"].__setitem__("audience", "wrong"), DRC["CAPABILITY_AUDIENCE_MISMATCH"]),
        (lambda r, t, p, c: t["token_core"].__setitem__("tenant_id", "wrong"), DRC["TENANT_MISMATCH"]),
        (lambda r, t, p, c: t["token_core"].__setitem__("policy_digest", "wrong"), DRC["POLICY_DIGEST_MISMATCH"]),
        (lambda r, t, p, c: t["token_core"].__setitem__("epoch_id", 48), DRC["EPOCH_MISMATCH"]),
        (lambda r, t, p, c: c["used_capability_nonces"].append("direct-cap-nonce"), DRC["CAPABILITY_REPLAY"]),
    ],
)
def test_standalone_capability_denial_matrix(mutation, expected: str) -> None:
    request, receipt, token, policy, context = _capability_case()
    mutation(request, token, policy, context)
    # Mutations to signed core fields need a fresh valid signature unless the
    # expected result specifically exercises signature failure.
    if expected != DRC["CAPABILITY_SIGNATURE_INVALID"] and isinstance(token, dict):
        token["authenticity"]["signature"] = sign_object(CAP_KEY, token["token_core"])
    assert verifier.verify_capability_token(request, token, policy, context, {}) == expected


class _CommitFalseReservation:
    def commit(self) -> bool:
        return False

    def release(self) -> None:
        pass


class _ExplodingReservation:
    def commit(self) -> bool:
        raise RuntimeError("commit fault")

    def release(self) -> None:
        raise RuntimeError("release fault")


class _CommitFalseCache:
    def reserve(self, domain, nonce):
        return _CommitFalseReservation()

    def contains(self, domain, nonce):
        return False


class _ExplodingCache:
    def reserve(self, domain, nonce):
        return _ExplodingReservation()

    def contains(self, domain, nonce):
        return False


class _ReserveExplodesCache:
    def reserve(self, domain, nonce):
        raise RuntimeError("reserve fault")

    def contains(self, domain, nonce):
        return False


@pytest.mark.parametrize(
    "cache,expected",
    [
        (_CommitFalseCache(), DRC["ANTI_REPLAY_FAILURE"]),
        (_ExplodingCache(), DRC["REPLAY_STATE_FAILURE"]),
        (_ReserveExplodesCache(), DRC["REPLAY_STATE_FAILURE"]),
    ],
)
def test_verifier_replay_fault_injection_is_fail_closed(cache, expected: str) -> None:
    receipt = make_receipt(nonce=f"fault-{type(cache).__name__}")
    context = base_context()
    context["replay_cache"] = cache
    result = verifier.verify_permit_receipt(
        base_request(), receipt, base_policy(), base_revocation(receipt), context
    )
    assert result.decision == DENY
    assert result.denial_reason_code == expected


def test_verifier_unsigned_revocation_mode_current_stale_and_revoked() -> None:
    request = base_request()
    policy = base_policy()
    policy["require_signed_revocation_list"] = False

    receipt = make_receipt(request, policy=policy, nonce="unsigned-current")
    current = {"status": "fresh", "last_updated": "2026-06-02T23:59:40Z", "revoked_receipt_digests": [], "revoked_issuers": []}
    allowed = verifier.verify_permit_receipt(request, receipt, policy, current, base_context())
    assert allowed.decision == ALLOW
    assert allowed.recency_observations["revocation_age_seconds"] == 20

    stale_receipt = make_receipt(request, policy=policy, nonce="unsigned-stale")
    stale = {**current, "last_updated": "2026-06-01T00:00:00Z"}
    denied = verifier.verify_permit_receipt(request, stale_receipt, policy, stale, base_context())
    assert denied.denial_reason_code == DRC["REVOCATION_UNKNOWN_OR_STALE"]

    revoked_receipt = make_receipt(request, policy=policy, nonce="unsigned-revoked")
    revoked = {**current, "revoked_issuers": [ISSUER_ID]}
    denied = verifier.verify_permit_receipt(request, revoked_receipt, policy, revoked, base_context())
    assert denied.denial_reason_code == DRC["REVOKED_CONFIRMED"]


def test_verifier_signed_revocation_list_binding_failures() -> None:
    receipt = make_receipt(nonce="rev-binding")

    missing = {"status": "fresh"}
    assert verifier.verify_permit_receipt(base_request(), receipt, base_policy(), missing, base_context()).denial_reason_code == DRC["REVOCATION_UNKNOWN_OR_STALE"]

    mismatch = base_revocation(receipt)
    mismatch["signed_revocation_list"]["authenticity"]["issuer_id"] = "other"
    assert verifier.verify_permit_receipt(base_request(), receipt, base_policy(), mismatch, base_context()).denial_reason_code == DRC["REVOCATION_SIGNATURE_INVALID"]

    untrusted_policy = base_policy()
    untrusted_policy["revocation_authorities"] = {}
    assert verifier.verify_permit_receipt(base_request(), receipt, untrusted_policy, base_revocation(receipt), base_context()).denial_reason_code == DRC["REVOCATION_SIGNATURE_INVALID"]


def test_verifier_context_profile_mismatch_and_downstream_capability_signal() -> None:
    receipt = make_receipt(nonce="profile-context")
    context = base_context()
    context["canonicalization_profile_ref"] = "CP-OTHER"
    result = verifier.verify_permit_receipt(base_request(), receipt, base_policy(), base_revocation(receipt), context)
    assert result.denial_reason_code == DRC["CANONICALIZATION_PROFILE_MISMATCH"]

    receipt = make_receipt(nonce="downstream-absent")
    context = base_context()
    context["downstream_capability_present"] = False
    result = verifier.verify_permit_receipt(base_request(), receipt, base_policy(), base_revocation(receipt), context)
    assert result.denial_reason_code == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]


def test_verifier_public_entrypoint_catches_unexpected_internal_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args, **kwargs):
        raise LookupError("attacker-controlled detail must not escape")

    monkeypatch.setattr(verifier, "_verify_permit_receipt_inner", boom)
    result = verifier.verify_permit_receipt({}, None, {}, {}, {})
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["INTERNAL_FAIL_CLOSED"]
    assert result.evidence_digests == {"fail_closed_error_category": "LookupError"}


def test_verifier_helper_reservation_fault_paths() -> None:
    class ReleaseFault:
        def release(self):
            raise RuntimeError

    verifier._release_all([None, ReleaseFault()])
    assert verifier._commit_all([None, _CommitFalseReservation()]) is False
    assert verifier._reserve(None, "d", "n") is None


def test_make_receipt_core_optional_fields_and_extras() -> None:
    core = verifier.make_receipt_core(
        base_request(),
        policy_digest="p",
        epoch_id=1,
        issuer_id="i",
        valid_from="2026-06-02T00:00:00Z",
        valid_to="2026-06-04T00:00:00Z",
        scope=base_scope(),
        nonce="n",
        permit_provenance_digest=None,
        tenant_id=None,
        purpose_id=None,
        jurisdiction=None,
        extras={"assurance_evidence_digest": "e"},
    )
    assert "permit_provenance_digest" not in core
    assert "tenant_id" not in core
    assert "purpose_id" not in core
    assert "jurisdiction" not in core
    assert core["assurance_evidence_digest"] == "e"


def test_schema_rejects_nul_in_required_request_string() -> None:
    from orprg_eval.models import DRC
    from orprg_eval.schema import validate_request_schema
    from orprg_eval.vector_factory import base_request

    request = base_request()
    request["target_id"] = "bad\x00target"
    assert validate_request_schema(request) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_schema_rejects_extension_request_without_artifact_id() -> None:
    from orprg_eval.models import DRC
    from orprg_eval.schema import validate_request_schema
    from orprg_eval.vector_factory import base_request

    request = base_request()
    request["effect_type"] = "EXTENSION_INSTALL"
    assert validate_request_schema(request) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_schema_rejects_non_string_receipt_profile() -> None:
    from orprg_eval.models import DRC
    from orprg_eval.schema import validate_receipt_schema
    from orprg_eval.vector_factory import base_request, make_receipt

    receipt = make_receipt(base_request(), nonce="schema-profile-type")
    receipt["receipt_core"]["canonicalization_profile_ref"] = 7
    assert validate_receipt_schema(receipt) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_package_root_exports_hardened_verifier() -> None:
    import orprg_eval
    from orprg_eval.verifier import verify_permit_receipt as hardened_verify

    assert orprg_eval.verify_permit_receipt is hardened_verify


def test_request_schema_rejects_noncanonical_float_before_numeric_coercion() -> None:
    request = base_request()
    request["max_effect_budget"] = 1.5
    assert validate_request_schema(request) == DRC["SCHEMA_VALIDATION_FAILURE"]


# ---------------------------------------------------------------------------
# JSON-serializable transactional replay adapter.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain,nonce",
    [("", "n"), (1, "n"), ("d" * 513, "n"), ("d", ""), ("d", 1), ("d", "n" * 257)],
)
def test_mutable_nonce_list_replay_validates_namespaces(domain, nonce) -> None:
    cache = MutableNonceListReplayCache([])
    with pytest.raises(ValueError):
        cache.reserve(domain, nonce)  # type: ignore[arg-type]


def test_mutable_nonce_list_requires_a_real_list() -> None:
    with pytest.raises(TypeError):
        MutableNonceListReplayCache(())  # type: ignore[arg-type]


def test_mutable_nonce_list_full_transaction_and_properties() -> None:
    values: list[str] = []
    cache = MutableNonceListReplayCache(values)
    reservation = cache.reserve("domain", "nonce")
    assert reservation is not None
    assert reservation.active is True
    assert reservation.committed is False
    assert cache.contains("domain", "nonce") is True
    assert cache.reserve("domain", "nonce") is None
    assert reservation.commit() is True
    assert reservation.active is False
    assert reservation.committed is True
    assert reservation.commit() is True
    reservation.release()
    assert values == ["nonce"]
    assert cache.count() == 1
    assert cache.check_and_mark("domain", "nonce") is False
    assert cache.contains("other-domain", "missing") is False


def test_mutable_nonce_list_release_and_token_fault_branches() -> None:
    values: list[str] = []
    cache = MutableNonceListReplayCache(values)
    reservation = cache.reserve("d", "release")
    assert reservation is not None
    cache._release("d", "release", "wrong")
    assert cache.contains("d", "release") is True
    reservation.release()
    assert reservation.active is False
    assert cache.contains("d", "release") is False

    # A token not owned by this reservation reports the durable list state.
    assert cache._commit("d", "absent", "wrong") is False
    values.append("present")
    assert cache._commit("d", "present", "wrong") is True


def test_mutable_nonce_list_detects_external_commit_race() -> None:
    values: list[str] = []
    cache = MutableNonceListReplayCache(values)
    reservation = cache.reserve("d", "raced")
    assert reservation is not None
    values.append("raced")
    assert reservation.commit() is False
    assert reservation.committed is False


def test_mutable_nonce_list_check_and_mark_success() -> None:
    values: list[str] = []
    cache = MutableNonceListReplayCache(values)
    assert cache.check_and_mark("d", "fresh") is True
    assert values == ["fresh"]


# ---------------------------------------------------------------------------
# Remaining verifier branch closure after transactional list-state hardening.
# ---------------------------------------------------------------------------


def test_finish_timings_is_idempotent() -> None:
    timings = {"total_ns": 9}
    assert verifier._finish_timings(timings) == {"total_ns": 9}


def test_scope_without_budget_constraint_can_pass() -> None:
    request = base_request()
    scope = dict(request)
    scope.pop("payload_digest")
    scope.pop("max_effect_budget")
    assert verifier._scope_code(request, scope) is None


def test_merkle_helper_rejects_nonmapping_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    request = base_request()
    policy = base_policy()
    policy["require_merkle_revocation_proof"] = True
    receipt = make_receipt(request, policy=policy, nonce="v226-merkle-entry-shape")
    state = base_revocation(receipt, merkle=True)
    state["merkle"]["receipt_proof"] = {"proof_type": "inclusion", "entry": []}
    monkeypatch.setattr(verifier, "verify_inclusion_proof", lambda proof, root: True)
    code = verifier._verify_merkle_revocation_proofs(
        state,
        policy,
        {},
        {},
        parse_rfc3339(base_context()["now"]),
        verifier.digest_obj(receipt["receipt_core"]),
        ISSUER_ID,
    )
    assert code == DRC["TRANSPARENCY_PROOF_INVALID"]


def test_merkle_helper_converts_parser_fault_to_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    request = base_request()
    policy = base_policy()
    receipt = make_receipt(request, policy=policy, nonce="v226-merkle-parser-fault")
    state = base_revocation(receipt, merkle=True)
    monkeypatch.setattr(verifier, "parse_time", lambda value: (_ for _ in ()).throw(ValueError("fault")))
    code = verifier._verify_merkle_revocation_proofs(
        state,
        policy,
        {},
        {},
        parse_rfc3339(base_context()["now"]),
        verifier.digest_obj(receipt["receipt_core"]),
        ISSUER_ID,
    )
    assert code == DRC["TRANSPARENCY_PROOF_INVALID"]


def test_capability_requires_replay_state_when_cache_absent() -> None:
    request = base_request()
    policy = base_policy()
    receipt = make_receipt(request, policy=policy, nonce="v226-cap-replay-state-receipt")
    token = make_capability(request, receipt, policy, nonce="v226-cap-replay-state")
    context = base_context()
    context.pop("used_capability_nonces")
    code, replay = verifier._validate_capability_token(
        request,
        token,
        policy,
        context,
        {},
        parse_rfc3339(context["now"]),
        expected_receipt_digest=verifier.digest_obj(receipt["receipt_core"]),
    )
    assert code == DRC["REPLAY_STATE_FAILURE"] and replay is None


def test_public_capability_helper_accepts_preparsed_now() -> None:
    request = base_request()
    policy = base_policy()
    receipt = make_receipt(request, policy=policy, nonce="v226-cap-now-receipt")
    token = make_capability(request, receipt, policy, nonce="v226-cap-now")
    context = base_context()
    code = verifier.verify_capability_token(
        request,
        token,
        policy,
        context,
        {},
        now=parse_rfc3339(context["now"]),
        expected_receipt_digest=verifier.digest_obj(receipt["receipt_core"]),
    )
    assert code is None


def test_matching_identity_and_present_attestation_continue_to_allow() -> None:
    request = base_request()
    policy = base_policy()
    policy["require_identity_binding"] = True
    receipt = make_receipt(
        request,
        policy=policy,
        nonce="v226-identity-attestation-pass",
        core_overrides={"identity_binding": {"workload": "agent-A"}},
    )
    context = base_context()
    context.update(
        {
            "identity_binding": {"workload": "agent-A"},
            "attestation_required": True,
            "attestation_present": True,
        }
    )
    result = verifier.verify_permit_receipt(
        request, receipt, policy, base_revocation(receipt), context
    )
    assert result.decision == ALLOW


def test_policy_can_disable_provenance_requirement() -> None:
    request = base_request()
    policy = base_policy()
    policy["require_permit_provenance"] = False
    receipt = make_receipt(
        request,
        policy=policy,
        nonce="v226-provenance-not-required",
        permit_provenance_digest=None,
    )
    result = verifier.verify_permit_receipt(
        request, receipt, policy, base_revocation(receipt), base_context()
    )
    assert result.decision == ALLOW
