from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import os
import time

import pytest

from orprg_eval.canonicalization import CanonicalizationError, canonicalize
from orprg_eval.crypto import sign_object
from orprg_eval.jsonio import DuplicateJSONKeyError, StrictJSONError, loads_strict_json
from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.replay import ReplayCache
from orprg_eval.vector_factory import (
    CAP_KEY,
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
from orprg_eval.verifier import verify_permit_receipt


def _resign_receipt(receipt: dict) -> dict:
    receipt["authenticity"]["signature"] = sign_object(ISSUER_KEY, receipt["receipt_core"])
    return receipt


def _resign_revocation(state: dict) -> dict:
    signed = state["signed_revocation_list"]
    signed["authenticity"]["signature"] = sign_object(REVOCATION_KEY, signed["body"])
    return state


def _resign_capability(token: dict) -> dict:
    token["authenticity"]["signature"] = sign_object(CAP_KEY, token["token_core"])
    return token


def _verify(
    *, request: dict | None = None, receipt: dict | None = None,
    policy: dict | None = None, revocation: dict | None = None,
    context: dict | None = None,
):
    request = request or base_request()
    receipt = receipt if receipt is not None else make_receipt(request, nonce="v226-default")
    return verify_permit_receipt(
        request,
        receipt,
        policy or base_policy(),
        revocation if revocation is not None else base_revocation(receipt),
        context or base_context(),
    )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda core: core["scope"].__setitem__("max_effect_budget", "10"),
        lambda core: core["scope"].__setitem__("key_ops", None),
        lambda core: core.__setitem__("epoch_id", True),
        lambda core: core.__setitem__("valid_to", "2026-06-04T00:00:00"),
        lambda core: core.__setitem__("anti_replay", None),
        lambda core: core.__setitem__("anti_replay", {}),
        lambda core: core.__setitem__("anti_replay", {"nonce": ""}),
        lambda core: core.__setitem__("anti_replay", {"nonce": 7}),
        lambda core: core.__setitem__("anti_replay", {"nonce": False}),
    ],
)
def test_correctly_signed_malformed_receipts_fail_closed(mutator):
    receipt = make_receipt(nonce="signed-malformed")
    mutator(receipt["receipt_core"])
    _resign_receipt(receipt)
    result = _verify(receipt=receipt)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["SCHEMA_VALIDATION_FAILURE"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("issued_at", 123),
        ("issued_at", "2026-06-02T23:59:40"),
        ("sequence", True),
        ("revoked_receipt_digests", None),
        ("revoked_issuers", [False]),
    ],
)
def test_correctly_signed_malformed_revocation_lists_fail_closed(field, value):
    receipt = make_receipt(nonce=f"rev-malformed-{field}")
    state = base_revocation(receipt)
    state["signed_revocation_list"]["body"][field] = value
    _resign_revocation(state)
    result = _verify(receipt=receipt, revocation=state)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["SCHEMA_VALIDATION_FAILURE"]


@pytest.mark.parametrize("bad_nonce", [None, "", 0, 1, False, True, [], {}])
def test_capability_nonce_is_required_and_strictly_typed(bad_nonce):
    request = base_request()
    policy = base_policy()
    policy["require_capability_token"] = True
    receipt = make_receipt(request, policy=policy, nonce="receipt-cap-nonce-types")
    token = make_capability(request, receipt, policy, nonce="valid-cap-nonce")
    token["token_core"]["nonce"] = bad_nonce
    _resign_capability(token)
    context = base_context()
    context["capability_token"] = token
    result = _verify(
        request=request, receipt=receipt, policy=policy,
        revocation=base_revocation(receipt), context=context,
    )
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]


def _constrained_case(*, nonce: str = "constrained-nonce"):
    request = base_request()
    request["effect_type"] = "SAFETY_HEARTBEAT"
    request["target_id"] = "safety-monitor"
    scope = base_scope()
    scope["effect_type"] = "SAFETY_HEARTBEAT"
    scope["target_id"] = "safety-monitor"
    policy = base_policy()
    policy["offline_constrained_mode_allowed"] = True
    policy["offline_constrained_effect_types"] = ["SAFETY_HEARTBEAT"]
    receipt = make_receipt(request, policy=policy, scope=scope, nonce=nonce)
    context = base_context()
    context["partitioned"] = True
    return request, policy, receipt, context


def test_constrained_mode_still_checks_receipt_replay():
    request, policy, receipt, context = _constrained_case(nonce="constrained-reused")
    context["used_nonces"] = ["constrained-reused"]
    result = _verify(
        request=request,
        receipt=receipt,
        policy=policy,
        revocation={"status": "missing"},
        context=context,
    )
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["ANTI_REPLAY_FAILURE"]


def test_constrained_mode_still_requires_capability():
    request, policy, receipt, context = _constrained_case(nonce="constrained-cap-required")
    policy["require_capability_token"] = True
    # Reissue because the policy digest/epoch profile is signature-bound even
    # though this synthetic policy uses the same digest value.
    receipt = make_receipt(
        request,
        policy=policy,
        scope=receipt["receipt_core"]["scope"],
        nonce="constrained-cap-required",
    )
    result = _verify(
        request=request,
        receipt=receipt,
        policy=policy,
        revocation={"status": "missing"},
        context=context,
    )
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]


def test_constrained_allow_occurs_only_after_nonwaivable_checks():
    request, policy, receipt, context = _constrained_case(nonce="constrained-good")
    context["replay_cache"] = ReplayCache()
    result = _verify(
        request=request,
        receipt=receipt,
        policy=policy,
        revocation={"status": "missing"},
        context=context,
    )
    assert result.decision == ALLOW
    assert result.constrained_mode is True
    second = _verify(
        request=request,
        receipt=receipt,
        policy=policy,
        revocation={"status": "missing"},
        context=context,
    )
    assert second.decision == DENY
    assert second.denial_reason_code == DRC["ANTI_REPLAY_FAILURE"]


def test_negative_clock_drift_uses_absolute_value():
    context = base_context()
    context["clock_drift_seconds"] = -301
    result = _verify(context=context)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["TIME_SOURCE_UNTRUSTED_OR_DRIFT"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("clock_drift_seconds", True),
        ("clock_drift_seconds", "301"),
        ("now", "2026-06-03T00:00:00"),
        ("used_nonces", None),
        ("used_capability_nonces", [False]),
    ],
)
def test_malformed_context_is_structured_schema_denial(field, value):
    context = base_context()
    context[field] = value
    result = _verify(context=context)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_naive_timestamp_result_is_host_timezone_invariant():
    receipt = make_receipt(nonce="naive-host-tz")
    receipt["receipt_core"]["valid_to"] = "2026-06-04T00:00:00"
    _resign_receipt(receipt)
    original = os.environ.get("TZ")
    observations = []
    try:
        for tz in ("UTC", "America/New_York", "Pacific/Kiritimati"):
            os.environ["TZ"] = tz
            if hasattr(time, "tzset"):
                time.tzset()
            result = _verify(receipt=receipt)
            observations.append((result.decision, result.denial_reason_code))
    finally:
        if original is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = original
        if hasattr(time, "tzset"):
            time.tzset()
    assert observations == [(DENY, DRC["SCHEMA_VALIDATION_FAILURE"])] * 3


@pytest.mark.parametrize("status", ["REVoked", "valid", "", 7, True, None])
def test_unknown_or_mistyped_revocation_status_denies(status):
    receipt = make_receipt(nonce=f"bad-status-{status!r}")
    state = base_revocation(receipt)
    state["status"] = status
    result = _verify(receipt=receipt, revocation=state)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_missing_revocation_status_is_not_implicitly_fresh():
    receipt = make_receipt(nonce="status-missing-field")
    state = base_revocation(receipt)
    del state["status"]
    result = _verify(receipt=receipt, revocation=state)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_explicit_revoked_status_cannot_allow_with_clean_signed_list():
    receipt = make_receipt(nonce="top-level-revoked")
    state = base_revocation(receipt)
    state["status"] = "revoked"
    result = _verify(receipt=receipt, revocation=state)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["REVOKED_CONFIRMED"]


def test_capability_is_bound_to_active_receipt_digest():
    request = base_request()
    policy = base_policy()
    policy["require_capability_token"] = True
    receipt = make_receipt(request, policy=policy, nonce="cap-receipt-binding")
    token = make_capability(request, receipt, policy, nonce="cap-binding-nonce")
    token["token_core"]["receipt_digest"] = "00" * 32
    _resign_capability(token)
    context = base_context()
    context["capability_token"] = token
    result = _verify(
        request=request, receipt=receipt, policy=policy,
        revocation=base_revocation(receipt), context=context,
    )
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["CAPABILITY_RECEIPT_BINDING_MISMATCH"]


def test_failed_capability_does_not_poison_receipt_replay_state():
    request = base_request()
    policy = base_policy()
    policy["require_capability_token"] = True
    receipt = make_receipt(request, policy=policy, nonce="transactional-receipt")
    bad = make_capability(request, receipt, policy, nonce="transactional-cap")
    bad["token_core"]["audience"] = "wrong-gateway"
    _resign_capability(bad)
    good = make_capability(request, receipt, policy, nonce="transactional-cap")

    receipt_cache = ReplayCache()
    capability_cache = ReplayCache()
    context = base_context()
    context.update(
        {
            "replay_cache": receipt_cache,
            "capability_replay_cache": capability_cache,
            "capability_token": bad,
        }
    )
    first = _verify(
        request=request, receipt=receipt, policy=policy,
        revocation=base_revocation(receipt), context=context,
    )
    assert first.denial_reason_code == DRC["CAPABILITY_AUDIENCE_MISMATCH"]
    assert receipt_cache.count() == 0
    assert capability_cache.count() == 0

    context["capability_token"] = good
    second = _verify(
        request=request, receipt=receipt, policy=policy,
        revocation=base_revocation(receipt), context=context,
    )
    assert second.decision == ALLOW
    assert receipt_cache.count() == 1
    assert capability_cache.count() == 1


def test_replay_reservation_allows_exactly_one_concurrent_commit():
    request = base_request()
    receipt = make_receipt(request, nonce="concurrent-receipt")
    cache = ReplayCache()

    def one_attempt(_):
        context = base_context()
        context["replay_cache"] = cache
        return _verify(
            request=request,
            receipt=receipt,
            revocation=base_revocation(receipt),
            context=context,
        ).decision

    with ThreadPoolExecutor(max_workers=16) as executor:
        decisions = list(executor.map(one_attempt, range(64)))
    assert decisions.count(ALLOW) == 1
    assert decisions.count(DENY) == 63


def test_duplicate_json_keys_are_rejected_before_object_construction():
    with pytest.raises(DuplicateJSONKeyError):
        loads_strict_json('{"effect_type":"A","effect_type":"B"}')


def test_nfc_colliding_json_keys_are_rejected():
    with pytest.raises(DuplicateJSONKeyError):
        loads_strict_json('{"é":1,"e\\u0301":2}')


@pytest.mark.parametrize("text", ['{"x":1.0}', '{"x":NaN}', '{"x":9223372036854775808}'])
def test_strict_json_rejects_nonprofile_numbers(text):
    with pytest.raises(StrictJSONError):
        loads_strict_json(text)


def test_strict_json_enforces_body_limit():
    with pytest.raises(StrictJSONError):
        loads_strict_json('{"x":"0123456789"}', max_bytes=8)


def test_canonicalization_rejects_normalized_duplicate_keys():
    with pytest.raises(CanonicalizationError):
        canonicalize({"é": 1, "e\u0301": 2})


def test_canonicalization_rejects_nonstring_keys_and_integer_overflow():
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "bad"})
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": 2**63})


class _ExplodingMapping(Mapping):
    def __getitem__(self, key):
        raise RuntimeError("boom")

    def __iter__(self):
        raise RuntimeError("boom")

    def __len__(self):
        raise RuntimeError("boom")


def test_public_verifier_is_total_for_hostile_mapping_objects():
    result = verify_permit_receipt(
        base_request(),
        make_receipt(nonce="hostile-mapping"),
        base_policy(),
        base_revocation(),
        _ExplodingMapping(),
    )
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["INTERNAL_FAIL_CLOSED"]
    assert result.evidence_digests["fail_closed_error_category"] == "RuntimeError"
