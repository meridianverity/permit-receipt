from __future__ import annotations

from copy import deepcopy

import pytest

import orprg_eval.verifier as verifier
from orprg_eval.canonicalization import digest_obj
from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.replay import MutableNonceListReplayCache, ReplayCache
from orprg_eval.retrieval_gateway_adapter import RetrievalGatewayAdapter
from orprg_eval.schema import (
    validate_policy_state_schema,
    validate_receipt_schema,
    validate_revocation_state_schema,
)
from orprg_eval.vector_factory import (
    base_context,
    base_policy,
    base_request,
    base_revocation,
    make_capability,
    make_receipt,
)


class _RejectingCache:
    def reserve(self, _domain: str, _nonce: str):
        return None

    def contains(self, _domain: str, _nonce: str) -> bool:
        return False


# Replay state is a security boundary: exercise every reservation lifecycle edge.
def test_in_memory_replay_reservation_full_lifecycle() -> None:
    cache = ReplayCache()
    reservation = cache.reserve("receipt", "n1")
    assert reservation is not None
    assert reservation.domain == "receipt"
    assert reservation.nonce == "n1"
    assert cache.contains("receipt", "n1")
    assert cache.count() == 0
    assert cache.reserve("receipt", "n1") is None
    assert cache._commit("receipt", "n1", "wrong-token") is False
    assert reservation.active is True
    assert reservation.committed is False
    assert reservation.commit() is True
    assert reservation.active is False
    assert reservation.committed is True
    assert cache.count() == 1
    assert reservation.commit() is True
    reservation.release()  # committed reservations are not removed
    assert cache.contains("receipt", "n1")

    released = cache.reserve("receipt", "n2")
    assert released is not None
    released.release()
    released.release()
    assert not cache.contains("receipt", "n2")
    assert cache._commit("receipt", "missing", "token") is False
    cache._release("receipt", "missing", "token")
    assert cache.check_and_mark("receipt", "n3") is True
    assert cache.check_and_mark("receipt", "n3") is False


def test_mutable_nonce_list_replay_full_lifecycle() -> None:
    with pytest.raises(TypeError):
        MutableNonceListReplayCache(("n1",))  # type: ignore[arg-type]

    state: list[str] = []
    cache = MutableNonceListReplayCache(state)
    with pytest.raises(ValueError):
        cache.reserve("", "n")
    with pytest.raises(ValueError):
        cache.reserve("receipt", "")
    reservation = cache.reserve("receipt", "n1")
    assert reservation is not None
    assert reservation.domain == "receipt"
    assert reservation.nonce == "n1"
    assert cache.contains("receipt", "n1")
    assert cache.count() == 0
    assert cache.reserve("receipt", "n1") is None
    assert cache._commit("receipt", "n1", "wrong-token") is False
    assert reservation.active is True
    assert reservation.committed is False
    assert reservation.commit() is True
    assert reservation.active is False
    assert reservation.committed is True
    assert state == ["n1"]
    assert cache.count() == 1
    assert reservation.commit() is True
    reservation.release()

    released = cache.reserve("receipt", "n2")
    assert released is not None
    released.release()
    released.release()
    assert "n2" not in state

    externally_consumed = cache.reserve("receipt", "n3")
    assert externally_consumed is not None
    state.append("n3")
    assert externally_consumed.commit() is False
    externally_consumed.release()
    state.remove("n3")

    missing = cache.reserve("receipt", "n4")
    assert missing is not None
    cache._release("receipt", "n4", "wrong-token")
    assert cache.contains("receipt", "n4")
    missing.release()
    cache._release("receipt", "missing", "token")

    assert cache.check_and_mark("receipt", "n5") is True
    assert cache.check_and_mark("receipt", "n5") is False


# Strict schema branches are tested with otherwise-valid surrounding objects so
# each assertion reaches the intended fail-closed rule rather than an earlier one.
def test_schema_release_edge_cases() -> None:
    request = base_request()
    receipt = make_receipt(request, nonce="schema-edges")

    malformed_provenance = deepcopy(receipt)
    malformed_provenance["receipt_core"]["permit_provenance_digest"] = "sha256:not-a-digest"
    assert validate_receipt_schema(malformed_provenance) == DRC["SCHEMA_VALIDATION_FAILURE"]

    policy = base_policy()
    bad_profiles = deepcopy(policy)
    bad_profiles["trusted_authority_profile_ids"] = "AP-SYNTH-AL5"
    assert validate_policy_state_schema(bad_profiles) == DRC["SCHEMA_VALIDATION_FAILURE"]
    bad_provenance = deepcopy(policy)
    bad_provenance["trusted_permit_provenance_digests"] = ["sha256:not-a-digest"]
    assert validate_policy_state_schema(bad_provenance) == DRC["SCHEMA_VALIDATION_FAILURE"]

    valid_revocation = base_revocation(receipt)
    bad_last_updated = deepcopy(valid_revocation)
    bad_last_updated["last_updated"] = "2026-06-03T00:00:00"
    assert validate_revocation_state_schema(bad_last_updated) == DRC["SCHEMA_VALIDATION_FAILURE"]

    bad_top_level_list = deepcopy(valid_revocation)
    bad_top_level_list["revoked_receipt_digests"] = None
    assert validate_revocation_state_schema(bad_top_level_list) == DRC["SCHEMA_VALIDATION_FAILURE"]

    bad_signed_type = deepcopy(valid_revocation)
    bad_signed_type["signed_revocation_list"] = []
    assert validate_revocation_state_schema(bad_signed_type) == DRC["SCHEMA_VALIDATION_FAILURE"]

    bad_body = deepcopy(valid_revocation)
    bad_body["signed_revocation_list"]["body"] = []
    assert validate_revocation_state_schema(bad_body) == DRC["SCHEMA_VALIDATION_FAILURE"]

    duplicate_entries = deepcopy(valid_revocation)
    duplicate_entries["signed_revocation_list"]["body"]["revoked_receipt_digests"] = ["x", "x"]
    assert validate_revocation_state_schema(duplicate_entries) == DRC["SCHEMA_VALIDATION_FAILURE"]

    unsafe_extra = deepcopy(valid_revocation)
    unsafe_extra["signed_revocation_list"]["extension"] = 1.5
    assert validate_revocation_state_schema(unsafe_extra) == DRC["SCHEMA_VALIDATION_FAILURE"]

    bad_merkle = deepcopy(valid_revocation)
    bad_merkle["merkle"] = []
    assert validate_revocation_state_schema(bad_merkle) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_verifier_success_and_defensive_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    request = base_request()

    # Matching required identity and a positive attestation exercise the success
    # sides of two non-waivable checks.
    identity_policy = base_policy()
    identity_policy["require_identity_binding"] = True
    identity_receipt = make_receipt(
        request,
        policy=identity_policy,
        nonce="identity-success",
        core_overrides={"identity_binding": {"workload": "agent-A"}},
    )
    identity_context = base_context()
    identity_context.update(
        {
            "identity_binding": {"workload": "agent-A"},
            "attestation_required": True,
            "attestation_present": True,
        }
    )
    result = verifier.verify_permit_receipt(
        request,
        identity_receipt,
        identity_policy,
        base_revocation(identity_receipt),
        identity_context,
    )
    assert result.decision == ALLOW

    # Provenance is profile-selectable; when not required, omission is valid.
    no_provenance_policy = base_policy()
    no_provenance_policy["require_permit_provenance"] = False
    no_provenance_receipt = make_receipt(
        request,
        policy=no_provenance_policy,
        nonce="provenance-optional",
        permit_provenance_digest=None,
    )
    assert (
        verifier.verify_permit_receipt(
            request,
            no_provenance_receipt,
            no_provenance_policy,
            base_revocation(no_provenance_receipt),
            base_context(),
        ).decision
        == ALLOW
    )

    # A scope with no budget constraint reaches the unconstrained budget branch.
    scope_without_budget = deepcopy(no_provenance_receipt["receipt_core"]["scope"])
    scope_without_budget.pop("max_effect_budget")
    assert verifier._scope_code(request, scope_without_budget) is None

    # Existing total timing values are preserved.
    assert verifier._finish_timings({"total_ns": 7}) == {"total_ns": 7}

    # A valid capability with no mutable state fails closed before reservation.
    policy = base_policy()
    policy["require_capability_token"] = True
    receipt = make_receipt(request, policy=policy, nonce="cap-no-state-receipt")
    capability = make_capability(request, receipt, policy, nonce="cap-no-state")
    code, replay = verifier._validate_capability_token(
        request,
        capability,
        policy,
        {"now": policy["now"]},
        {},
        verifier.parse_time(policy["now"]),
        expected_receipt_digest=digest_obj(receipt["receipt_core"]),
    )
    assert code == DRC["REPLAY_STATE_FAILURE"]
    assert replay is None

    # Explicit-now standalone verification reaches the cache-refusal path.
    direct_context = {
        **base_context(),
        "capability_replay_cache": _RejectingCache(),
        "expected_receipt_digest": digest_obj(receipt["receipt_core"]),
    }
    assert (
        verifier.verify_capability_token(
            request,
            capability,
            policy,
            direct_context,
            {},
            now=verifier.parse_time(policy["now"]),
        )
        == DRC["CAPABILITY_REPLAY"]
    )

    merkle_state = base_revocation(receipt, merkle=True)
    malformed_inclusion = deepcopy(merkle_state)
    malformed_inclusion["merkle"]["receipt_proof"] = {
        "proof_type": "inclusion",
        "entry": [],
    }
    monkeypatch.setattr(verifier, "verify_inclusion_proof", lambda *_args: True)
    assert (
        verifier._verify_merkle_revocation_proofs(
            malformed_inclusion,
            policy,
            {},
            {},
            verifier.parse_time(policy["now"]),
            digest_obj(receipt["receipt_core"]),
            receipt["receipt_core"]["issuer_id"],
        )
        == DRC["TRANSPARENCY_PROOF_INVALID"]
    )

    monkeypatch.setattr(
        verifier,
        "verify_signed_checkpoint",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("synthetic verifier fault")),
    )
    assert (
        verifier._verify_merkle_revocation_proofs(
            merkle_state,
            policy,
            {},
            {},
            verifier.parse_time(policy["now"]),
            digest_obj(receipt["receipt_core"]),
            receipt["receipt_core"]["issuer_id"],
        )
        == DRC["TRANSPARENCY_PROOF_INVALID"]
    )


def test_public_verifier_cache_reservation_refusal_is_deterministic() -> None:
    request = base_request()
    policy = base_policy()
    receipt = make_receipt(request, policy=policy, nonce="rejecting-receipt-cache")
    context = base_context()
    context["replay_cache"] = _RejectingCache()
    result = verifier.verify_permit_receipt(
        request,
        receipt,
        policy,
        base_revocation(receipt),
        context,
    )
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["ANTI_REPLAY_FAILURE"]


def test_retrieval_gateway_owns_replay_state_and_ignores_wire_claims() -> None:
    request = base_request()
    policy = base_policy()
    # Use a record that exists in the adapter after a valid verifier decision.
    request.update(
        {
            "effect_type": "DATA_ACCESS",
            "interface_id": "retrieval-gateway-1",
            "action_type": "READ",
            "target_id": "case-record-001",
            "max_effect_budget": 1,
        }
    )
    scope = {
        "effect_type": request["effect_type"],
        "interface_id": request["interface_id"],
        "action_type": request["action_type"],
        "target_id": request["target_id"],
        "tenant_id": request["tenant_id"],
        "purpose_id": request["purpose_id"],
        "representation_class_id": request["representation_class_id"],
        "max_effect_budget": 1,
    }
    receipt = make_receipt(request, policy=policy, scope=scope, nonce="http-owned-replay")
    envelope = {
        "request": request,
        "permit_receipt": receipt,
        "policy_state": policy,
        "revocation_state": base_revocation(receipt),
        "context": {**base_context(), "used_nonces": ["http-owned-replay"]},
    }
    adapter = RetrievalGatewayAdapter()
    first_status, first = adapter.handle_retrieve(envelope)
    second_status, second = adapter.handle_retrieve(envelope)
    assert first_status == 200
    assert first["decision"] == ALLOW
    assert second_status == 403
    assert second["denial_reason_code"] == DRC["ANTI_REPLAY_FAILURE"]

    malformed = deepcopy(envelope)
    malformed["context"] = []
    status, body = RetrievalGatewayAdapter().handle_retrieve(malformed)
    assert status == 400
    assert body["denial_reason_code"] == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_standalone_capability_impossible_success_without_replay_spec_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = base_request()
    policy = base_policy()
    receipt = make_receipt(request, policy=policy, nonce="cap-invariant-receipt")
    capability = make_capability(request, receipt, policy, nonce="cap-invariant-token")
    context = {
        **base_context(),
        "expected_receipt_digest": digest_obj(receipt["receipt_core"]),
    }
    monkeypatch.setattr(verifier, "_validate_capability_token", lambda *_args, **_kwargs: (None, None))
    assert (
        verifier.verify_capability_token(request, capability, policy, context, {})
        == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
    )


def test_permit_capability_impossible_success_without_replay_spec_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = base_request()
    policy = base_policy()
    policy["require_capability_token"] = True
    receipt = make_receipt(request, policy=policy, nonce="permit-cap-invariant-receipt")
    capability = make_capability(request, receipt, policy, nonce="permit-cap-invariant-token")
    context = {**base_context(), "capability_token": capability}
    monkeypatch.setattr(verifier, "_validate_capability_token", lambda *_args, **_kwargs: (None, None))
    result = verifier.verify_permit_receipt(
        request,
        receipt,
        policy,
        base_revocation(receipt),
        context,
    )
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]
