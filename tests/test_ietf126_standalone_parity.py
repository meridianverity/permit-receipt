from __future__ import annotations

from ietf126 import run_review_packet as packet


def test_standalone_transparency_missing_code_matches_full_registry() -> None:
    vectors = packet.build_selected_vectors_standalone()
    target = next(v for v in vectors if v["vector_id"] == "KNEG-TRANSPARENCY-PROOF-MISSING")
    observed = packet.verify_standalone(
        target["request"],
        target["permit_receipt"],
        target["policy_state"],
        target["revocation_state"],
        target["context"],
    )
    assert target["expected"]["denial_reason_code"] == "DRC-053_TRANSPARENCY_PROOF_MISSING"
    assert observed["denial_reason_code"] == target["expected"]["denial_reason_code"]


def test_standalone_selected_vectors_have_modern_drc_codes() -> None:
    expected_by_vector = {
        "KNEG-MISSING-RECEIPT": "DRC-000-MISSING_RECEIPT",
        "KNEG-ACTION-DIGEST-MISMATCH": "DRC-009_ACTION_DIGEST_MISMATCH",
        "KNEG-SCOPE-VIOLATION-TARGET": "DRC-005_SCOPE_VIOLATION",
        "KNEG-SCOPE-VIOLATION-BUDGET-OMITTED": "DRC-005_SCOPE_VIOLATION",
        "KNEG-VALIDITY-EXPIRED": "DRC-004_VALIDITY_WINDOW_EXPIRED",
        "KNEG-REVOCATION-STATE-STALE": "DRC-008_REVOCATION_UNKNOWN_OR_STALE",
        "KNEG-ANTI-REPLAY-NONCE-REUSE": "DRC-006_ANTI_REPLAY_FAILURE",
        "KNEG-CANONICALIZATION-PROFILE-MISMATCH": "DRC-016_CANONICALIZATION_PROFILE_MISMATCH",
        "KNEG-TRANSPARENCY-PROOF-MISSING": "DRC-053_TRANSPARENCY_PROOF_MISSING",
    }
    vectors = packet.build_selected_vectors_standalone()
    assert {v["vector_id"] for v in vectors} == set(expected_by_vector)
    for vector in vectors:
        assert vector["expected"]["denial_reason_code"] == expected_by_vector[vector["vector_id"]]

def test_standalone_scope_constrained_optional_field_cannot_be_omitted_by_request() -> None:
    request = packet.base_request_standalone()
    request.pop("max_effect_budget", None)
    scope = packet.base_scope_standalone()
    receipt = packet.make_receipt_standalone(request, scope=scope, nonce="scope-budget-omitted")

    observed = packet.verify_standalone(
        request,
        receipt,
        packet.base_policy_standalone(),
        packet.base_revocation_standalone(receipt),
        packet.base_context_standalone(),
    )
    assert observed["decision"] == "DENY"
    assert observed["denial_reason_code"] == "DRC-005_SCOPE_VIOLATION"
