"""Targeted malformed-profile cases for strict-schema branch closure."""
from __future__ import annotations

from copy import deepcopy

import pytest

import orprg_eval.schema as schema
from orprg_eval.models import DRC
from orprg_eval.vector_factory import (
    base_context,
    base_policy,
    base_request,
    base_revocation,
    make_capability,
    make_receipt,
)


def test_string_collection_limit_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schema, "MAX_LIST_ITEMS", 0)
    context = base_context()
    context["used_nonces"] = ["nonce"]
    assert schema.validate_context_schema(context) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_request_noncanonical_float_fails_shape() -> None:
    request = base_request()
    request["max_effect_budget"] = 1.5
    assert schema.validate_request_schema(request) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_key_release_requires_key_fields() -> None:
    request = base_request()
    request["effect_type"] = "KEY_RELEASE"
    assert schema.validate_request_schema(request) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_scope_string_constraint_must_be_nonempty() -> None:
    receipt = make_receipt(nonce="schema-empty-scope-string")
    receipt["receipt_core"]["scope"]["effect_type"] = ""
    assert schema.validate_receipt_schema(receipt) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_receipt_nonmapping_is_malformed() -> None:
    assert schema.validate_receipt_schema([]) == DRC["RECEIPT_MALFORMED"]


def test_receipt_noncanonical_extension_fails_shape() -> None:
    receipt = make_receipt(nonce="schema-receipt-float")
    receipt["receipt_core"]["identity_binding"] = {"score": 1.5}
    assert schema.validate_receipt_schema(receipt) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_capability_noncanonical_value_fails_shape() -> None:
    request = base_request()
    policy = base_policy()
    receipt = make_receipt(request, policy=policy, nonce="schema-cap-receipt")
    token = make_capability(request, receipt, policy, nonce="schema-cap-nonce")
    token["token_core"]["tenant_id"] = 1.5
    assert schema.validate_capability_schema(token) == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]


def test_policy_nonmapping_fails_shape() -> None:
    assert schema.validate_policy_state_schema(None) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_optional_policy_maps_and_offline_list_may_be_absent() -> None:
    policy = base_policy()
    for field in (
        "revocation_authorities",
        "transparency_logs",
        "trusted_capability_issuers",
        "offline_constrained_effect_types",
    ):
        policy.pop(field)
    assert schema.validate_policy_state_schema(policy) is None


def test_signed_revocation_list_rejects_noncanonical_surrogate() -> None:
    receipt = make_receipt(nonce="schema-revocation-surrogate")
    state = deepcopy(base_revocation(receipt))
    state["signed_revocation_list"]["body"]["revoked_receipt_digests"] = ["\ud800"]
    assert schema.validate_revocation_state_schema(state) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_receipt_rejects_nonprefixed_provenance_digest() -> None:
    receipt = make_receipt(nonce="schema-provenance-format")
    receipt["receipt_core"]["permit_provenance_digest"] = "not-a-prefixed-digest"
    assert schema.validate_receipt_schema(receipt) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_policy_rejects_invalid_trust_lists_and_provenance_format() -> None:
    policy = base_policy()
    policy["trusted_authority_profile_ids"] = "not-a-list"
    assert schema.validate_policy_state_schema(policy) == DRC["SCHEMA_VALIDATION_FAILURE"]

    policy = base_policy()
    policy["trusted_permit_provenance_digests"] = ["not-a-prefixed-digest"]
    assert schema.validate_policy_state_schema(policy) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_revocation_rejects_invalid_top_level_time_and_lists() -> None:
    state = {"status": "fresh", "last_updated": "not-a-time"}
    assert schema.validate_revocation_state_schema(state) == DRC["SCHEMA_VALIDATION_FAILURE"]

    state = {"status": "fresh", "revoked_issuers": "not-a-list"}
    assert schema.validate_revocation_state_schema(state) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_revocation_rejects_malformed_signed_envelope_shapes() -> None:
    assert schema.validate_revocation_state_schema(
        {"status": "fresh", "signed_revocation_list": []}
    ) == DRC["SCHEMA_VALIDATION_FAILURE"]
    assert schema.validate_revocation_state_schema(
        {"status": "fresh", "signed_revocation_list": {"body": [], "authenticity": {}}}
    ) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_revocation_rejects_duplicate_signed_entries_and_nonjson_signature() -> None:
    receipt = make_receipt(nonce="schema-revocation-duplicates")
    state = deepcopy(base_revocation(receipt))
    state["signed_revocation_list"]["body"]["revoked_issuers"] = ["issuer-X", "issuer-X"]
    assert schema.validate_revocation_state_schema(state) == DRC["SCHEMA_VALIDATION_FAILURE"]

    state = deepcopy(base_revocation(receipt))
    state["signed_revocation_list"]["authenticity"]["signature"] = "\ud800"
    assert schema.validate_revocation_state_schema(state) == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_revocation_rejects_nonmapping_merkle_evidence() -> None:
    assert schema.validate_revocation_state_schema(
        {"status": "fresh", "merkle": []}
    ) == DRC["SCHEMA_VALIDATION_FAILURE"]
