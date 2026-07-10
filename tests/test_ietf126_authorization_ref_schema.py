from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from ietf126 import run_review_packet as packet


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "ietf126" / "schemas" / "authorization_ref.public-eval.v2.schema.json"


def test_generated_authorization_ref_validates_canonical_schema():
    request = packet.base_request()
    policy = packet.base_policy()
    receipt = packet.make_receipt(request, policy, nonce="authref-schema")
    canonical = packet.canonicalize_request(request, packet.SUPPORTED_PROFILE)
    action_digest = packet.compute_action_digest(canonical)
    ref = packet.make_authorization_ref(receipt, action_digest)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(instance=ref, schema=schema)
    assert packet.crossref_decision(
        ref,
        expected_action_commitment=action_digest,
        supported_profile=packet.SUPPORTED_PROFILE,
    )["decision"] == "BOUND"

    profile_document = (ROOT / "ietf126" / "AUTHORIZATION_REF_PROFILE.md").read_text(encoding="utf-8")
    for name in {
        "ref_kind",
        "ref_artifact_digest",
        "issuer_or_signer",
        "action_commitment",
        "valid_until",
        "policy_epoch",
        "nonce_commitment",
        "verifier_behavior",
    }:
        assert f'"{name}"' in profile_document
    for legacy_name in {
        "reference_kind",
        "artifact_digest",
        "protected_action_commitment",
        "failure_behavior",
    }:
        assert f'"{legacy_name}"' not in profile_document


def test_authorization_ref_schema_rejects_old_conflicting_field_model():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    old = {
        "ref_profile": packet.AUTH_REF_PROFILE,
        "reference_kind": "PermitReceipt",
        "artifact_digest": "0" * 64,
        "issuer_id": "issuer",
        "protected_action_commitment": "0" * 64,
        "signature_coverage": True,
    }
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(old))
    assert errors


def test_generated_signed_authorization_ref_carrier_validates_and_authenticates():
    from referencing import Registry, Resource

    request = packet.base_request()
    policy = packet.base_policy()
    receipt = packet.make_receipt(request, policy, nonce="authref-carrier-schema")
    action_digest = packet.compute_action_digest(
        packet.canonicalize_request(request, packet.SUPPORTED_PROFILE)
    )
    ref = packet.make_authorization_ref(receipt, action_digest)
    carrier = packet.make_authorization_ref_carrier(ref)
    assert carrier is not None

    ref_schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    carrier_schema_path = ROOT / "ietf126" / "schemas" / "authorization_ref_carrier.public-eval.v1.schema.json"
    carrier_schema = json.loads(carrier_schema_path.read_text(encoding="utf-8"))
    registry = Registry().with_resource(ref_schema["$id"], Resource.from_contents(ref_schema))
    validator = jsonschema.Draft202012Validator(carrier_schema, registry=registry)
    assert not list(validator.iter_errors(carrier))

    observed = packet.crossref_carrier_decision(
        carrier,
        expected_action_commitment=action_digest,
        supported_profile=packet.SUPPORTED_PROFILE,
        trusted_issuers=policy["trusted_issuers"],
    )
    assert observed["decision"] == "BOUND"


def test_signed_authorization_ref_carrier_tamper_fails_closed():
    request = packet.base_request()
    policy = packet.base_policy()
    receipt = packet.make_receipt(request, policy, nonce="authref-carrier-tamper")
    action_digest = packet.compute_action_digest(
        packet.canonicalize_request(request, packet.SUPPORTED_PROFILE)
    )
    ref = packet.make_authorization_ref(receipt, action_digest)
    carrier = packet.make_authorization_ref_carrier(ref)
    assert carrier is not None
    carrier["carrier"]["authorization_ref"]["status"] = "revoked"
    observed = packet.crossref_carrier_decision(
        carrier,
        expected_action_commitment=action_digest,
        supported_profile=packet.SUPPORTED_PROFILE,
        trusted_issuers=policy["trusted_issuers"],
    )
    assert observed["decision"] == "DENY"
    assert observed["reason"] == "AUTHREF_CARRIER_SIGNATURE_INVALID"
