from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from orprg_eval.schema import (
    validate_capability_schema,
    validate_receipt_schema,
    validate_revocation_state_schema,
)
from orprg_eval.vector_factory import (
    base_policy,
    base_request,
    base_revocation,
    make_capability,
    make_receipt,
)

ROOT = Path(__file__).resolve().parents[2]


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _is_valid(validator: Draft202012Validator, value: object) -> bool:
    return not list(validator.iter_errors(value))


def test_generated_objects_validate_under_published_schemas() -> None:
    receipt = make_receipt()
    capability = make_capability(base_request(), receipt, base_policy())
    revocation = base_revocation(receipt)
    assert _is_valid(_validator("permit_receipt.schema.json"), receipt)
    assert _is_valid(_validator("capability_token.schema.json"), capability)
    assert _is_valid(_validator("revocation_state.schema.json"), revocation)


def test_receipt_schema_and_runtime_reject_same_security_critical_mutations() -> None:
    validator = _validator("permit_receipt.schema.json")
    receipt = make_receipt()
    mutations = []
    for nonce in (None, "", 7, True, [], {}):
        value = deepcopy(receipt)
        value["receipt_core"]["anti_replay"]["nonce"] = nonce
        mutations.append(value)
    value = deepcopy(receipt)
    value["receipt_core"]["valid_from"] = "2026-06-02T00:00:00"
    mutations.append(value)
    value = deepcopy(receipt)
    value["receipt_core"]["valid_from"] = "2026-06-02T00:00:00-00:00"
    mutations.append(value)
    value = deepcopy(receipt)
    value["receipt_core"]["identity_binding"] = {"score": 1.5}
    mutations.append(value)
    value = deepcopy(receipt)
    value["receipt_core"]["epoch_id"] = True
    mutations.append(value)
    value = deepcopy(receipt)
    value["receipt_core"]["scope"]["ignored_constraint"] = "must-not-be-ignored"
    mutations.append(value)
    value = deepcopy(receipt)
    value["receipt_core"]["action_digest"] = "not-a-digest"
    mutations.append(value)
    for candidate in mutations:
        assert validate_receipt_schema(candidate) is not None
        assert not _is_valid(validator, candidate)


def test_capability_schema_and_runtime_reject_same_security_critical_mutations() -> None:
    validator = _validator("capability_token.schema.json")
    receipt = make_receipt()
    capability = make_capability(base_request(), receipt, base_policy())
    mutations = []
    for nonce in (None, "", 7, True, [], {}):
        value = deepcopy(capability)
        value["token_core"]["nonce"] = nonce
        mutations.append(value)
    value = deepcopy(capability)
    value["token_core"]["valid_to"] = "2026-06-04 00:00:00Z"
    mutations.append(value)
    value = deepcopy(capability)
    value["token_core"]["valid_to"] = "2026-06-04T00:00:00-00:00"
    mutations.append(value)
    value = deepcopy(capability)
    value["token_core"]["receipt_digest"] = "00"
    mutations.append(value)
    value = deepcopy(capability)
    value["token_core"]["unexpected"] = "ignored"
    mutations.append(value)
    for candidate in mutations:
        assert validate_capability_schema(candidate) is not None
        assert not _is_valid(validator, candidate)


def test_revocation_schema_and_runtime_reject_same_security_critical_mutations() -> None:
    validator = _validator("revocation_state.schema.json")
    receipt = make_receipt()
    revocation = base_revocation(receipt)
    mutations = []
    for status in ("unsupported", 1, True, None):
        value = deepcopy(revocation)
        value["status"] = status
        mutations.append(value)
    value = deepcopy(revocation)
    value["signed_revocation_list"]["body"]["issued_at"] = "2026-06-02T23:59:40"
    mutations.append(value)
    value = deepcopy(revocation)
    value["signed_revocation_list"]["body"]["sequence"] = True
    mutations.append(value)
    value = deepcopy(revocation)
    value["signed_revocation_list"]["body"]["revoked_receipt_digests"] = ["not-a-sha256"]
    mutations.append(value)
    value = deepcopy(revocation)
    value["signed_revocation_list"]["body"]["ignored"] = "ignored"
    mutations.append(value)
    for candidate in mutations:
        assert validate_revocation_state_schema(candidate) is not None
        assert not _is_valid(validator, candidate)


def test_orprg_ref_alias_is_semantically_locked_to_canonical_schema() -> None:
    canonical = json.loads((ROOT / "schemas" / "permit_receipt.schema.json").read_text(encoding="utf-8"))
    alias = json.loads((ROOT / "schemas_orprg_ref" / "permit_receipt.schema.json").read_text(encoding="utf-8"))
    assert canonical["$id"] != alias["$id"]
    assert alias["x-compatibility-alias-of"] == canonical["$id"]
    for document in (canonical, alias):
        document.pop("$id", None)
        document.pop("title", None)
        document.pop("description", None)
        document.pop("x-compatibility-alias-of", None)
    assert alias == canonical
