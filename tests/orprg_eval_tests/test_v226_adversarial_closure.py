from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import runpy
import shutil

import pytest

from orprg_eval.crypto import sign_object
from orprg_eval.models import DENY, DRC
from orprg_eval.vector_factory import (
    ISSUER_KEY,
    base_context,
    base_policy,
    base_request,
    base_revocation,
    build_vectors,
    make_receipt,
)
from orprg_eval.verifier import verify_permit_receipt


def _resign(receipt: dict) -> dict:
    receipt = deepcopy(receipt)
    receipt["authenticity"]["signature"] = sign_object(
        ISSUER_KEY, receipt["receipt_core"]
    )
    return receipt


def _verify(receipt: dict, policy: dict | None = None, context: dict | None = None):
    request = base_request()
    selected_policy = policy or base_policy()
    return verify_permit_receipt(
        request,
        receipt,
        selected_policy,
        base_revocation(receipt),
        context or base_context(),
    )


def test_unknown_authority_profile_fails_closed() -> None:
    receipt = make_receipt(base_request(), nonce="v226-unknown-authority")
    receipt["receipt_core"]["authority_profile_id"] = "AP-UNKNOWN"
    result = _verify(_resign(receipt))
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["AUTHORITY_PROFILE_SELECTION_FAILED"]


def test_unknown_assurance_level_fails_closed() -> None:
    receipt = make_receipt(base_request(), nonce="v226-unknown-assurance")
    receipt["receipt_core"]["assurance_level_id"] = "AL-UNKNOWN"
    result = _verify(_resign(receipt))
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["ASSURANCE_PROFILE_NOT_SATISFIED"]


def test_untrusted_well_formed_provenance_digest_fails_closed() -> None:
    receipt = make_receipt(base_request(), nonce="v226-untrusted-provenance")
    receipt["receipt_core"]["permit_provenance_digest"] = "sha256:" + "0" * 64
    result = _verify(_resign(receipt))
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["PERMIT_PROVENANCE_INVALID_OR_MISSING"]


def test_required_identity_binding_cannot_be_absent_on_both_sides() -> None:
    policy = base_policy()
    policy["require_identity_binding"] = True
    receipt = make_receipt(
        base_request(), policy=policy, nonce="v226-required-identity-absent"
    )
    result = _verify(receipt, policy=policy, context=base_context())
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["IDENTITY_BINDING_MISMATCH"]


def test_required_attestation_cannot_be_omitted() -> None:
    context = base_context()
    context["attestation_required"] = True
    receipt = make_receipt(base_request(), nonce="v226-required-attestation-absent")
    result = _verify(receipt, context=context)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["ATTESTATION_FAILURE"]


def test_transparency_anchor_is_not_a_substitute_for_verified_proof() -> None:
    policy = base_policy()
    policy["require_transparency"] = True
    receipt = make_receipt(
        base_request(),
        policy=policy,
        nonce="v226-marker-only-transparency",
        extras={"transparency_anchor_digest": "sha256:" + "1" * 64},
    )
    result = _verify(receipt, policy=policy)
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["TRANSPARENCY_PROOF_MISSING"]


def test_vector_runner_exits_nonzero_when_any_vector_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import orprg_eval.vector_factory as vector_factory

    vector = deepcopy(build_vectors()[0])
    vector["expected"] = {
        "decision": "DENY" if vector["expected"]["decision"] == "ALLOW" else "ALLOW",
        "denial_reason_code": "DRC-TEST-IMPOSSIBLE",
    }
    monkeypatch.setattr(vector_factory, "build_vectors", lambda: [vector])

    copied_runner = tmp_path / "run_vectors.py"
    shutil.copyfile(Path(__file__).resolve().parents[2] / "run_vectors.py", copied_runner)
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(copied_runner), run_name="__main__")
    assert exc_info.value.code == 1


def test_default_json_replay_state_commits_only_on_allow_and_blocks_reuse() -> None:
    request = base_request()
    policy = base_policy()
    receipt = make_receipt(request, policy=policy, nonce="v226-list-state-replay")
    context = base_context()
    revocation = base_revocation(receipt)

    first = verify_permit_receipt(request, receipt, policy, revocation, context)
    second = verify_permit_receipt(request, receipt, policy, revocation, context)

    assert first.decision == "ALLOW"
    assert context["used_nonces"] == ["v226-list-state-replay"]
    assert second.decision == DENY
    assert second.denial_reason_code == DRC["ANTI_REPLAY_FAILURE"]


def test_missing_replay_state_fails_closed() -> None:
    request = base_request()
    receipt = make_receipt(request, nonce="v226-no-replay-state")
    context = base_context()
    del context["used_nonces"]

    result = verify_permit_receipt(
        request, receipt, base_policy(), base_revocation(receipt), context
    )
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["REPLAY_STATE_FAILURE"]


