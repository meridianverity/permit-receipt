from __future__ import annotations

import sqlite3
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

import orprg_eval.merkle as merkle
import orprg_eval.timeutil as timeutil
import orprg_eval.verifier as verifier
from orprg_eval.canonicalization import digest_obj
from orprg_eval.crypto import deterministic_private_key, public_key_b64
from orprg_eval.models import ALLOW, DENY, DRC
from orprg_eval.persistent_replay import SQLiteReplayCache
from orprg_eval.vector_factory import (
    ISSUER_ID,
    LOG_ID,
    base_context,
    base_policy,
    base_request,
    base_revocation,
    base_scope,
    make_receipt,
    make_revocation_state,
    add_merkle_proofs,
)


def _entries() -> list[dict]:
    return [
        merkle.revocation_entry("receipt", "a"),
        merkle.revocation_entry("receipt", "c"),
        merkle.revocation_entry("receipt", "e"),
    ]


def test_merkle_primitives_empty_tree_sorting_and_input_errors() -> None:
    assert merkle.merkle_root([]) == merkle.EMPTY_ROOT
    assert merkle._levels([]) == [[merkle.EMPTY_TREE_HASH]]
    with pytest.raises(ValueError, match="non-negative"):
        merkle._size_bound_root(-1, merkle.EMPTY_TREE_HASH)
    with pytest.raises(ValueError, match="require a key"):
        merkle.merkle_root([{"identifier": "x"}])
    with pytest.raises(ValueError, match="duplicate"):
        merkle.merkle_root([{"key": "x"}, {"key": "x"}])
    with pytest.raises(KeyError):
        merkle.build_inclusion_proof(_entries(), "receipt:missing")
    with pytest.raises(ValueError, match="positive"):
        merkle._expected_audit_directions(0, 0)
    with pytest.raises(ValueError, match="outside"):
        merkle._expected_audit_directions(3, 3)


def test_merkle_inclusion_proof_happy_and_failure_matrix() -> None:
    entries = _entries()
    root = merkle.merkle_root(entries)
    proof = merkle.build_inclusion_proof(entries, "receipt:c")
    assert merkle.verify_inclusion_proof(proof, root)

    variants = []
    bad = deepcopy(proof); bad["proof_type"] = "non_inclusion"; variants.append(bad)
    bad = deepcopy(proof); bad["tree_size"] = 0; variants.append(bad)
    bad = deepcopy(proof); bad["leaf_index"] = 99; variants.append(bad)
    bad = deepcopy(proof); bad["audit_path"] = {}; variants.append(bad)
    bad = deepcopy(proof); bad["audit_path"] = []; variants.append(bad)
    bad = deepcopy(proof); bad["audit_path"][0]["direction"] = "left" if bad["audit_path"][0]["direction"] == "right" else "right"; variants.append(bad)
    bad = deepcopy(proof); bad["audit_path"][0]["hash"] = "00" * 32; variants.append(bad)
    bad = deepcopy(proof); del bad["entry"]; variants.append(bad)
    for variant in variants:
        assert not merkle.verify_inclusion_proof(variant, root)


def test_merkle_non_inclusion_happy_paths_and_boundary_failures() -> None:
    entries = _entries()
    root = merkle.merkle_root(entries)
    for target in ("receipt:0", "receipt:b", "receipt:d", "receipt:z"):
        proof = merkle.build_non_inclusion_proof(entries, target)
        assert merkle.verify_non_inclusion_proof(proof, root)

    empty = merkle.build_non_inclusion_proof([], "receipt:x")
    assert merkle.verify_non_inclusion_proof(empty, merkle.EMPTY_ROOT)
    assert not merkle.verify_non_inclusion_proof(empty, root)
    with pytest.raises(ValueError, match="included"):
        merkle.build_non_inclusion_proof(entries, "receipt:a")

    base = merkle.build_non_inclusion_proof(entries, "receipt:b")
    variants = []
    bad = deepcopy(base); bad["proof_type"] = "inclusion"; variants.append(bad)
    bad = deepcopy(base); bad["tree_size"] = -1; variants.append(bad)
    bad = deepcopy(base); bad.pop("prev"); bad.pop("next"); variants.append(bad)
    bad = deepcopy(base); bad["prev"]["audit_path"][0]["hash"] = "00" * 32; variants.append(bad)
    bad = deepcopy(base); bad["prev"]["tree_size"] += 1; variants.append(bad)
    bad = deepcopy(base); bad["prev"]["entry"]["key"] = "receipt:z"; variants.append(bad)
    bad = deepcopy(base); bad["next"]["audit_path"][0]["hash"] = "00" * 32; variants.append(bad)
    bad = deepcopy(base); bad["next"]["tree_size"] += 1; variants.append(bad)
    bad = deepcopy(base); bad["next"]["entry"]["key"] = "receipt:0"; variants.append(bad)
    bad = deepcopy(base); bad["prev"], bad["next"] = bad["next"], bad["prev"]; variants.append(bad)
    bad = deepcopy(base); bad["next"]["leaf_index"] = 2; variants.append(bad)
    bad = deepcopy(base); del bad["target_key"]; variants.append(bad)
    for variant in variants:
        assert not merkle.verify_non_inclusion_proof(variant, root)

    only_prev = merkle.build_non_inclusion_proof(entries, "receipt:z")
    only_prev["prev"]["leaf_index"] = 1
    assert not merkle.verify_non_inclusion_proof(only_prev, root)
    only_next = merkle.build_non_inclusion_proof(entries, "receipt:0")
    only_next["next"]["leaf_index"] = 1
    assert not merkle.verify_non_inclusion_proof(only_next, root)


def test_signed_checkpoint_valid_invalid_and_malformed() -> None:
    key = deterministic_private_key("merkle-checkpoint-unit")
    public = public_key_b64(key)
    signed = merkle.sign_checkpoint(
        key,
        log_id="log",
        sequence=1,
        issued_at="2026-06-03T00:00:00Z",
        entries=_entries(),
    )
    assert merkle.verify_signed_checkpoint(signed, public)
    tampered = deepcopy(signed)
    tampered["checkpoint"]["sequence"] = 2
    assert not merkle.verify_signed_checkpoint(tampered, public)
    assert not merkle.verify_signed_checkpoint({}, public)


def _merkle_helper(state: dict, receipt: dict, policy: dict | None = None) -> str | None:
    return verifier._verify_merkle_revocation_proofs(
        state,
        policy or base_policy(),
        {},
        {},
        datetime(2026, 6, 3, tzinfo=timezone.utc),
        digest_obj(receipt["receipt_core"]),
        ISSUER_ID,
    )


def test_verifier_merkle_helper_denial_matrix_and_revoked_inclusion() -> None:
    receipt = make_receipt(nonce="merkle-helper")
    valid = add_merkle_proofs(make_revocation_state(), receipt)
    assert _merkle_helper(valid, receipt) is None

    missing = deepcopy(valid); missing.pop("merkle")
    assert _merkle_helper(missing, receipt) == DRC["TRANSPARENCY_PROOF_MISSING"]
    missing = deepcopy(valid); missing["merkle"].pop("signed_checkpoint")
    assert _merkle_helper(missing, receipt) == DRC["TRANSPARENCY_PROOF_MISSING"]
    missing = deepcopy(valid); missing["merkle"]["signed_checkpoint"].pop("checkpoint")
    assert _merkle_helper(missing, receipt) == DRC["SIGNED_CHECKPOINT_INVALID"]

    untrusted = base_policy(); untrusted["transparency_logs"] = {}
    assert _merkle_helper(valid, receipt, untrusted) == DRC["SIGNED_CHECKPOINT_INVALID"]

    stale = add_merkle_proofs(make_revocation_state(), receipt, checkpoint_at="2026-06-01T00:00:00Z")
    assert _merkle_helper(stale, receipt) == DRC["REVOCATION_UNKNOWN_OR_STALE"]

    missing_proof = deepcopy(valid); missing_proof["merkle"].pop("receipt_proof")
    assert _merkle_helper(missing_proof, receipt) == DRC["MERKLE_INCLUSION_REQUIRED_BUT_MISSING"]

    target_mismatch = deepcopy(valid)
    target_mismatch["merkle"]["receipt_proof"]["target_key"] = "receipt:wrong"
    assert _merkle_helper(target_mismatch, receipt) == DRC["NON_INCLUSION_PROOF_INVALID"]

    bad_noninclusion = deepcopy(valid)
    bad_noninclusion["merkle"]["receipt_proof"]["tree_size"] = -1
    assert _merkle_helper(bad_noninclusion, receipt) == DRC["NON_INCLUSION_PROOF_INVALID"]

    unknown = deepcopy(valid)
    unknown["merkle"]["receipt_proof"]["proof_type"] = "unknown"
    assert _merkle_helper(unknown, receipt) == DRC["TRANSPARENCY_PROOF_INVALID"]

    malformed = deepcopy(valid)
    malformed["merkle"]["signed_checkpoint"]["checkpoint"]["issued_at"] = object()
    assert _merkle_helper(malformed, receipt) == DRC["SIGNED_CHECKPOINT_INVALID"]

    revoked_state = make_revocation_state(
        revoked_receipts=[digest_obj(receipt["receipt_core"])],
        revoked_issuers=[ISSUER_ID],
    )
    revoked_state = add_merkle_proofs(revoked_state, receipt)
    assert _merkle_helper(revoked_state, receipt) == DRC["REVOKED_CONFIRMED"]

    # A valid inclusion proof for the wrong target is not evidence of revocation.
    wrong_entry = deepcopy(revoked_state)
    wrong_entry["merkle"]["receipt_proof"] = wrong_entry["merkle"]["issuer_proof"]
    assert _merkle_helper(wrong_entry, receipt) == DRC["TRANSPARENCY_PROOF_INVALID"]

    invalid_inclusion = deepcopy(revoked_state)
    invalid_inclusion["merkle"]["receipt_proof"]["audit_path"] = [{"direction": "right", "hash": "00" * 32}]
    assert _merkle_helper(invalid_inclusion, receipt) == DRC["TRANSPARENCY_PROOF_INVALID"]


def test_time_parser_defensively_rejects_unexpected_naive_platform_result(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeDateTime:
        @staticmethod
        def fromisoformat(value: str) -> datetime:
            return datetime(2026, 6, 3, 0, 0, 0)  # deliberately naive

    monkeypatch.setattr(timeutil, "datetime", FakeDateTime)
    with pytest.raises(timeutil.TimeFormatError, match="timezone-naive"):
        timeutil.parse_rfc3339("2026-06-03T00:00:00Z")


class _FailingConnection:
    def __init__(self, path: str, needle: str) -> None:
        self._db = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.needle = needle
        self.triggered = False

    @property
    def in_transaction(self) -> bool:
        return self._db.in_transaction

    def execute(self, sql: str, *args):
        if self.needle in sql and not self.triggered:
            self.triggered = True
            raise sqlite3.OperationalError(f"fault injected at {self.needle}")
        return self._db.execute(sql, *args)

    def close(self) -> None:
        self._db.close()


def test_sqlite_replay_rolls_back_reserve_commit_and_release_faults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "faults.sqlite3"
    cache = SQLiteReplayCache(path)
    real_connect = cache._connect

    monkeypatch.setattr(cache, "_connect", lambda: _FailingConnection(str(path), "INSERT INTO"))
    with pytest.raises(sqlite3.OperationalError):
        cache.reserve("d", "reserve-fault")
    monkeypatch.setattr(cache, "_connect", real_connect)
    assert not cache.contains("d", "reserve-fault")

    reservation = cache.reserve("d", "commit-fault")
    assert reservation is not None
    monkeypatch.setattr(cache, "_connect", lambda: _FailingConnection(str(path), "UPDATE used_nonces"))
    with pytest.raises(sqlite3.OperationalError):
        reservation.commit()
    monkeypatch.setattr(cache, "_connect", real_connect)
    # The failed transaction remains an uncommitted reservation and can be
    # explicitly released with a matching token.
    cache._release("d", "commit-fault", reservation.token)
    assert not cache.contains("d", "commit-fault")

    reservation = cache.reserve("d", "release-fault")
    assert reservation is not None
    monkeypatch.setattr(cache, "_connect", lambda: _FailingConnection(str(path), "DELETE FROM"))
    with pytest.raises(sqlite3.OperationalError):
        reservation.release()
    monkeypatch.setattr(cache, "_connect", real_connect)
    cache._release("d", "release-fault", reservation.token)
    assert not cache.contains("d", "release-fault")


def _verify(receipt: dict, *, request=None, policy=None, context=None, revocation=None):
    return verifier.verify_permit_receipt(
        request or base_request(),
        receipt,
        policy or base_policy(),
        revocation or base_revocation(receipt),
        context or base_context(),
    )


def test_verifier_remaining_scope_and_entrypoint_branches() -> None:
    request = base_request()
    receipt = make_receipt(request, nonce="tenant-scope-branch")
    receipt["receipt_core"]["scope"]["tenant_id"] = "tenant-B"
    receipt = verifier.issue_receipt(receipt["receipt_core"], __import__("orprg_eval.vector_factory", fromlist=["ISSUER_KEY"]).ISSUER_KEY)
    assert _verify(receipt, request=request).denial_reason_code == DRC["TENANT_MISMATCH"]

    receipt = make_receipt(request, nonce="purpose-scope-branch")
    receipt["receipt_core"]["scope"]["purpose_id"] = "other"
    receipt = verifier.issue_receipt(receipt["receipt_core"], __import__("orprg_eval.vector_factory", fromlist=["ISSUER_KEY"]).ISSUER_KEY)
    assert _verify(receipt, request=request).denial_reason_code == DRC["PURPOSE_OUT_OF_SCOPE_OR_MISSING"]

    request_no_budget = base_request(); request_no_budget.pop("max_effect_budget")
    receipt = make_receipt(request_no_budget, scope=base_scope(), nonce="budget-missing-branch")
    assert _verify(receipt, request=request_no_budget).denial_reason_code == DRC["SCOPE_VIOLATION"]

    assert verifier.verify_permit_receipt([], None, base_policy(), {}, {}).denial_reason_code == DRC["SCHEMA_VALIDATION_FAILURE"]  # type: ignore[arg-type]
    assert verifier.verify_permit_receipt({}, None, {}, {}, {}).denial_reason_code == DRC["SCHEMA_VALIDATION_FAILURE"]


def test_standalone_capability_no_cache_commit_failure_and_exception() -> None:
    from orprg_eval.vector_factory import make_capability

    request = base_request()
    policy = base_policy(); policy["require_capability_token"] = True
    receipt = make_receipt(request, policy=policy, nonce="standalone-extra-receipt")
    token = make_capability(request, receipt, policy, nonce="standalone-extra-cap")
    context = base_context(); context["expected_receipt_digest"] = digest_obj(receipt["receipt_core"])
    assert verifier.verify_capability_token(request, token, policy, context, {}) is None

    class FalseReservation:
        def commit(self): return False
        def release(self): pass
    class FalseCache:
        def reserve(self, domain, nonce): return FalseReservation()
        def contains(self, domain, nonce): return False
    context = base_context(); context["expected_receipt_digest"] = digest_obj(receipt["receipt_core"])
    context["capability_replay_cache"] = FalseCache()
    assert verifier.verify_capability_token(request, token, policy, context, {}) == DRC["CAPABILITY_REPLAY"]

    class ExplodingCache:
        def reserve(self, domain, nonce): raise RuntimeError("boom")
        def contains(self, domain, nonce): return False
    context = base_context(); context["expected_receipt_digest"] = digest_obj(receipt["receipt_core"])
    context["capability_replay_cache"] = ExplodingCache()
    assert verifier.verify_capability_token(request, token, policy, context, {}) == DRC["CAPABILITY_TOKEN_INVALID_OR_MISSING"]

    bad_profile = deepcopy(policy); bad_profile["canonicalization_profile_ref"] = "CP-UNSUPPORTED"
    assert verifier.verify_capability_token(request, token, bad_profile, context, {}) == DRC["CANONICALIZATION_PROFILE_MISMATCH"]


def test_attestation_nonce_mismatch_branch() -> None:
    receipt = make_receipt(nonce="attestation-nonce-branch")
    context = base_context()
    context.update({"attestation_required": True, "attestation_present": True, "attestation_nonce_mismatch": True})
    assert _verify(receipt, context=context).denial_reason_code == DRC["ATTESTATION_STALE"]


def test_merkle_non_inclusion_rejects_target_that_overtakes_valid_next_neighbor() -> None:
    entries = _entries()
    root = merkle.merkle_root(entries)
    proof = merkle.build_non_inclusion_proof(entries, "receipt:b")
    # Keep both inclusion proofs cryptographically valid, but move the claimed
    # absent target beyond the authenticated next neighbor.
    proof["target_key"] = "receipt:z"
    assert not merkle.verify_non_inclusion_proof(proof, root)


class _BeginFailConnection:
    """Connection-shaped fault that fails before a SQLite transaction starts."""

    in_transaction = False

    def execute(self, sql: str, *args):
        raise sqlite3.OperationalError("fault injected before transaction")

    def close(self) -> None:
        return None


def test_sqlite_replay_error_paths_without_active_transaction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = SQLiteReplayCache(tmp_path / "begin-faults.sqlite3")
    monkeypatch.setattr(cache, "_connect", lambda: _BeginFailConnection())

    with pytest.raises(sqlite3.OperationalError):
        cache.reserve("d", "reserve-before-begin")
    with pytest.raises(sqlite3.OperationalError):
        cache._commit("d", "commit-before-begin", "token")
    with pytest.raises(sqlite3.OperationalError):
        cache._release("d", "release-before-begin", "token")
