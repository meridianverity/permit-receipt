import pytest

from orprg_eval.merkle import (
    build_inclusion_proof,
    build_non_inclusion_proof,
    merkle_root,
    revocation_entry,
    verify_inclusion_proof,
    verify_non_inclusion_proof,
)


def _entries(*keys: str):
    return [revocation_entry("receipt", key) for key in keys]


def test_non_inclusion_requires_adjacent_neighbors():
    entries = _entries("a", "b", "c")
    root = merkle_root(entries)

    # This malicious proof tries to prove absence of receipt:b using non-adjacent
    # neighbors receipt:a and receipt:c. It must fail because receipt:b is present.
    forged = {
        "proof_type": "non_inclusion",
        "target_key": "receipt:b",
        "tree_size": len(entries),
        "prev": build_inclusion_proof(entries, "receipt:a"),
        "next": build_inclusion_proof(entries, "receipt:c"),
    }
    assert not verify_non_inclusion_proof(forged, root)


def test_non_inclusion_boundary_neighbor_must_be_tree_edge():
    entries = _entries("a", "c", "z")
    root = merkle_root(entries)

    forged_prev_only = {
        "proof_type": "non_inclusion",
        "target_key": "receipt:b",
        "tree_size": len(entries),
        "prev": build_inclusion_proof(entries, "receipt:a"),
    }
    assert not verify_non_inclusion_proof(forged_prev_only, root)

    forged_next_only = {
        "proof_type": "non_inclusion",
        "target_key": "receipt:y",
        "tree_size": len(entries),
        "next": build_inclusion_proof(entries, "receipt:z"),
    }
    assert not verify_non_inclusion_proof(forged_next_only, root)


def test_inclusion_leaf_index_tree_size_and_path_direction_are_bound():
    entries = _entries("a", "b", "c")
    root = merkle_root(entries)
    proof = build_inclusion_proof(entries, "receipt:b")

    tampered_index = dict(proof)
    tampered_index["leaf_index"] = 0
    assert not verify_inclusion_proof(tampered_index, root)

    tampered_size = dict(proof)
    tampered_size["tree_size"] = 4
    assert not verify_inclusion_proof(tampered_size, root)

    tampered_path = dict(proof)
    tampered_path["audit_path"] = [dict(step) for step in proof["audit_path"]]
    tampered_path["audit_path"][0]["direction"] = (
        "left" if tampered_path["audit_path"][0]["direction"] == "right" else "right"
    )
    assert not verify_inclusion_proof(tampered_path, root)


def test_merkle_entries_reject_duplicate_keys():
    duplicate_entries = [revocation_entry("receipt", "dup"), revocation_entry("receipt", "dup")]
    with pytest.raises(ValueError, match="duplicate Merkle entry key"):
        merkle_root(duplicate_entries)


def test_legitimate_non_inclusion_still_verifies():
    entries = _entries("a", "c", "z")
    root = merkle_root(entries)
    proof = build_non_inclusion_proof(entries, "receipt:b")
    assert verify_non_inclusion_proof(proof, root)
