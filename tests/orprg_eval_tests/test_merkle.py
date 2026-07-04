from orprg_eval.merkle import revocation_entry, merkle_root, build_inclusion_proof, verify_inclusion_proof, build_non_inclusion_proof, verify_non_inclusion_proof


def test_merkle_inclusion_and_non_inclusion():
    entries = [revocation_entry("receipt", "b"), revocation_entry("receipt", "d"), revocation_entry("issuer", "z")]
    root = merkle_root(entries)
    proof = build_inclusion_proof(entries, "receipt:b")
    assert verify_inclusion_proof(proof, root)
    absence = build_non_inclusion_proof(entries, "receipt:c")
    assert verify_non_inclusion_proof(absence, root)
    absence_bad = dict(absence)
    absence_bad["target_key"] = "receipt:a"
    assert not verify_non_inclusion_proof(absence_bad, root)
