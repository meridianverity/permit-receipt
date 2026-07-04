from orprg_eval.vector_factory import build_vectors
from orprg_eval.verifier import verify_permit_receipt


def test_all_evaluation_vectors_pass():
    failures = []
    for v in build_vectors():
        res = verify_permit_receipt(v["request"], v["permit_receipt"], v["policy_state"], v["revocation_state"], v["context"])
        if res.decision != v["expected"]["decision"] or res.denial_reason_code != v["expected"].get("denial_reason_code"):
            failures.append((v["vector_id"], v["expected"], res.to_dict()))
    assert not failures
