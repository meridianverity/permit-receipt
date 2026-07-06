from orprg_eval.models import DENY, DRC
from orprg_eval.vector_factory import base_context, base_policy, base_request, base_revocation, base_scope, make_receipt
from orprg_eval.verifier import verify_permit_receipt


def test_scope_constrained_optional_field_cannot_be_omitted_by_request():
    request = base_request()
    scope = {
        "effect_type": "DATA_EGRESS",
        "interface_id": "egress-gateway-1",
        "action_type": "POST",
        "target_id": "partner-api-submit",
        "tenant_id": "tenant-A",
        "purpose_id": "support",
        "representation_class_id": "json-v1",
        "artifact_id": "artifact:approved",
        "max_effect_budget": 10,
    }
    receipt = make_receipt(request, scope=scope, nonce="scope-artifact-required")

    result = verify_permit_receipt(request, receipt, base_policy(), base_revocation(receipt), base_context())
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["SCOPE_VIOLATION"]

def test_scope_constrained_budget_cannot_be_omitted_by_request():
    request = base_request()
    del request["max_effect_budget"]
    receipt = make_receipt(request, scope=base_scope(), nonce="scope-budget-omitted")

    result = verify_permit_receipt(request, receipt, base_policy(), base_revocation(receipt), base_context())
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["SCOPE_VIOLATION"]

