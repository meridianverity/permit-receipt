from orprg_eval.models import DENY, DRC
from orprg_eval.vector_factory import base_context, base_policy, base_request, base_revocation, base_scope, make_receipt
from orprg_eval.verifier import verify_permit_receipt


def test_scope_constrained_optional_field_cannot_be_omitted_by_request():
    request = base_request()
    request.pop("max_effect_budget", None)
    scope = base_scope()
    receipt = make_receipt(request, scope=scope, nonce="scope-budget-omitted")

    result = verify_permit_receipt(request, receipt, base_policy(), base_revocation(receipt), base_context())
    assert result.decision == DENY
    assert result.denial_reason_code == DRC["SCOPE_VIOLATION"]


def test_scope_constrained_optional_field_allows_when_present_and_within_budget():
    request = base_request()
    scope = base_scope()
    receipt = make_receipt(request, scope=scope, nonce="scope-budget-present")

    result = verify_permit_receipt(request, receipt, base_policy(), base_revocation(receipt), base_context())
    assert result.decision == "ALLOW"
    assert result.denial_reason_code is None
