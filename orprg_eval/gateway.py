"""Mock external-interface gateway for dual-enforcement experiments."""
from __future__ import annotations
from typing import Any, Dict, Mapping, Optional
from .canonicalization import digest_obj
from .models import ALLOW, DENY, DRC
from .verifier import verify_capability_token, parse_time

class MockEgressGateway:
    """A minimal downstream external-interface verifier.

    It does not call the PermitReceipt verifier. It accepts only signed,
    audience-bound capability tokens derived from successful permit verification.
    This demonstrates dual enforcement: a direct bypass without derived evidence
    fails at the external interface.
    """
    def __init__(self, gateway_id: str):
        self.gateway_id = gateway_id
        self.audit = []

    def commit(self, request: Mapping[str, Any], capability_token: Optional[Mapping[str, Any]], policy_state: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        context = dict(context or {})
        evidence: Dict[str, Any] = {}
        if request.get("interface_id") != self.gateway_id:
            result = {"decision": DENY, "denial_reason_code": DRC["CAPABILITY_AUDIENCE_MISMATCH"], "evidence_digests": evidence}
            self.audit.append(result)
            return result
        code = verify_capability_token(request, capability_token, policy_state, context, evidence, parse_time(context.get("now", policy_state["now"])))
        if code:
            result = {"decision": DENY, "denial_reason_code": DRC["GATEWAY_BYPASS_DENIED"] if capability_token is None else code, "evidence_digests": evidence}
        else:
            result = {"decision": ALLOW, "denial_reason_code": None, "evidence_digests": evidence}
        self.audit.append(result)
        return result
