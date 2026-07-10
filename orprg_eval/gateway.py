"""Mock external-interface gateway for dual-enforcement experiments."""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from .models import ALLOW, DENY, DRC
from .verifier import parse_time, verify_capability_token


class MockEgressGateway:
    """A minimal downstream external-interface verifier.

    The gateway accepts a capability only when the caller supplies the trusted
    digest of the active PermitReceipt in ``context['expected_receipt_digest']``.
    A capability's self-asserted receipt digest is never sufficient on its own.
    """

    def __init__(self, gateway_id: str):
        self.gateway_id = gateway_id
        self.audit: list[Dict[str, Any]] = []

    def commit(
        self,
        request: Mapping[str, Any],
        capability_token: Optional[Mapping[str, Any]],
        policy_state: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        context = dict(context or {})
        evidence: Dict[str, Any] = {}
        if request.get("interface_id") != self.gateway_id:
            result = {
                "decision": DENY,
                "denial_reason_code": DRC["CAPABILITY_AUDIENCE_MISMATCH"],
                "evidence_digests": evidence,
            }
            self.audit.append(result)
            return result
        if capability_token is None:
            result = {
                "decision": DENY,
                "denial_reason_code": DRC["GATEWAY_BYPASS_DENIED"],
                "evidence_digests": evidence,
            }
            self.audit.append(result)
            return result
        code = verify_capability_token(
            request,
            capability_token,
            policy_state,
            context,
            evidence,
            parse_time(context.get("now", policy_state["now"])),
            expected_receipt_digest=context.get("expected_receipt_digest"),
        )
        result = {
            "decision": DENY if code else ALLOW,
            "denial_reason_code": code,
            "evidence_digests": evidence,
        }
        self.audit.append(result)
        return result
