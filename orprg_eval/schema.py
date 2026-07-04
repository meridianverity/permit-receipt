"""Small schema validator for synthetic ORPRG test artifacts."""
from __future__ import annotations
from typing import Any, Mapping, Optional
from .models import DRC

BASE_REQUEST_REQUIRED = {"effect_type", "interface_id", "action_type", "target_id", "tenant_id", "purpose_id", "payload_digest"}
RECEIPT_CORE_REQUIRED = {
    "policy_digest", "epoch_id", "valid_from", "valid_to", "action_digest", "scope",
    "anti_replay", "canonicalization_profile_ref", "authority_profile_id", "assurance_level_id", "issuer_id",
}
AUTH_REQUIRED = {"issuer_id", "signature"}

def validate_request_schema(request: Mapping[str, Any]) -> Optional[str]:
    if not isinstance(request, Mapping):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    missing = BASE_REQUEST_REQUIRED - set(request.keys())
    if missing:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    for key in ("effect_type", "interface_id", "action_type", "target_id", "tenant_id", "purpose_id", "payload_digest"):
        if not isinstance(request.get(key), str) or not request.get(key):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    effect_type = request.get("effect_type")
    if effect_type == "KEY_RELEASE" and ("key_id" not in request or "key_op" not in request):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if effect_type in {"EXTENSION_INSTALL", "EXTENSION_ENABLE", "EXTENSION_UPDATE"} and "artifact_id" not in request:
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if "max_effect_budget" in request:
        try:
            if int(request["max_effect_budget"]) < 0:
                return DRC["SCHEMA_VALIDATION_FAILURE"]
        except (TypeError, ValueError):
            return DRC["SCHEMA_VALIDATION_FAILURE"]
    return None

def validate_receipt_schema(receipt: Mapping[str, Any]) -> Optional[str]:
    if not isinstance(receipt, Mapping):
        return DRC["RECEIPT_MALFORMED"]
    core = receipt.get("receipt_core")
    auth = receipt.get("authenticity")
    if not isinstance(core, Mapping) or not isinstance(auth, Mapping):
        return DRC["RECEIPT_MALFORMED"]
    if RECEIPT_CORE_REQUIRED - set(core.keys()):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if AUTH_REQUIRED - set(auth.keys()):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    if not isinstance(core.get("scope"), Mapping) or not isinstance(core.get("anti_replay"), Mapping):
        return DRC["SCHEMA_VALIDATION_FAILURE"]
    return None
