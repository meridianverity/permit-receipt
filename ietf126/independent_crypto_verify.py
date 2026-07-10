#!/usr/bin/env python3
"""Independent Ed25519 verification for the generated IETF 126 review packet.

This checker does not import ``orprg_eval`` or ``run_review_packet``. It reads
public output bytes, independently canonicalizes the three signed objects, and
verifies the PermitReceipt, revocation list, and authorization-reference carrier.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "ietf126" / "results"
INPUT = RESULTS / "one-protected-action.json"
OUTPUT = RESULTS / "independent-crypto-verification.json"
PROFILE = "CP-JSON-2"
MAX_DEPTH = 32
MAX_ITEMS = 10_000
MAX_NODES = 50_000
MAX_STRING_BYTES = 65_536
MAX_CANONICAL_BYTES = 1_048_576
MAX_INPUT_BYTES = 8 * 1_048_576
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1


def _text(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("lone surrogate")
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized.encode("utf-8")) > MAX_STRING_BYTES:
        raise ValueError("string limit")
    return normalized


def _normalize(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_NODES or depth > MAX_DEPTH:
        raise ValueError("canonicalization resource limit")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not MIN_INTEGER <= value <= MAX_INTEGER:
            raise ValueError("integer outside profile")
        return value
    if isinstance(value, float):
        raise ValueError("floating point rejected")
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise ValueError("array limit")
        return [_normalize(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, Mapping):
        if len(value) > MAX_ITEMS:
            raise ValueError("object limit")
        output: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("non-string member name")
            normalized_key = _text(key)
            if normalized_key in output:
                raise ValueError("duplicate normalized member name")
            output[normalized_key] = _normalize(item, depth=depth + 1, budget=budget)
        return {key: output[key] for key in sorted(output)}
    raise ValueError("unsupported canonicalization type")


def canonicalize(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        raise ValueError("signed value is not an object")
    encoded = json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical byte limit")
    return encoded


def _strict_load(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input file limit")

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        normalized_names: set[str] = set()
        for key, value in pairs:
            if key in output or _text(key) in normalized_names:
                raise ValueError("duplicate JSON member")
            normalized_names.add(_text(key))
            output[key] = value
        return output

    def parse_int(text: str) -> int:
        value = int(text, 10)
        if not MIN_INTEGER <= value <= MAX_INTEGER:
            raise ValueError("integer outside profile")
        return value

    return json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=pairs_hook,
        parse_int=parse_int,
        parse_float=lambda _value: (_ for _ in ()).throw(ValueError("float rejected")),
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite rejected")),
    )


def _decode_b64(value: Any, expected_length: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64 value is not text")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("invalid base64") from exc
    if len(raw) != expected_length:
        raise ValueError("unexpected decoded length")
    return raw


def verify(public_key_b64: Any, signature_b64: Any, body: Mapping[str, Any]) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode_b64(public_key_b64, 32))
        public_key.verify(_decode_b64(signature_b64, 64), canonicalize(body))
        return True
    except (ValueError, InvalidSignature, TypeError):
        return False


def digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonicalize(value)).hexdigest()


def add(checks: list[dict[str, Any]], check_id: str, condition: bool, detail: str = "") -> None:
    checks.append({"check_id": check_id, "pass": bool(condition), "detail": detail})


def main() -> int:
    checks: list[dict[str, Any]] = []
    if not INPUT.exists():
        report = {"ok": False, "error": "missing one-protected-action.json", "checks": []}
        OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    document = _strict_load(INPUT)
    add(checks, "full-repository-runner", document.get("runner_mode") == "full-repository", str(document.get("runner_mode")))
    add(checks, "canonicalization-profile", document.get("canonicalization_profile_ref") == PROFILE)

    policy = document["policy_state_public_subset"]
    receipt = document["permit_receipt"]
    receipt_core = receipt["receipt_core"]
    receipt_auth = receipt["authenticity"]
    receipt_issuer = receipt_auth.get("issuer_id")
    receipt_key = policy.get("trusted_issuers", {}).get(receipt_issuer)
    add(checks, "receipt-issuer-bound", receipt_issuer == receipt_core.get("issuer_id"))
    add(checks, "receipt-issuer-trusted", isinstance(receipt_key, str))
    add(checks, "receipt-ed25519-signature", verify(receipt_key, receipt_auth.get("signature"), receipt_core))
    receipt_digest = digest(receipt_core)
    add(checks, "receipt-core-digest", receipt_digest == document.get("permit_receipt_core_digest"), receipt_digest)

    revocation_public = document["revocation_state_public_subset"]
    signed_list = revocation_public["signed_revocation_list"]
    list_body = signed_list["body"]
    list_auth = signed_list["authenticity"]
    list_issuer = list_auth.get("issuer_id")
    revocation_key = policy.get("revocation_authorities", {}).get(list_issuer)
    add(checks, "revocation-issuer-bound", list_issuer == list_body.get("issuer_id"))
    add(checks, "revocation-issuer-trusted", isinstance(revocation_key, str))
    add(checks, "revocation-ed25519-signature", verify(revocation_key, list_auth.get("signature"), list_body))
    list_digest = digest(list_body)
    add(checks, "revocation-list-digest", list_digest == revocation_public.get("signed_revocation_list_digest"), list_digest)

    carrier = document["authorization_ref_carrier"]
    carrier_body = carrier["carrier"]
    carrier_auth = carrier["authenticity"]
    authorization_ref = carrier_body["authorization_ref"]
    carrier_issuer = carrier_auth.get("issuer_id")
    carrier_key = policy.get("trusted_issuers", {}).get(carrier_issuer)
    add(checks, "carrier-issuer-bound", carrier_issuer == authorization_ref.get("issuer_or_signer"))
    add(checks, "carrier-issuer-trusted", isinstance(carrier_key, str))
    add(checks, "carrier-ed25519-signature", verify(carrier_key, carrier_auth.get("signature"), carrier_body))
    add(checks, "carrier-ref-equals-sample", authorization_ref == document.get("authorization_ref_sample"))
    add(checks, "carrier-ref-commits-receipt", authorization_ref.get("ref_artifact_digest") == "sha256:" + receipt_digest)
    add(checks, "carrier-ref-commits-action", authorization_ref.get("action_commitment") == "sha256:" + document.get("action_digest", ""))

    tampered_receipt = copy.deepcopy(receipt_core)
    tampered_receipt["epoch_id"] += 1
    add(checks, "receipt-tamper-negative", not verify(receipt_key, receipt_auth.get("signature"), tampered_receipt))
    tampered_list = copy.deepcopy(list_body)
    tampered_list["sequence"] += 1
    add(checks, "revocation-tamper-negative", not verify(revocation_key, list_auth.get("signature"), tampered_list))
    tampered_carrier = copy.deepcopy(carrier_body)
    tampered_carrier["authorization_ref"]["status"] = "revoked"
    add(checks, "carrier-tamper-negative", not verify(carrier_key, carrier_auth.get("signature"), tampered_carrier))

    report = {
        "ok": all(item["pass"] for item in checks),
        "tooling_boundary": "independent CP-JSON-2 implementation plus cryptography Ed25519; no orprg_eval import",
        "checks": checks,
        "passed": sum(1 for item in checks if item["pass"]),
        "total": len(checks),
    }
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
