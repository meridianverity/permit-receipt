#!/usr/bin/env python3
"""Independent standard-library recomputation check for the IETF 126 packet.

This script intentionally does not import ``orprg_eval`` or ``run_review_packet``.
It rereads generated public outputs and recomputes the canonical request bytes,
action digest, receipt-core digest, selected negative-vector pass flags, and
signature-covered authorization-reference commitments from first principles.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "ietf126" / "results"
SUPPORTED_PROFILE = "CP-JSON-2"
EXPECTED_TRANSPARENCY_MISSING = "DRC-053_TRANSPARENCY_PROOF_MISSING"
EXPECTED_SCOPE_VIOLATION = "DRC-005_SCOPE_VIOLATION"
MAX_CANONICAL_DEPTH = 32
MAX_CONTAINER_ITEMS = 10_000
MAX_TOTAL_NODES = 50_000
MAX_STRING_UTF8_BYTES = 65_536
MAX_CANONICAL_BYTES = 1_048_576
MAX_INPUT_FILE_BYTES = 8 * 1_048_576
MIN_PROFILE_INTEGER = -(2**63)
MAX_PROFILE_INTEGER = 2**63 - 1


def _normalize_text(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("CP-JSON-2 rejects lone UTF-16 surrogate code points")
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized.encode("utf-8")) > MAX_STRING_UTF8_BYTES:
        raise ValueError("CP-JSON-2 string length limit exceeded")
    return normalized


def normalize(
    value: Any, *, depth: int = 0, budget: list[int] | None = None
) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_TOTAL_NODES:
        raise ValueError("CP-JSON-2 node limit exceeded")
    if depth > MAX_CANONICAL_DEPTH:
        raise ValueError("CP-JSON-2 nesting limit exceeded")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value < MIN_PROFILE_INTEGER or value > MAX_PROFILE_INTEGER:
            raise ValueError("CP-JSON-2 integer outside signed 64-bit profile")
        return value
    if isinstance(value, float):
        raise ValueError("CP-JSON-2 rejects floating point inputs")
    if isinstance(value, str):
        return _normalize_text(value)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("CP-JSON-2 array item limit exceeded")
        return [normalize(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, Mapping):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("CP-JSON-2 object member limit exceeded")
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("CP-JSON-2 object member names must be strings")
            normalized_key = _normalize_text(key)
            if normalized_key in out:
                raise ValueError(f"duplicate normalized key: {normalized_key}")
            out[normalized_key] = normalize(item, depth=depth + 1, budget=budget)
        return {key: out[key] for key in sorted(out)}
    raise ValueError(f"unsupported canonicalization type: {type(value)!r}")


def canonicalize(value: Mapping[str, Any], profile: str = SUPPORTED_PROFILE) -> bytes:
    if profile != SUPPORTED_PROFILE:
        raise ValueError(f"unsupported canonicalization profile: {profile}")
    if not isinstance(value, Mapping):
        raise ValueError("canonicalize expects a mapping")
    encoded = json.dumps(
        normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ValueError("CP-JSON-2 canonical byte limit exceeded")
    return encoded


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_FILE_BYTES:
        raise ValueError(f"input exceeds independent recompute limit: {path.name}")

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        normalized_names: set[str] = set()
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            normalized = _normalize_text(key)
            if normalized in normalized_names:
                raise ValueError(f"duplicate normalized JSON member: {normalized}")
            normalized_names.add(normalized)
            out[key] = value
        return out

    def parse_int(text: str) -> int:
        value = int(text, 10)
        if value < MIN_PROFILE_INTEGER or value > MAX_PROFILE_INTEGER:
            raise ValueError("JSON integer outside signed 64-bit profile")
        return value

    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_int=parse_int,
            parse_float=lambda _text: (_ for _ in ()).throw(ValueError("floating point rejected")),
            parse_constant=lambda _text: (_ for _ in ()).throw(ValueError("nonfinite number rejected")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid strict JSON: {path.name}") from exc


def check(condition: bool, checks: list[dict[str, Any]], check_id: str, detail: str = "") -> None:
    checks.append({"check_id": check_id, "pass": bool(condition), "detail": detail})


def main() -> int:
    checks: list[dict[str, Any]] = []
    one_path = RESULTS / "one-protected-action.json"
    negative_path = RESULTS / "negative-vector-results.json"
    crossref_path = RESULTS / "interop-crossref-results.json"
    bytes_path = RESULTS / "canonical-request.bytes.txt"
    hex_path = RESULTS / "canonical-request.hex.txt"

    missing = [p.relative_to(ROOT).as_posix() for p in [one_path, negative_path, crossref_path, bytes_path, hex_path] if not p.exists()]
    if missing:
        report = {"ok": False, "error": "missing_generated_outputs", "missing": missing}
        RESULTS.mkdir(parents=True, exist_ok=True)
        (RESULTS / "independent-recompute-results.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    one = load_json(one_path)
    negative = load_json(negative_path)
    crossref = load_json(crossref_path)

    profile = one.get("canonicalization_profile_ref")
    canonical_bytes = canonicalize(one["request"], profile)
    canonical_text = canonical_bytes.decode("utf-8")
    canonical_hex = canonical_bytes.hex()
    action_digest = sha256_hex(canonical_bytes)
    receipt_core_digest = sha256_hex(canonicalize(one["permit_receipt"]["receipt_core"], profile))

    check(profile == SUPPORTED_PROFILE, checks, "profile-supported", str(profile))
    check(one.get("canonical_request_utf8") == canonical_text, checks, "canonical-utf8-matches")
    check(bytes_path.read_text(encoding="utf-8").rstrip("\n") == canonical_text, checks, "canonical-bytes-file-matches")
    check(one.get("canonical_request_hex") == canonical_hex, checks, "canonical-hex-matches")
    check(hex_path.read_text(encoding="utf-8").strip() == canonical_hex, checks, "canonical-hex-file-matches")
    check(one.get("action_digest") == action_digest, checks, "action-digest-recomputed", action_digest)
    check(one.get("permit_receipt_core_digest") == receipt_core_digest, checks, "receipt-core-digest-recomputed", receipt_core_digest)

    auth_ref = one.get("authorization_ref_sample") or {}
    check(auth_ref.get("action_commitment") == "sha256:" + action_digest, checks, "authref-commits-to-action-digest")
    check(auth_ref.get("ref_artifact_digest") == "sha256:" + receipt_core_digest, checks, "authref-artifact-digest-recomputed")
    check(auth_ref.get("signature_coverage") is True, checks, "authref-signature-coverage-marker")

    neg_rows = negative.get("selected_negative_vectors", [])
    check(bool(neg_rows), checks, "negative-vector-rows-present", str(len(neg_rows)))
    check(all(row.get("pass") is True for row in neg_rows), checks, "negative-vector-pass-flags", str(len(neg_rows)))
    transparency_rows = [row for row in neg_rows if row.get("vector_id") == "KNEG-TRANSPARENCY-PROOF-MISSING"]
    observed_transparency = transparency_rows[0].get("observed", {}).get("denial_reason_code") if transparency_rows else None
    expected_transparency = transparency_rows[0].get("expected", {}).get("denial_reason_code") if transparency_rows else None
    check(observed_transparency == EXPECTED_TRANSPARENCY_MISSING, checks, "transparency-missing-code-observed", str(observed_transparency))
    check(expected_transparency == EXPECTED_TRANSPARENCY_MISSING, checks, "transparency-missing-code-expected", str(expected_transparency))
    budget_omission_rows = [row for row in neg_rows if row.get("vector_id") == "KNEG-SCOPE-VIOLATION-BUDGET-OMITTED"]
    budget_omission_ok = bool(budget_omission_rows) and budget_omission_rows[0].get("pass") is True and budget_omission_rows[0].get("observed", {}).get("denial_reason_code") == EXPECTED_SCOPE_VIOLATION
    check(budget_omission_ok, checks, "scope-budget-omission-fails-closed", str(budget_omission_rows[0].get("observed", {}).get("denial_reason_code") if budget_omission_rows else None))

    cross_rows = crossref.get("results", [])
    check(bool(cross_rows), checks, "crossref-rows-present", str(len(cross_rows)))
    check(all(row.get("pass") is True for row in cross_rows), checks, "crossref-pass-flags", str(len(cross_rows)))

    report = {
        "ok": all(row["pass"] for row in checks),
        "runner_mode_observed": one.get("runner_mode"),
        "tooling_boundary": "standard-library recomputation; no package import; no signature implementation",
        "canonicalization_profile_ref": profile,
        "action_digest": action_digest,
        "permit_receipt_core_digest": receipt_core_digest,
        "checks": checks,
        "passed": sum(1 for row in checks if row["pass"]),
        "total": len(checks),
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "independent-recompute-results.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
