#!/usr/bin/env python3
"""Verify the downloaded public-evaluation release ZIP against its sidecar."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

EXPECTED_ASSET_NAME = "permit-receipt-ref-eval-v2_2_5-public-eval.zip"
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_sidecar(path: Path) -> tuple[str, str]:
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"sidecar must contain exactly one non-empty line, observed {len(lines)}")
    parts = lines[0].split()
    if len(parts) != 2:
        raise ValueError("sidecar line must contain a 64-character SHA-256 digest followed by the asset name")
    digest, name = parts
    if not HEX64_RE.match(digest):
        raise ValueError("sidecar digest is not a 64-character hexadecimal SHA-256 value")
    return digest.lower(), name


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the v2.2.5 public-evaluation ZIP and .sha256 sidecar.")
    parser.add_argument("zip_path", help="Path to permit-receipt-ref-eval-v2_2_5-public-eval.zip")
    parser.add_argument("sidecar_path", help="Path to permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256")
    parser.add_argument("--expected-name", default=EXPECTED_ASSET_NAME)
    args = parser.parse_args()

    zip_path = Path(args.zip_path)
    sidecar_path = Path(args.sidecar_path)
    findings: list[dict[str, str]] = []
    if not zip_path.exists():
        findings.append({"kind": "missing_zip", "detail": str(zip_path)})
    if not sidecar_path.exists():
        findings.append({"kind": "missing_sidecar", "detail": str(sidecar_path)})
    if findings:
        print(json.dumps({"ok": False, "findings": findings}, indent=2, sort_keys=True))
        return 1

    try:
        sidecar_digest, sidecar_name = parse_sidecar(sidecar_path)
    except Exception as exc:
        print(json.dumps({"ok": False, "findings": [{"kind": "sidecar_parse_error", "detail": repr(exc)}]}, indent=2, sort_keys=True))
        return 1

    observed_digest = sha256(zip_path)
    if zip_path.name != args.expected_name:
        findings.append({"kind": "zip_name_mismatch", "detail": f"expected {args.expected_name}, observed {zip_path.name}"})
    if sidecar_name != args.expected_name:
        findings.append({"kind": "sidecar_asset_name_mismatch", "detail": f"expected {args.expected_name}, observed {sidecar_name}"})
    if sidecar_digest != observed_digest:
        findings.append({"kind": "sha256_mismatch", "detail": f"sidecar {sidecar_digest}, observed {observed_digest}"})

    report = {
        "ok": not findings,
        "asset_name": zip_path.name,
        "asset_size_bytes": zip_path.stat().st_size,
        "observed_sha256": observed_digest,
        "sidecar_name": sidecar_path.name,
        "sidecar_asset_name": sidecar_name,
        "sidecar_sha256_value": sidecar_digest,
        "findings": findings,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
