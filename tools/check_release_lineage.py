#!/usr/bin/env python3
"""Check v2.2.5 release-lineage and reviewer-pointer hygiene."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
CURRENT_VERSION = "2.2.5-public-eval"
CURRENT_PROJECT_VERSION = "2.2.5"
CURRENT_TAG = "v2.2.5-public-eval"
CURRENT_ASSET = "permit-receipt-ref-eval-v2_2_5-public-eval.zip"
CURRENT_SIDECAR = CURRENT_ASSET + ".sha256"

ACTIVE_FILES = [
    "README.md",
    "README_FIRST.md",
    "QUICKSTART.md",
    "docs/GITHUB_RELEASE_BODY.md",
    "docs/GITHUB_UPLOAD_CHECKLIST.md",
    "docs/IETF126_RELEASE_POINTER_LOCK.md",
    "docs/IETF_HACKATHON_PROJECT_PAGE.md",
    "docs/PRE_RELEASE_AUDIT_CHECKLIST.md",
    "ietf126/README.md",
    "ietf126/SUBMISSION_TEXT.md",
]
REQUIRED_FILES = [
    "RELEASE_NOTES_v2_2_5.md",
    "docs/RELEASE_DECISION_RECORD_v2_2_5.md",
    "docs/RELEASE_LINEAGE_v2_2_5.md",
    "docs/RELEASE_PUBLISHING_PROTOCOL_v2_2_5.md",
    "docs/RELEASE_PROVENANCE_AND_ASSET_BINDING.md",
    "docs/REVIEWER_FAST_PATH_v2_2_5.md",
    "docs/QA_REPORT_v2_2_5_PUBLIC_EVAL.md",
    "docs/GIT_UPDATE_CHECKLIST_v2_2_5.md",
    "tools/build_release_asset.py",
    "tools/verify_release_artifact.py",
]
STALE_ACTIVE_PATTERNS = [
    r"v2\.2\.4-public-eval",
    r"permit-receipt-ref-eval-v2_2_4-public-eval\.zip",
    r"permit-receipt-ref-eval-v2_2_4-public-eval\.zip\.sha256",
]
HISTORICAL_MARKERS = (
    "superseded",
    "supersedes",
    "historical",
    "not current",
    "not canonical",
    "do not ",
    "must not ",
    "older",
    "previous",
    "fresh tag",
    "same-tag",
    "release-lineage",
)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def stale_is_historical(line: str, start: int) -> bool:
    before = line[max(0, start - 180):start].lower()
    full = line.lower()
    return any(marker in before or marker in full for marker in HISTORICAL_MARKERS)


def main() -> int:
    findings: list[dict[str, str]] = []
    version_path = ROOT / "VERSION"
    if not version_path.exists() or version_path.read_text(encoding="utf-8").strip() != CURRENT_VERSION:
        findings.append({"path": "VERSION", "kind": "version_mismatch", "detail": CURRENT_VERSION})

    pyproject = read("pyproject.toml") if (ROOT / "pyproject.toml").exists() else ""
    if f'version = "{CURRENT_PROJECT_VERSION}"' not in pyproject:
        findings.append({"path": "pyproject.toml", "kind": "project_version_mismatch", "detail": CURRENT_PROJECT_VERSION})

    for rel in REQUIRED_FILES:
        if not (ROOT / rel).exists():
            findings.append({"path": rel, "kind": "missing_required_lineage_file", "detail": "file not found"})

    for rel in ACTIVE_FILES:
        path = ROOT / rel
        if not path.exists():
            findings.append({"path": rel, "kind": "missing_active_file", "detail": "file not found"})
            continue
        text = path.read_text(encoding="utf-8")
        if rel in {"README.md", "docs/GITHUB_RELEASE_BODY.md", "docs/GITHUB_UPLOAD_CHECKLIST.md", "docs/IETF126_RELEASE_POINTER_LOCK.md"}:
            for required in (CURRENT_TAG, CURRENT_ASSET):
                if required not in text:
                    findings.append({"path": rel, "kind": "current_pointer_missing", "detail": required})
        if rel in {"docs/GITHUB_RELEASE_BODY.md", "docs/GITHUB_UPLOAD_CHECKLIST.md", "docs/IETF126_RELEASE_POINTER_LOCK.md"} and CURRENT_SIDECAR not in text:
            findings.append({"path": rel, "kind": "current_sidecar_missing", "detail": CURRENT_SIDECAR})
        for pattern in STALE_ACTIVE_PATTERNS:
            for match in re.finditer(pattern, text):
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end]
                if not stale_is_historical(line, match.start() - line_start):
                    findings.append({"path": rel, "kind": "stale_active_pointer", "detail": pattern})

    lineage = read("docs/RELEASE_LINEAGE_v2_2_5.md") if (ROOT / "docs/RELEASE_LINEAGE_v2_2_5.md").exists() else ""
    for phrase in ("fresh tag", "same-tag asset-refresh ambiguity", "v2.2.4-public-eval", "v2.2.5-public-eval"):
        if phrase not in lineage:
            findings.append({"path": "docs/RELEASE_LINEAGE_v2_2_5.md", "kind": "lineage_phrase_missing", "detail": phrase})

    report = {
        "ok": not findings,
        "current_version": CURRENT_VERSION,
        "current_tag": CURRENT_TAG,
        "current_asset": CURRENT_ASSET,
        "current_sidecar": CURRENT_SIDECAR,
        "finding_count": len(findings),
        "findings": findings,
    }
    CHECKS.mkdir(exist_ok=True)
    (CHECKS / "release_lineage_check.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
