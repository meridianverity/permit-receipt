#!/usr/bin/env python3
"""Verify the active immutable v2.2.6 release tuple and historical lineage."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    from release_config import ASSET_NAME, MANIFEST_NAME, PROJECT_VERSION, PROVENANCE_NAME, PUBLIC_VERSION, SIDECAR_NAME, TAG
except ImportError:  # pragma: no cover
    from tools.release_config import ASSET_NAME, MANIFEST_NAME, PROJECT_VERSION, PROVENANCE_NAME, PUBLIC_VERSION, SIDECAR_NAME, TAG

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"

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
    "RELEASE_NOTES_v2_2_6.md",
    "docs/RELEASE_DECISION_RECORD_v2_2_6.md",
    "docs/RELEASE_LINEAGE_v2_2_6.md",
    "docs/RELEASE_PUBLISHING_PROTOCOL_v2_2_6.md",
    "docs/RELEASE_PROVENANCE_AND_ASSET_BINDING.md",
    "docs/REVIEWER_FAST_PATH_v2_2_6.md",
    "docs/QA_REPORT_v2_2_6_PUBLIC_EVAL.md",
    "docs/GIT_UPDATE_CHECKLIST_v2_2_6.md",
    "docs/V2_2_5_ERRATA_AND_FORWARD_POINTER.md",
    "docs/VERSION_TAXONOMY.md",
    "tools/release_config.py",
    "tools/build_release_asset.py",
    "tools/verify_release_artifact.py",
    "ietf126/independent_crypto_verify.py",
]
HISTORICAL_MARKERS = (
    "superseded", "supersedes", "historical", "not current", "not canonical",
    "do not ", "must not ", "older", "previous", "fresh tag", "same-tag",
    "release-lineage", "forward pointer", "errata", "history",
)
STALE_ACTIVE_RE = re.compile(
    r"v2\.2\.[0-5]-public-eval|permit-receipt-ref-eval-v2_2_[0-5]-public-eval\.zip(?:\.sha256)?"
)


def _historical(line: str, start: int) -> bool:
    before = line[max(0, start - 220):start].lower()
    full = line.lower()
    return any(marker in before or marker in full for marker in HISTORICAL_MARKERS)


def main() -> int:
    findings: list[dict[str, str]] = []
    version_path = ROOT / "VERSION"
    if not version_path.exists() or version_path.read_text(encoding="utf-8").strip() != PUBLIC_VERSION:
        findings.append({"path": "VERSION", "kind": "version_mismatch", "detail": PUBLIC_VERSION})

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8") if (ROOT / "pyproject.toml").exists() else ""
    if f'version = "{PROJECT_VERSION}"' not in pyproject:
        findings.append({"path": "pyproject.toml", "kind": "project_version_mismatch", "detail": PROJECT_VERSION})

    for rel in REQUIRED_FILES:
        if not (ROOT / rel).is_file():
            findings.append({"path": rel, "kind": "missing_required_lineage_file", "detail": "file not found"})

    for rel in ACTIVE_FILES:
        path = ROOT / rel
        if not path.is_file():
            findings.append({"path": rel, "kind": "missing_active_file", "detail": "file not found"})
            continue
        text = path.read_text(encoding="utf-8")
        if TAG not in text:
            findings.append({"path": rel, "kind": "current_tag_missing", "detail": TAG})
        if rel in {"README.md", "docs/GITHUB_RELEASE_BODY.md", "docs/GITHUB_UPLOAD_CHECKLIST.md", "docs/IETF126_RELEASE_POINTER_LOCK.md"}:
            if ASSET_NAME not in text:
                findings.append({"path": rel, "kind": "current_asset_missing", "detail": ASSET_NAME})
        if rel in {"docs/GITHUB_RELEASE_BODY.md", "docs/GITHUB_UPLOAD_CHECKLIST.md", "docs/IETF126_RELEASE_POINTER_LOCK.md"}:
            for label, required_name in (
                ("current_sidecar_missing", SIDECAR_NAME),
                ("current_manifest_missing", MANIFEST_NAME),
                ("current_provenance_missing", PROVENANCE_NAME),
            ):
                if required_name not in text:
                    findings.append({"path": rel, "kind": label, "detail": required_name})
        for match in STALE_ACTIVE_RE.finditer(text):
            observed = match.group(0)
            if TAG in observed or ASSET_NAME in observed or SIDECAR_NAME in observed:
                continue
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end < 0:
                line_end = len(text)
            line = text[line_start:line_end]
            if not _historical(line, match.start() - line_start):
                findings.append({"path": rel, "kind": "stale_active_pointer", "detail": observed})

    lineage_path = ROOT / "docs/RELEASE_LINEAGE_v2_2_6.md"
    lineage = lineage_path.read_text(encoding="utf-8") if lineage_path.exists() else ""
    for phrase in ("fresh tag", "same-tag asset-refresh ambiguity", "v2.2.5-public-eval", TAG):
        if phrase not in lineage:
            findings.append({"path": lineage_path.relative_to(ROOT).as_posix(), "kind": "lineage_phrase_missing", "detail": phrase})

    report = {
        "ok": not findings,
        "current_version": PUBLIC_VERSION,
        "current_tag": TAG,
        "current_asset": ASSET_NAME,
        "current_sidecar": SIDECAR_NAME,
        "current_manifest": MANIFEST_NAME,
        "current_provenance": PROVENANCE_NAME,
        "finding_count": len(findings),
        "findings": findings,
    }
    CHECKS.mkdir(exist_ok=True)
    (CHECKS / "release_lineage_check.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
