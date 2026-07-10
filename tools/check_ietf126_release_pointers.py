#!/usr/bin/env python3
"""Check that active reviewer-facing files use the exact v2.2.6 release tuple."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    from release_config import ASSET_NAME, MANIFEST_NAME, PROVENANCE_NAME, RELEASE_URL, SIDECAR_NAME, TAG
except ImportError:  # pragma: no cover
    from tools.release_config import ASSET_NAME, MANIFEST_NAME, PROVENANCE_NAME, RELEASE_URL, SIDECAR_NAME, TAG

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
ACTIVE_POINTER_FILES = [
    "README.md", "QUICKSTART.md", "docs/GITHUB_RELEASE_BODY.md",
    "docs/GITHUB_UPLOAD_CHECKLIST.md", "docs/IETF_HACKATHON_PROJECT_PAGE.md",
    "docs/PRE_RELEASE_AUDIT_CHECKLIST.md", "ietf126/README.md", "ietf126/SUBMISSION_TEXT.md",
]
CURRENT_URL_REQUIRED_FILES = ["docs/IETF126_RELEASE_POINTER_LOCK.md"]
ASSET_REQUIRED_FILES = {
    "docs/GITHUB_RELEASE_BODY.md", "docs/GITHUB_UPLOAD_CHECKLIST.md",
    "docs/PRE_RELEASE_AUDIT_CHECKLIST.md", "docs/IETF126_RELEASE_POINTER_LOCK.md",
}
SIDECAR_REQUIRED_FILES = set(ASSET_REQUIRED_FILES)
MANIFEST_REQUIRED_FILES = set(ASSET_REQUIRED_FILES)
PROVENANCE_REQUIRED_FILES = set(ASSET_REQUIRED_FILES)
RELEASE_TAG_RE = re.compile(r"https://github\.com/meridianverity/permit-receipt/releases/tag/([^\s)]+)")
STALE_TAG_RE = re.compile(r"v2\.2\.[0-5]-public-eval")
STALE_ASSET_RE = re.compile(r"permit-receipt-ref-eval-v2_2_[0-5]-public-eval\.zip(?:\.sha256)?")
NEGATION_MARKERS = (
    "do not ", "must not ", "not ", "stale", "older", "previous", "historical",
    "superseded", "supersedes", "release-lineage", "avoid", "history", "earlier",
    "forward pointer", "errata",
)


def _historical(line: str, start: int) -> bool:
    before = line[max(0, start - 180):start].lower()
    full = line.lower()
    return any(marker in before or marker in full for marker in NEGATION_MARKERS)


def main() -> int:
    findings: list[dict[str, str]] = []
    inspected: list[str] = []
    for rel in ACTIVE_POINTER_FILES:
        path = ROOT / rel
        if not path.is_file():
            findings.append({"path": rel, "kind": "missing_active_pointer_file", "detail": "file not found"})
            continue
        inspected.append(rel)
        text = path.read_text(encoding="utf-8")
        if TAG not in text:
            findings.append({"path": rel, "kind": "canonical_tag_missing", "detail": TAG})
        for match in RELEASE_TAG_RE.finditer(text):
            observed = match.group(1).rstrip(".,`>")
            if observed != TAG:
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end < 0:
                    line_end = len(text)
                line = text[line_start:line_end]
                if not _historical(line, match.start() - line_start):
                    findings.append({"path": rel, "kind": "stale_release_url", "detail": observed})
        for pattern in (STALE_TAG_RE, STALE_ASSET_RE):
            for match in pattern.finditer(text):
                observed = match.group(0)
                if observed in {TAG, ASSET_NAME, SIDECAR_NAME}:
                    continue
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end < 0:
                    line_end = len(text)
                line = text[line_start:line_end]
                if not _historical(line, match.start() - line_start):
                    findings.append({"path": rel, "kind": "stale_active_pointer", "detail": observed})
        if rel in ASSET_REQUIRED_FILES and ASSET_NAME not in text:
            findings.append({"path": rel, "kind": "canonical_asset_name_missing", "detail": ASSET_NAME})
        if rel in SIDECAR_REQUIRED_FILES and SIDECAR_NAME not in text:
            findings.append({"path": rel, "kind": "canonical_sidecar_name_missing", "detail": SIDECAR_NAME})
        if rel in MANIFEST_REQUIRED_FILES and MANIFEST_NAME not in text:
            findings.append({"path": rel, "kind": "canonical_manifest_name_missing", "detail": MANIFEST_NAME})
        if rel in PROVENANCE_REQUIRED_FILES and PROVENANCE_NAME not in text:
            findings.append({"path": rel, "kind": "canonical_provenance_name_missing", "detail": PROVENANCE_NAME})

    for rel in CURRENT_URL_REQUIRED_FILES:
        path = ROOT / rel
        if not path.is_file():
            findings.append({"path": rel, "kind": "missing_current_url_file", "detail": "file not found"})
            continue
        inspected.append(rel)
        if RELEASE_URL not in path.read_text(encoding="utf-8"):
            findings.append({"path": rel, "kind": "canonical_release_url_missing", "detail": RELEASE_URL})

    project_page = ROOT / "docs/IETF_HACKATHON_PROJECT_PAGE.md"
    if not project_page.is_file() or RELEASE_URL not in project_page.read_text(encoding="utf-8"):
        findings.append({"path": project_page.relative_to(ROOT).as_posix(), "kind": "canonical_release_url_missing", "detail": RELEASE_URL})

    report = {
        "ok": not findings,
        "current_tag": TAG,
        "current_release_url": RELEASE_URL,
        "current_asset_name": ASSET_NAME,
        "current_sidecar_name": SIDECAR_NAME,
        "current_manifest_name": MANIFEST_NAME,
        "current_provenance_name": PROVENANCE_NAME,
        "inspected": inspected,
        "finding_count": len(findings),
        "findings": findings,
    }
    CHECKS.mkdir(exist_ok=True)
    (CHECKS / "ietf126_release_pointer_check.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
