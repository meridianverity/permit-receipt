#!/usr/bin/env python3
"""Check that reviewer-facing IETF 126 release pointers use the current tag."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
CURRENT_TAG = "v2.2.5-public-eval"
CURRENT_RELEASE_URL = f"https://github.com/meridianverity/permit-receipt/releases/tag/{CURRENT_TAG}"
CURRENT_ASSET_NAME = "permit-receipt-ref-eval-v2_2_5-public-eval.zip"
CURRENT_SIDECAR_NAME = f"{CURRENT_ASSET_NAME}.sha256"

# Active, reviewer-facing files. Historical release notes and decision records are
# intentionally excluded because they preserve earlier publication history.
ACTIVE_POINTER_FILES = [
    "README.md",
    "QUICKSTART.md",
    "docs/GITHUB_RELEASE_BODY.md",
    "docs/GITHUB_UPLOAD_CHECKLIST.md",
    "docs/IETF_HACKATHON_PROJECT_PAGE.md",
    "docs/PRE_RELEASE_AUDIT_CHECKLIST.md",
    "ietf126/README.md",
    "ietf126/SUBMISSION_TEXT.md",
]

# Files allowed to mention old tags in a negated/historical context, but still
# required to contain the current canonical release URL.
CURRENT_URL_REQUIRED_FILES = [
    "docs/IETF126_RELEASE_POINTER_LOCK.md",
]

RELEASE_TAG_RE = re.compile(r"https://github\.com/meridianverity/permit-receipt/releases/tag/([^\s)]+)")
STALE_TAG_RE = re.compile(r"v2\.2\.[0-4]-public-eval")
STALE_ASSET_RE = re.compile(r"permit-receipt-main-v2_2_[0-5]-ietf126-hardened\.zip|permit-receipt-ref-eval-v2_2_[0-4][^\s`]*\.zip")
ASSET_REQUIRED_FILES = {
    "docs/GITHUB_RELEASE_BODY.md",
    "docs/GITHUB_UPLOAD_CHECKLIST.md",
    "docs/PRE_RELEASE_AUDIT_CHECKLIST.md",
    "docs/IETF126_RELEASE_POINTER_LOCK.md",
}
SIDECAR_REQUIRED_FILES = {
    "docs/GITHUB_RELEASE_BODY.md",
    "docs/GITHUB_UPLOAD_CHECKLIST.md",
    "docs/PRE_RELEASE_AUDIT_CHECKLIST.md",
    "docs/IETF126_RELEASE_POINTER_LOCK.md",
}
NEGATION_MARKERS = (
    "do not ",
    "must not ",
    "not ",
    "not current",
    "not canonical",
    "stale",
    "older",
    "previous",
    "historical",
    "superseded",
    "supersedes",
    "review-reference only",
    "release-lineage",
    "avoid",
    "do not reuse",
    "do not publish",
    "do not ship",
    "superseded",
    "historical",
    "history",
    "earlier",
    "previous",
)


def stale_mention_is_historical(line: str, start: int) -> bool:
    before = line[max(0, start - 160):start].lower()
    full = line.lower()
    return any(marker in before or marker in full for marker in NEGATION_MARKERS)


def stale_reference_is_historical_or_negated(line: str, start: int) -> bool:
    before = line[max(0, start - 120):start].lower()
    full = line.lower()
    return any(marker in before or marker in full for marker in NEGATION_MARKERS)


def main() -> int:
    findings: list[dict[str, str]] = []
    inspected: list[str] = []
    for rel in ACTIVE_POINTER_FILES:
        path = ROOT / rel
        if not path.exists():
            findings.append({"path": rel, "kind": "missing_active_pointer_file", "detail": "file not found"})
            continue
        inspected.append(rel)
        text = path.read_text(encoding="utf-8")
        for match in RELEASE_TAG_RE.finditer(text):
            observed_tag = match.group(1).rstrip(".,`>")
            if observed_tag != CURRENT_TAG:
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end]
                if not stale_reference_is_historical_or_negated(line, match.start() - line_start):
                    findings.append({"path": rel, "kind": "stale_release_url", "detail": observed_tag})
        for match in STALE_TAG_RE.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end]
            if not stale_mention_is_historical(line, match.start() - line_start):
                findings.append({"path": rel, "kind": "stale_release_tag_text", "detail": match.group(0)})
        for match in STALE_ASSET_RE.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end]
            if not stale_reference_is_historical_or_negated(line, match.start() - line_start):
                findings.append({"path": rel, "kind": "stale_asset_name_text", "detail": match.group(0)})
        if rel in ASSET_REQUIRED_FILES and CURRENT_ASSET_NAME not in text:
            findings.append({"path": rel, "kind": "canonical_asset_name_missing", "detail": CURRENT_ASSET_NAME})
        if rel in SIDECAR_REQUIRED_FILES and CURRENT_SIDECAR_NAME not in text:
            findings.append({"path": rel, "kind": "canonical_sidecar_name_missing", "detail": CURRENT_SIDECAR_NAME})

    for rel in CURRENT_URL_REQUIRED_FILES:
        path = ROOT / rel
        if not path.exists():
            findings.append({"path": rel, "kind": "missing_current_url_file", "detail": "file not found"})
            continue
        inspected.append(rel)
        if CURRENT_RELEASE_URL not in path.read_text(encoding="utf-8"):
            findings.append({"path": rel, "kind": "canonical_release_url_missing", "detail": CURRENT_RELEASE_URL})

    project_page = (ROOT / "docs/IETF_HACKATHON_PROJECT_PAGE.md").read_text(encoding="utf-8") if (ROOT / "docs/IETF_HACKATHON_PROJECT_PAGE.md").exists() else ""
    if CURRENT_RELEASE_URL not in project_page:
        findings.append({
            "path": "docs/IETF_HACKATHON_PROJECT_PAGE.md",
            "kind": "canonical_release_url_missing",
            "detail": CURRENT_RELEASE_URL,
        })

    report = {
        "ok": not findings,
        "current_tag": CURRENT_TAG,
        "current_release_url": CURRENT_RELEASE_URL,
        "current_asset_name": CURRENT_ASSET_NAME,
        "current_sidecar_name": CURRENT_SIDECAR_NAME,
        "inspected": inspected,
        "finding_count": len(findings),
        "findings": findings,
    }
    CHECKS.mkdir(exist_ok=True)
    (CHECKS / "ietf126_release_pointer_check.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
