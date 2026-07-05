#!/usr/bin/env python3
"""Check that reviewer-facing IETF 126 release pointers use the current tag."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
CURRENT_TAG = "v2.2.4-public-eval"
CURRENT_RELEASE_URL = f"https://github.com/meridianverity/permit-receipt/releases/tag/{CURRENT_TAG}"

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
STALE_TAG_RE = re.compile(r"v2\.2\.[0-3]-public-eval")


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
                findings.append({"path": rel, "kind": "stale_release_url", "detail": observed_tag})
        for match in STALE_TAG_RE.finditer(text):
            findings.append({"path": rel, "kind": "stale_release_tag_text", "detail": match.group(0)})

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
