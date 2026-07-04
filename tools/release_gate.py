#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
CHECKS.mkdir(exist_ok=True)

SKIP_CONTENT = {
    Path("tools/release_gate.py"),
    Path("checks/release_gate_report.json"),
    Path("checks/release_gate_report.md"),
    Path(".gitignore"),
}
SKIP_DIRS = {
    ".git",
    ".github",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "tmp",
    "dist",
    "build",
    "results",
    "checks",
}
FORBIDDEN_PATH_FRAGMENTS = [
    "restricted_diligence",
    "restricted_annex",
    "legal_private",
    "legal_mapping_private",
    "nonpublic_strategy",
    "production_secret",
    "live_processor",
    "cardholder_data",
]
FORBIDDEN_CONTENT_PATTERNS = [
    r"private\s+diligence",
    r"evidence\s+of\s+use",
    r"production\s+processor\s+credential",
    r"live\s+processor\s+credential",
    r"cardholder\s+data\s+environment",
    r"raw\s+card\s+data",
]
# These patterns are forbidden when asserted positively. Negated boundary language
# such as "not a certification program" is allowed and encouraged.
OVERCLAIM_PATTERNS = [
    r"production[-\s]+ready",
    r"production[-\s]+grade",
    r"stable[-\s]+release",
    r"certified\s+production",
    r"official\s+IETF\s+reference\s+implementation",
    r"official\s+IETF\s+implementation",
    r"IETF[-\s]+endorsed",
    r"\bIETF\s+standard\b",
    r"\breference\s+implementation\b",
    r"open[-\s]+source[-\s]+implementation",
    r"public\s+trust\s+anchor",
    r"certificate\s+registry",
    r"conformance\s+program",
    r"conformance\s+suite",
    r"certification\s+program",
    r"compliance\s+certification",
    r"production\s+authorization\s+boundary",
    r"production\s+non[-\s]+bypassability\s+provided",
    r"proves\s+production\s+non[-\s]+bypassability",
]
NEGATION_MARKERS = (
    "not ",
    "not a ",
    "not an ",
    "no ",
    "does not ",
    "do not ",
    "is not ",
    "are not ",
    "without ",
    "excludes ",
    "exclude ",
    "no claim",
    "not claim",
    "does not claim",
)
ALLOWED_BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".pdf"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files():
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        yield rel, p


def read_text(path: Path):
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def overclaim_is_negated(line: str, start: int) -> bool:
    window = line[max(0, start - 80) : start].lower()
    full = line.lower()
    if any(marker in window for marker in NEGATION_MARKERS):
        return True
    if any(marker in full for marker in ('not ', 'no ', 'does not ', 'do not ', 'is not ', 'are not ', 'avoid', 'use instead', 'preferred wording', 'overclaim', 'release-gate scan')):
        return True
    # Common list item patterns: "- No X" or "It is not X".
    if re.search(r"(^|[\n\.;:\-])\s*(no|not|does\s+not|do\s+not|is\s+not|are\s+not)\b", full):
        return True
    return False


def main() -> int:
    findings = []
    files = []
    for rel, p in iter_files():
        rel_s = rel.as_posix()
        lower = rel_s.lower()
        files.append({"path": rel_s, "bytes": p.stat().st_size, "sha256": sha256(p)})
        if p.suffix.lower() == ".zip":
            findings.append(
                {
                    "path": rel_s,
                    "kind": "embedded_zip",
                    "detail": "ZIP files must not be nested in the public evaluation slice",
                }
            )
        for frag in FORBIDDEN_PATH_FRAGMENTS:
            if frag in lower:
                findings.append({"path": rel_s, "kind": "forbidden_path_fragment", "detail": frag})
        if rel in SKIP_CONTENT:
            continue
        txt = read_text(p)
        if txt is None:
            if p.suffix.lower() not in ALLOWED_BINARY_EXTS:
                findings.append({"path": rel_s, "kind": "unexpected_binary", "detail": p.suffix})
            continue
        for pat in FORBIDDEN_CONTENT_PATTERNS:
            if re.search(pat, txt, flags=re.IGNORECASE):
                findings.append({"path": rel_s, "kind": "forbidden_content_pattern", "detail": pat})
        for pat in OVERCLAIM_PATTERNS:
            for m in re.finditer(pat, txt, flags=re.IGNORECASE):
                line_start = txt.rfind("\n", 0, m.start()) + 1
                line_end = txt.find("\n", m.end())
                if line_end == -1:
                    line_end = len(txt)
                line = txt[line_start:line_end]
                if not overclaim_is_negated(line, m.start() - line_start):
                    findings.append(
                        {
                            "path": rel_s,
                            "kind": "positive_overclaim_pattern",
                            "detail": pat,
                            "line": line.strip()[:240],
                        }
                    )
    report = {
        "artifact": "PermitReceipt Public Evaluation Slice for AI-Agent External Effects v2.2.4",
        "ok": not findings,
        "file_count": len(files),
        "finding_count": len(findings),
        "findings": findings,
    }
    (CHECKS / "release_gate_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    md = [
        "# Release Gate Report",
        "",
        f"Status: **{'PASS' if report['ok'] else 'FAIL'}**",
        "",
        f"Files scanned: {len(files)}",
        f"Findings: {len(findings)}",
        "",
    ]
    if findings:
        md += ["| Path | Kind | Detail | Line |", "|---|---|---|---|"]
        for finding in findings:
            md.append(
                f"| {finding['path']} | {finding['kind']} | `{finding['detail']}` | {finding.get('line', '')} |"
            )
    else:
        md.append(
            "No restricted-publication markers, embedded ZIPs, unexpected binaries, or positive overclaim patterns were found in the public slice."
        )
    (CHECKS / "release_gate_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
