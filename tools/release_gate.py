#!/usr/bin/env python3
"""Fail-closed structural, publication-boundary, and metadata release gate."""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tomllib
from xml.parsers import expat
from pathlib import Path
from typing import Any

try:
    from release_config import ARTIFACT_LABEL, PUBLIC_VERSION, TAG
    from source_inventory import iter_source_files, sha256_file
except ImportError:  # pragma: no cover
    from tools.release_config import ARTIFACT_LABEL, PUBLIC_VERSION, TAG
    from tools.source_inventory import iter_source_files, sha256_file

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
CHECKS.mkdir(exist_ok=True)
SKIP_CONTENT = {
    "tools/release_gate.py",
    "tools/static_security_scan.py",
    "docs/KNOWN_ISSUES_v2_2_5.md",
    "PermitReceipt_v2.2.5_Aggressive_Audit_2026-07-10.md",
}
ALLOWED_BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".pdf"}
FORBIDDEN_PATH_FRAGMENTS = (
    "restricted_diligence",
    "restricted_annex",
    "legal_private",
    "nonpublic_strategy",
    "production_secret",
    "live_processor",
    "cardholder_data",
)
FORBIDDEN_CONTENT_PATTERNS = (
    r"private\s+diligence",
    r"production\s+processor\s+credential",
    r"live\s+processor\s+credential",
    r"raw\s+card\s+data",
)
OVERCLAIM_PATTERNS = (
    r"production[-\s]+ready",
    r"production[-\s]+grade",
    r"certified\s+production",
    r"official\s+IETF\s+reference\s+implementation",
    r"official\s+IETF\s+implementation",
    r"IETF[-\s]+endorsed",
    r"\bIETF\s+standard\b",
    r"\breference\s+implementation\b",
    r"public\s+trust\s+anchor",
    r"certificate\s+registry",
    r"conformance\s+program",
    r"certification\s+program",
    r"compliance\s+certification",
    r"production\s+authorization\s+boundary",
    r"proves\s+production\s+non[-\s]+bypassability",
    r"\bflawless\b",
    r"99\.9+%?",
    r"#1\s+(?:at|in|global)",
)
NEGATION_MARKERS = (
    "not ", "no ", "does not ", "do not ", "is not ", "are not ", "without ",
    "excludes ", "no claim", "cannot claim", "must not claim", "overclaim",
    "avoid ", "avoid:",
)


def duplicate_rejecting_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member {key!r}")
        value[key] = item
    return value


def overclaim_is_negated(line: str, start: int) -> bool:
    before = line[max(0, start - 120):start].lower()
    whole = line.lower()
    return any(marker in before or marker in whole for marker in NEGATION_MARKERS)


def collect_pytest_count() -> int:
    env = dict(os.environ)
    env.update({
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONWARNINGS": "error",
    })
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = completed.stdout + "\n" + completed.stderr
    if completed.returncode != 0:
        raise RuntimeError(f"pytest collection failed ({completed.returncode}): {output[-2000:]}")
    match = re.search(r"(?m)^(\d+) tests? collected(?: in [^\n]+)?$", output.strip())
    if match:
        return int(match.group(1))
    node_ids = [line for line in completed.stdout.splitlines() if "::" in line and not line.startswith("=")]
    if node_ids:
        return len(node_ids)
    raise ValueError("unable to determine collected pytest count")


def numeric_metric_at_least(
    coverage: dict[str, object],
    name: str,
    minimum: float,
    findings: list[dict[str, object]],
    path: Path,
) -> None:
    observed = coverage.get(name)
    if isinstance(observed, bool) or not isinstance(observed, (int, float)) or float(observed) < minimum:
        findings.append({
            "path": path.relative_to(ROOT).as_posix(),
            "kind": "attestation_metric_below_minimum",
            "detail": f"{name}: minimum {minimum}, observed {observed!r}",
        })


def check_attestation(findings: list[dict[str, object]]) -> None:
    path = ROOT / "attestations/synthetic_evaluation_attestation.json"
    try:
        attestation = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=duplicate_rejecting_pairs)
        core = attestation["attestation_core"]
    except Exception as exc:
        findings.append({"path": path.relative_to(ROOT).as_posix(), "kind": "attestation_invalid", "detail": str(exc)})
        return
    if core.get("version") != PUBLIC_VERSION:
        findings.append({"path": path.relative_to(ROOT).as_posix(), "kind": "attestation_version_mismatch", "detail": repr(core.get("version"))})
    if core.get("result") != "PASS":
        findings.append({"path": path.relative_to(ROOT).as_posix(), "kind": "attestation_result_not_pass", "detail": repr(core.get("result"))})
    coverage = core.get("coverage") or {}
    try:
        vector_count = len(json.loads((ROOT / "evaluation_vectors/vectors.json").read_text(encoding="utf-8"), object_pairs_hook=duplicate_rejecting_pairs))
    except Exception as exc:
        findings.append({"path": "evaluation_vectors/vectors.json", "kind": "vector_corpus_invalid", "detail": str(exc)})
    else:
        if coverage.get("orprg_evaluation_vectors") != vector_count:
            findings.append({"path": path.relative_to(ROOT).as_posix(), "kind": "attestation_vector_count_mismatch", "detail": f"expected {vector_count}, observed {coverage.get('orprg_evaluation_vectors')!r}"})
    try:
        pytest_count = collect_pytest_count()
    except Exception as exc:
        findings.append({"path": "tests", "kind": "pytest_collection_failed", "detail": str(exc)})
    else:
        if coverage.get("strict_pytest_cases") != pytest_count:
            findings.append({
                "path": path.relative_to(ROOT).as_posix(),
                "kind": "attestation_test_count_mismatch",
                "detail": f"expected {pytest_count}, observed {coverage.get('strict_pytest_cases')!r}",
            })

    for metric, minimum in (
        ("strict_pytest_cases", 300),
        ("ietf126_review_checks", 20),
        ("independent_recompute_checks", 17),
        ("independent_crypto_checks", 19),
        ("orprg_eval_statement_coverage_percent", 99.0),
        ("orprg_eval_branch_coverage_percent", 98.0),
        ("security_core_line_coverage_percent", 99.0),
        ("security_core_branch_coverage_percent", 97.5),
        ("hybrid_scenarios", 5),
    ):
        numeric_metric_at_least(coverage, metric, minimum, findings, path)
    for rel, expected in ((core.get("subject") or {}).get("validator_components") or {}).items():
        target = ROOT / rel
        observed = "sha256:" + sha256_file(target) if target.is_file() else "missing"
        if observed != expected:
            findings.append({"path": rel, "kind": "attestation_component_digest_mismatch", "detail": f"expected {expected}, observed {observed}"})
    evidence = core.get("evidence") or {}
    for field, rel in (
        ("vectors_digest", "evaluation_vectors/vectors.json"),
        ("policy_digest", "policy_paygate_domain/paygate_policy_v1.json"),
        ("dependency_lock_digest", "requirements-lock-py313-linux-x86_64.txt"),
        ("sbom_digest", "sbom.cdx.json"),
    ):
        target = ROOT / rel
        observed = "sha256:" + sha256_file(target) if target.is_file() else "missing"
        if evidence.get(field) != observed:
            findings.append({"path": path.relative_to(ROOT).as_posix(), "kind": "attestation_evidence_digest_mismatch", "detail": f"{field}: expected {evidence.get(field)}, observed {observed}"})


def check_sbom(findings: list[dict[str, object]]) -> None:
    path = ROOT / "sbom.cdx.json"
    try:
        sbom = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=duplicate_rejecting_pairs)
    except Exception as exc:
        findings.append({"path": path.relative_to(ROOT).as_posix(), "kind": "sbom_invalid", "detail": str(exc)})
        return
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        findings.append({"path": path.relative_to(ROOT).as_posix(), "kind": "sbom_profile_mismatch", "detail": repr((sbom.get("bomFormat"), sbom.get("specVersion")))})
    components = sbom.get("components")
    if not isinstance(components, list) or len(components) < 10:
        findings.append({"path": path.relative_to(ROOT).as_posix(), "kind": "sbom_component_count_too_low", "detail": repr(len(components) if isinstance(components, list) else None)})


def parse_xml_without_dtd_or_entities(text: str) -> None:
    """Parse XML while rejecting DTDs, entity declarations, and external entities."""
    parser = expat.ParserCreate()

    def reject_declaration(*_args: object) -> None:
        raise ValueError("DTD/entity declarations are forbidden in the public slice")

    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = lambda *_args: 0
    parser.Parse(text, True)


def main() -> int:
    findings: list[dict[str, object]] = []
    files: list[dict[str, object]] = []
    schema_ids: dict[str, str] = {}
    for rel_path, path in iter_source_files(ROOT):
        rel = rel_path.as_posix()
        files.append({"path": rel, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
        lower = rel.lower()
        if path.stat().st_size > 10 * 1024 * 1024:
            findings.append({"path": rel, "kind": "file_too_large", "detail": str(path.stat().st_size)})
        if path.suffix.lower() == ".zip":
            findings.append({"path": rel, "kind": "embedded_zip", "detail": "ZIP files may not be nested in the public slice"})
        for fragment in FORBIDDEN_PATH_FRAGMENTS:
            if fragment in lower:
                findings.append({"path": rel, "kind": "forbidden_path_fragment", "detail": fragment})
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            if path.suffix.lower() not in ALLOWED_BINARY_EXTS:
                findings.append({"path": rel, "kind": "unexpected_binary", "detail": path.suffix})
            continue
        if b"\r" in raw:
            findings.append({"path": rel, "kind": "non_lf_line_endings", "detail": "CR byte observed"})
        if raw and not raw.endswith(b"\n"):
            findings.append({"path": rel, "kind": "missing_final_newline", "detail": "text file must end with LF"})
        if rel not in SKIP_CONTENT:
            for pattern in FORBIDDEN_CONTENT_PATTERNS:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    findings.append({"path": rel, "kind": "forbidden_content_pattern", "detail": pattern})
            for pattern in OVERCLAIM_PATTERNS:
                for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                    line_start = text.rfind("\n", 0, match.start()) + 1
                    line_end = text.find("\n", match.end())
                    line_end = len(text) if line_end < 0 else line_end
                    line = text[line_start:line_end]
                    if not overclaim_is_negated(line, match.start() - line_start):
                        findings.append({"path": rel, "kind": "positive_overclaim_pattern", "detail": pattern, "line": line.strip()[:240]})
        try:
            if path.suffix == ".py":
                ast.parse(text, filename=rel)
            elif path.suffix == ".json":
                value = json.loads(text, object_pairs_hook=duplicate_rejecting_pairs)
                if isinstance(value, dict) and isinstance(value.get("$id"), str):
                    schema_id = value["$id"]
                    if schema_id in schema_ids:
                        findings.append({"path": rel, "kind": "duplicate_json_schema_id", "detail": f"also in {schema_ids[schema_id]}"})
                    else:
                        schema_ids[schema_id] = rel
            elif path.suffix == ".toml":
                tomllib.loads(text)
            elif path.suffix == ".xml":
                parse_xml_without_dtd_or_entities(text)
            elif path.suffix in {".yml", ".yaml"} and "\t" in text:
                findings.append({"path": rel, "kind": "yaml_tab_indentation", "detail": "tab character observed"})
        except Exception as exc:
            findings.append({"path": rel, "kind": "structural_parse_error", "detail": f"{type(exc).__name__}: {exc}"})
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip() if (ROOT / "VERSION").exists() else None
    if version != PUBLIC_VERSION:
        findings.append({"path": "VERSION", "kind": "version_mismatch", "detail": f"expected {PUBLIC_VERSION}, observed {version}"})
    if TAG not in (ROOT / "README.md").read_text(encoding="utf-8"):
        findings.append({"path": "README.md", "kind": "active_tag_missing", "detail": TAG})
    check_sbom(findings)
    check_attestation(findings)
    report = {
        "artifact": ARTIFACT_LABEL,
        "version": PUBLIC_VERSION,
        "ok": not findings,
        "file_count": len(files),
        "finding_count": len(findings),
        "findings": findings,
    }
    (CHECKS / "release_gate_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    md = ["# Release Gate Report", "", f"Status: **{'PASS' if report['ok'] else 'FAIL'}**", "", f"Files scanned: {len(files)}", f"Findings: {len(findings)}", ""]
    if findings:
        md.extend(["| Path | Kind | Detail |", "|---|---|---|"])
        for finding in findings:
            md.append(f"| {finding.get('path', '')} | {finding['kind']} | `{str(finding.get('detail', ''))[:200]}` |")
    else:
        md.append("All structural, publication-boundary, metadata-binding, and overclaim checks passed.")
    (CHECKS / "release_gate_report.md").write_text("\n".join(md) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
