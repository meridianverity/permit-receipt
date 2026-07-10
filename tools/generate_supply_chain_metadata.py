#!/usr/bin/env python3
"""Generate deterministic SBOM, source provenance, and synthetic attestation metadata."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

try:
    from release_config import ARTIFACT_LABEL, BUILD_DATE, PUBLIC_VERSION, PROJECT_VERSION, TAG
    from source_inventory import STATIC_MANIFEST_FILES, digest_entries, sha256_file, source_entries
except ImportError:  # pragma: no cover
    from tools.release_config import ARTIFACT_LABEL, BUILD_DATE, PUBLIC_VERSION, PROJECT_VERSION, TAG
    from tools.source_inventory import STATIC_MANIFEST_FILES, digest_entries, sha256_file, source_entries

ROOT = Path(__file__).resolve().parents[1]
ATTESTATIONS = ROOT / "attestations"
LOCK = ROOT / "requirements-lock-py313-linux-x86_64.txt"
SBOM = ROOT / "sbom.cdx.json"
SOURCE_PROVENANCE = ATTESTATIONS / "source_provenance.json"
SYNTHETIC = ATTESTATIONS / "synthetic_evaluation_attestation.json"
LOCK_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)==([^\\\s]+)\s+\\\n\s+--hash=sha256:([0-9a-f]{64})\s+#\s+([^\s]+)$",
    re.MULTILINE,
)


def prefixed(path: Path) -> str:
    return "sha256:" + sha256_file(path)


def digest_path_set(paths: list[Path]) -> str:
    import hashlib

    h = hashlib.sha256()
    for path in sorted(paths, key=lambda p: p.relative_to(ROOT).as_posix()):
        rel = path.relative_to(ROOT).as_posix()
        data = path.read_bytes()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(str(len(data)).encode("ascii"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


def parse_lock() -> list[dict[str, str]]:
    text = LOCK.read_text(encoding="utf-8")
    rows = [
        {"name": name, "version": version, "sha256": digest, "wheel": wheel}
        for name, version, digest, wheel in LOCK_RE.findall(text)
    ]
    if not rows:
        raise ValueError("hash lock did not contain any parseable pinned wheel records")
    normalized = {row["name"].lower().replace("_", "-") for row in rows}
    required = {"cryptography", "pytest", "jsonschema", "coverage", "setuptools", "wheel"}
    if not required.issubset(normalized):
        raise ValueError(f"hash lock is missing required packages: {sorted(required - normalized)!r}")
    return rows


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def load_gate_report(path: Path, *, pass_field: str = "ok") -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"required release-gate report is missing: {path.relative_to(ROOT)}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"release-gate report is not an object: {path.relative_to(ROOT)}")
    if value.get(pass_field) is not True:
        raise ValueError(f"release-gate report is not PASS ({pass_field}): {path.relative_to(ROOT)}")
    return value


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


def observed_release_metrics() -> dict[str, object]:
    vectors = json.loads((ROOT / "evaluation_vectors/vectors.json").read_text(encoding="utf-8"))
    if not isinstance(vectors, list):
        raise ValueError("evaluation vector corpus must be a JSON array")

    hybrid = load_gate_report(ROOT / "checks/hybrid_demo_results.json", pass_field="hybrid_ok")
    passport = load_gate_report(ROOT / "ietf126/results/public-review-passport.json")
    recompute = load_gate_report(ROOT / "ietf126/results/independent-recompute-results.json")
    crypto = load_gate_report(ROOT / "ietf126/results/independent-crypto-verification.json")
    coverage = load_gate_report(ROOT / "checks/coverage_gate.json")
    core_coverage = load_gate_report(ROOT / "checks/core_coverage_gate.json")

    hybrid_rows = hybrid.get("hybrid_scenarios")
    critical = core_coverage.get("critical_totals")
    if not isinstance(hybrid_rows, list) or not isinstance(critical, dict):
        raise ValueError("coverage or hybrid release report has an unexpected shape")

    metrics: dict[str, object] = {
        "orprg_evaluation_vectors": len(vectors),
        "strict_pytest_cases": collect_pytest_count(),
        "ietf126_review_checks": int(passport["total"]),
        "independent_recompute_checks": int(recompute["total"]),
        "independent_crypto_checks": int(crypto["total"]),
        "orprg_eval_statement_coverage_percent": round(float(coverage["orprg_eval_statement_percent"]), 4),
        "orprg_eval_branch_coverage_percent": round(float(coverage["orprg_eval_branch_percent"]), 4),
        "repository_combined_coverage_percent": round(float(coverage["overall_combined_percent"]), 4),
        "repository_statement_coverage_percent": round(float(coverage["overall_statement_percent"]), 4),
        "repository_branch_coverage_percent": round(float(coverage["overall_branch_percent"]), 4),
        "security_core_line_coverage_percent": round(float(critical["line_percent"]), 4),
        "security_core_branch_coverage_percent": round(float(critical["branch_percent"]), 4),
        "hybrid_scenarios": len(hybrid_rows),
    }
    if metrics["strict_pytest_cases"] < 300:
        raise ValueError(f"strict test corpus unexpectedly small: {metrics['strict_pytest_cases']}")
    if metrics["orprg_eval_statement_coverage_percent"] < 99.0 or metrics["orprg_eval_branch_coverage_percent"] < 98.0:
        raise ValueError(f"orprg_eval package coverage is below release threshold: {metrics}")
    if metrics["security_core_line_coverage_percent"] < 99.0 or metrics["security_core_branch_coverage_percent"] < 97.5:
        raise ValueError(f"security-core coverage is below release threshold: {metrics}")
    return metrics


def build_sbom(rows: list[dict[str, str]]) -> None:
    components = [
        {
            "type": "application",
            "bom-ref": f"pkg:pypi/permit-receipt-ref-eval@{PROJECT_VERSION}",
            "name": "permit-receipt-ref-eval",
            "version": PROJECT_VERSION,
            "purl": f"pkg:pypi/permit-receipt-ref-eval@{PROJECT_VERSION}",
            "properties": [
                {"name": "permitreceipt:public-version", "value": PUBLIC_VERSION},
                {"name": "permitreceipt:release-tag", "value": TAG},
            ],
        }
    ]
    dependency_refs: list[str] = []
    for row in rows:
        normalized = row["name"].lower().replace("_", "-")
        ref = f"pkg:pypi/{normalized}@{row['version']}"
        dependency_refs.append(ref)
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": normalized,
                "version": row["version"],
                "purl": ref,
                "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                "properties": [
                    {"name": "permitreceipt:locked-wheel", "value": row["wheel"]},
                    {"name": "permitreceipt:lock-platform", "value": "CPython 3.13 / Linux x86_64"},
                ],
            }
        )
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/meridianverity/permit-receipt/{TAG}/sbom")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": f"{BUILD_DATE}T00:00:00Z",
            "component": components[0],
            "tools": {"components": [{"type": "application", "name": "permit-receipt deterministic metadata generator", "version": PROJECT_VERSION}]},
            "properties": [
                {"name": "permitreceipt:artifact", "value": ARTIFACT_LABEL},
                {"name": "permitreceipt:lockfile", "value": LOCK.name},
                {"name": "permitreceipt:lockfile-sha256", "value": sha256_file(LOCK)},
            ],
        },
        "components": components[1:],
        "dependencies": [{"ref": components[0]["bom-ref"], "dependsOn": sorted(dependency_refs)}]
        + [{"ref": ref, "dependsOn": []} for ref in sorted(dependency_refs)],
    }
    write_json(SBOM, sbom)


def build_synthetic_attestation() -> None:
    validators = [
        "orprg_eval/canonicalization.py",
        "orprg_eval/crypto.py",
        "orprg_eval/httpio.py",
        "orprg_eval/jsonio.py",
        "orprg_eval/persistent_replay.py",
        "orprg_eval/replay.py",
        "orprg_eval/schema.py",
        "orprg_eval/timeutil.py",
        "orprg_eval/verifier.py",
        "ietf126/independent_crypto_verify.py",
    ]
    core = {
        "artifact_type": "SyntheticEvaluationAttestation",
        "version": PUBLIC_VERSION,
        "packet": "permit-receipt-ref-eval-v2_2_6-public-eval",
        "issued_at": f"{BUILD_DATE}T00:00:00Z",
        "result": "PASS",
        "subject": {
            "validator_id": f"permit-receipt-ref-eval-v{PUBLIC_VERSION}",
            "validator_components": {rel: prefixed(ROOT / rel) for rel in validators},
        },
        "coverage": {
            **observed_release_metrics(),
            "expected_hybrid_outcomes": {
                "H01_ALLOW_joint_orprg_paygate_provider": "ALLOW",
                "H02_DENY_orprg_scope_before_paygate": "DENY",
                "H03_DENY_paygate_tsil_missing_after_orprg_allow": "DENY",
                "H04_DENY_direct_provider_bypass_without_gate_token": "DENY",
                "H05_DETECT_tetpay_evidence_tamper": "DENY",
            },
            "security_properties": [
                "strict_typed_ingress",
                "duplicate_key_rejection",
                "timezone_invariant_rfc3339",
                "transactional_anti_replay",
                "constrained_mode_mandatory_checks",
                "capability_receipt_binding",
                "signed_authorization_ref_carrier",
            ],
        },
        "evidence": {
            "vectors_digest": prefixed(ROOT / "evaluation_vectors/vectors.json"),
            "policy_digest": prefixed(ROOT / "policy_paygate_domain/paygate_policy_v1.json"),
            "hybrid_examples_digest": digest_path_set(list((ROOT / "examples").glob("h*.json"))),
            "hybrid_examples_digest_method": "sha256 over sorted examples/h*.json path + NUL + byte length + NUL + raw bytes + NUL",
            "dependency_lock_digest": prefixed(LOCK),
            "sbom_digest": prefixed(SBOM),
        },
        "limitations": [
            "synthetic_evaluation_only",
            "not_production_software",
            "no_live_payments",
            "no_pan_or_sad",
            "not_an_ietf_standard_or_endorsement",
            "not_a_certification_or_conformance_program",
            "no_patent_license_grant",
        ],
        "validity": {
            "not_before": f"{BUILD_DATE}T00:00:00Z",
            "not_after": "2027-01-31T23:59:59Z",
            "revocation_reference": "synthetic://permit-receipt-ref/v2.2.6/evaluation/status",
        },
    }
    attestation = {
        "attestation_core": core,
        "integrity_note": {
            "type": "synthetic_public_evaluation_metadata",
            "description": "Reproducibility metadata only; not a production attestation, security warranty, compliance approval, certification output, or trust anchor.",
            "canonical_note": "No patent license, trademark license, service mark license, product implementation right, certification right, conformance-program right, compliance approval, or endorsement is granted.",
        },
    }
    write_json(SYNTHETIC, attestation)


def build_source_provenance() -> None:
    exclusions = set(STATIC_MANIFEST_FILES) | {SOURCE_PROVENANCE.relative_to(ROOT).as_posix()}
    entries = source_entries(ROOT, extra_exclude_files=exclusions)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": ARTIFACT_LABEL, "digest": {"sha256": digest_entries(entries)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://meridianverity.com/buildtypes/permit-receipt-source-slice/v1",
                "externalParameters": {"tag": TAG, "version": PUBLIC_VERSION},
                "internalParameters": {
                    "inventory_algorithm": "sorted path + NUL + decimal byte length + NUL + lowercase SHA-256 + NUL",
                    "excluded_self": SOURCE_PROVENANCE.relative_to(ROOT).as_posix(),
                    "excluded_static_manifests": sorted(STATIC_MANIFEST_FILES),
                },
                "resolvedDependencies": [
                    {"uri": LOCK.name, "digest": {"sha256": sha256_file(LOCK)}},
                    {"uri": SBOM.relative_to(ROOT).as_posix(), "digest": {"sha256": sha256_file(SBOM)}},
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/meridianverity/permit-receipt/tools/generate_supply_chain_metadata.py"},
                "metadata": {"invocationId": TAG, "startedOn": f"{BUILD_DATE}T00:00:00Z", "finishedOn": f"{BUILD_DATE}T00:00:00Z"},
                "byproducts": [
                    {"name": "source-entry-count", "content": str(len(entries))},
                    {"name": "commit-binding", "content": "This statement binds the deterministic source-tree digest. Final publication must additionally bind the exact Git commit in the external release provenance and signed tag."},
                ],
            },
        },
    }
    write_json(SOURCE_PROVENANCE, statement)


def main() -> int:
    ATTESTATIONS.mkdir(exist_ok=True)
    rows = parse_lock()
    build_sbom(rows)
    build_synthetic_attestation()
    build_source_provenance()
    report = {
        "ok": True,
        "dependencies": len(rows),
        "sbom": SBOM.relative_to(ROOT).as_posix(),
        "sbom_sha256": sha256_file(SBOM),
        "synthetic_attestation": SYNTHETIC.relative_to(ROOT).as_posix(),
        "synthetic_attestation_sha256": sha256_file(SYNTHETIC),
        "source_provenance": SOURCE_PROVENANCE.relative_to(ROOT).as_posix(),
        "source_provenance_sha256": sha256_file(SOURCE_PROVENANCE),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
