#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

try:
    from release_config import ARTIFACT_LABEL
except ImportError:  # pragma: no cover
    from tools.release_config import ARTIFACT_LABEL

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = [
    "README.md", "README_FIRST.md", "GLOSSARY.md", "QUICKSTART.md", "NOTICE.md",
    "LICENSE-EVALUATION.md", "PATENT-NOTICE.md", "SECURITY.md", "CONTRIBUTING.md", "VERSION",
    "RELEASE_NOTES_v2_2_6.md", "docs/EVALUATION_BOUNDARY.md", "docs/STANDARDS_STATUS_AND_IPR.md",
    "docs/PUBLIC_REVIEWER_GUIDE.md", "docs/REPRODUCIBILITY.md", "docs/IETF_HACKATHON_PROJECT_PAGE.md",
    "docs/IETF126_RELEASE_POINTER_LOCK.md", "docs/RELEASE_DECISION_RECORD_v2_2_6.md",
    "docs/GIT_UPDATE_CHECKLIST_v2_2_6.md", "docs/RELEASE_LINEAGE_v2_2_6.md",
    "docs/RELEASE_PUBLISHING_PROTOCOL_v2_2_6.md", "docs/RELEASE_PROVENANCE_AND_ASSET_BINDING.md",
    "docs/REVIEWER_FAST_PATH_v2_2_6.md", "docs/QA_REPORT_v2_2_6_PUBLIC_EVAL.md",
    "docs/VERSION_TAXONOMY.md", "docs/SECURITY_HARDENING_v2_2_6.md",
    "tools/release_config.py", "tools/release_gate.py", "tools/check_release_lineage.py",
    "tools/check_ietf126_release_pointers.py", "tools/build_release_asset.py",
    "tools/verify_release_artifact.py", "tools/run_public_eval.py", "tools/check_core_coverage.py",
    "tools/source_inventory.py", "tools/generate_supply_chain_metadata.py", "tools/static_security_scan.py",
    "evaluation_vectors/vectors.json", "ietf126/README.md", "ietf126/run_review_packet.py",
    "ietf126/independent_recompute.py", "ietf126/independent_crypto_verify.py",
    "ietf126/AUTHORIZATION_REF_PROFILE.md", "ietf126/DIGEST_INTEROP_NOTES.md",
    "ietf126/NEGATIVE_VECTOR_PLAN.md", "ietf126/schemas/authorization_ref.public-eval.v2.schema.json",
    "ietf126/schemas/authorization_ref_carrier.public-eval.v1.schema.json",
    "schemas/permit_receipt.schema.json", "schemas/capability_token.schema.json",
    "schemas/revocation_state.schema.json", "attestations/synthetic_evaluation_attestation.json",
    "requirements-lock-py313-linux-x86_64.txt", "sbom.cdx.json",
    "attestations/source_provenance.json",
]
REQUIRED_README_PHRASES = [
    "Synthetic source-available evaluation artifact", "It is not production software",
    "not an IETF standard", "not an official IETF reference implementation",
    "not a certification program", "not a conformance program", "grants no patent license",
]


def _run(rel: str) -> int:
    return subprocess.call([sys.executable, str(ROOT / rel)], cwd=ROOT)


def main() -> int:
    missing = [rel for rel in REQUIRED_FILES if not (ROOT / rel).is_file()]
    readme = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""
    missing_phrases = [phrase for phrase in REQUIRED_README_PHRASES if phrase not in readme]
    release_gate_rc = _run("tools/release_gate.py")
    lineage_rc = _run("tools/check_release_lineage.py")
    pointer_rc = _run("tools/check_ietf126_release_pointers.py")
    report = {
        "ok": not missing and not missing_phrases and release_gate_rc == 0 and lineage_rc == 0 and pointer_rc == 0,
        "missing": missing,
        "missing_readme_phrases": missing_phrases,
        "release_gate_exit": release_gate_rc,
        "release_lineage_check_exit": lineage_rc,
        "release_pointer_check_exit": pointer_rc,
        "artifact": ARTIFACT_LABEL,
    }
    (ROOT / "checks").mkdir(exist_ok=True)
    (ROOT / "checks/public_packet_validation.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
