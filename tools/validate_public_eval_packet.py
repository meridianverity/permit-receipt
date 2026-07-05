#!/usr/bin/env python3
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    'README.md',
    'README_FIRST.md',
    'GLOSSARY.md',
    'QUICKSTART.md',
    'NOTICE.md',
    'LICENSE-EVALUATION.md',
    'PATENT-NOTICE.md',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'docs/EVALUATION_BOUNDARY.md',
    'docs/STANDARDS_STATUS_AND_IPR.md',
    'docs/PUBLIC_REVIEWER_GUIDE.md',
    'docs/REPRODUCIBILITY.md',
    'docs/IETF_HACKATHON_PROJECT_PAGE.md',
    'docs/IETF126_RELEASE_POINTER_LOCK.md',
    'tools/release_gate.py',
    'tools/run_public_eval.py',
    'tools/check_ietf126_release_pointers.py',
    'evaluation_vectors/vectors.json',
    'ietf126/README.md',
    'ietf126/run_review_packet.py',
    'ietf126/independent_recompute.py',
    'ietf126/AUTHORIZATION_REF_PROFILE.md',
    'ietf126/DIGEST_INTEROP_NOTES.md',
    'ietf126/NEGATIVE_VECTOR_PLAN.md',
    'ietf126/schemas/authorization_ref.public-eval.v2.schema.json',
    'attestations/synthetic_evaluation_attestation.json',
]

REQUIRED_README_PHRASES = [
    'Synthetic source-available evaluation artifact',
    'It is not production software',
    'not an IETF standard',
    'not an official IETF reference implementation',
    'not a certification program',
    'not a conformance program',
    'grants no patent license',
]


def main() -> int:
    missing = [p for p in REQUIRED_FILES if not (ROOT/p).exists()]
    readme = (ROOT/'README.md').read_text(encoding='utf-8') if (ROOT/'README.md').exists() else ''
    missing_phrases = [phrase for phrase in REQUIRED_README_PHRASES if phrase not in readme]
    rc = subprocess.call([sys.executable, str(ROOT/'tools/release_gate.py')])
    pointer_rc = subprocess.call([sys.executable, str(ROOT/'tools/check_ietf126_release_pointers.py')])
    report = {
        'ok': not missing and not missing_phrases and rc == 0 and pointer_rc == 0,
        'missing': missing,
        'missing_readme_phrases': missing_phrases,
        'release_gate_exit': rc,
        'release_pointer_check_exit': pointer_rc,
        'artifact': 'PermitReceipt Public Evaluation Slice v2.2.4',
    }
    (ROOT/'checks').mkdir(exist_ok=True)
    (ROOT/'checks'/'public_packet_validation.json').write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
