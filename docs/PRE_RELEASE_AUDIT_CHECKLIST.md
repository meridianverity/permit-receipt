# Pre-Release Audit Checklist

Use this checklist before publishing any public evaluation slice.

## 1. Scope and boundary

- Confirm the artifact is labeled `synthetic`, `public evaluation`, and `non-production`.
- Confirm the README states: not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and no patent license.
- Confirm `PATENT-NOTICE.md`, `LICENSE-EVALUATION.md`, `NOTICE.md`, and `docs/SECURITY_AND_LIMITATIONS.md` are present.
- Confirm `GLOSSARY.md`, `docs/TERMINOLOGY_AND_BOUNDARY_GUIDE.md`, `docs/EVALUATION_BOUNDARY.md`, `docs/STANDARDS_STATUS_AND_IPR.md`, `docs/PUBLIC_REVIEWER_GUIDE.md`, `docs/REPRODUCIBILITY.md`, and `docs/PUBLIC_STEWARDSHIP.md` are present.

## 2. No restricted material

Do not include:

- live payment credentials;
- PAN/SAD or cardholder-data samples;
- production checkout configuration;
- production processor integrations;
- non-public legal mapping materials;
- patent claim charts;
- commercial strategy materials;
- customer or partner deployment materials;
- production key-management design;
- no certificate registry operations;
- signed conformance/certification corpus.

## 3. Clean package hygiene

Remove before packaging:

```bash
rm -rf checks results .pytest_cache __pycache__ */__pycache__ */*/__pycache__ tmp dist build .mypy_cache
find . -name '*.pyc' -delete
```

## 4. Local verification

Run:

```bash
python -m pip install -r requirements.txt
make eval
make validate
make manifest
make verify
```

Expected:

- public evaluation harness: PASS;
- ORPRG public evaluation vectors: 64/64 PASS;
- pytest: PASS;
- release gate: PASS;
- packet validation: PASS;
- strict manifest verification: PASS.

## 5. Upload posture

- GitHub release: mark as **Pre-release**.
- Do not mark as `Latest` if a stable release semantics could be inferred.
- Release title should include `Public Evaluation Slice` and `IETF Discussion Artifact`.
- Attach the ZIP and SHA-256 file only.
- Do not attach patent PDFs, claim charts, legal analyses, partner materials, or private annexes.

## 6. Human review gate

Before broader promotion, perform counsel/IP/trademark/public-disclosure review. This checklist is not legal advice.
