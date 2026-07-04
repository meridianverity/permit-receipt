# GitHub Upload Checklist — v2.2.4-public-eval

Repository title suggestion:

`PermitReceipt Public Evaluation Slice for AI-Agent External Effects`

Repository name:

`permit-receipt`

Repository description suggestion:

`Synthetic source-available public evaluation artifact for PermitReceipt permit-before-commit external-effect authorization using action digests, policy epochs, status/recency checks, anti-replay, fail-closed denial, deterministic public vectors, and IETF 126 review materials.`

Release tag:

`v2.2.4-public-eval`

Release title:

`PermitReceipt Public Evaluation Slice v2.2.4 — IETF 126 Review Artifact`

Release settings:

```text
Pre-release: ON
Set as latest: OFF
```

Before upload:

1. Apply this repository state at the GitHub repo root.
2. Confirm `ietf126/` exists and includes `run_review_packet.py`, `README.md`, `AUTHORIZATION_REF_PROFILE.md`, `DIGEST_INTEROP_NOTES.md`, `NEGATIVE_VECTOR_PLAN.md`, and `schemas/authorization_ref.public-eval.v2.schema.json`.
3. Do not add non-public annexes, claim charts, legal opinions, field-of-use analysis, private implementation mapping, customer data, production logs, credentials, live payment or processor materials, or commercial strategy.
4. Do not add generated cache or run-output directories such as `__pycache__/`, `.pytest_cache/`, `checks/`, `results/`, `ietf126/results/`, `dist/`, or `build/`.
5. Do not describe this release as production software, stable production software, an official IETF reference implementation, an IETF standard, a certification program, a conformance program, a public trust anchor, or a production non-bypassability proof.

Pre-upload commands:

```bash
python -m pip install -r requirements.txt
make clean
python make_manifest.py
python verify_manifest.py
make qa
python run_vectors.py
python -m pytest -q
```

Expected result:

```text
verify_manifest.py: PASS
make qa: PASS
run_vectors.py: PASS
pytest: PASS
ietf126/run_review_packet.py: PASS
```

IETF Hackathon page pointer:

```text
https://github.com/meridianverity/permit-receipt/tree/main/ietf126
```

IETF release pointer after publishing:

```text
https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.4-public-eval
```
