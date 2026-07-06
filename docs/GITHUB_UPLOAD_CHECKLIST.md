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

`v2.2.4 Public Evaluation — IETF 126 Review Packet`

Release settings:

```text
Pre-release: OFF / unchecked
Set as latest: release-manager choice; acceptable for the active public-evaluation entry point
```

Before upload:

1. Apply this repository state at the GitHub repo root.
2. Confirm `ietf126/` exists and includes `run_review_packet.py`, `independent_recompute.py`, `README.md`, `AUTHORIZATION_REF_PROFILE.md`, `DIGEST_INTEROP_NOTES.md`, `NEGATIVE_VECTOR_PLAN.md`, and `schemas/authorization_ref.public-eval.v2.schema.json`.
3. Do not add non-public annexes, claim charts, legal opinions, field-of-use analysis, private implementation mapping, customer data, production logs, credentials, live payment or processor materials, or commercial strategy.
4. Do not add generated cache or run-output directories such as `__pycache__/`, `.pytest_cache/`, `checks/`, `results/`, `ietf126/results/`, `dist/`, or `build/`.
5. Do not describe this release as production software, an official IETF reference implementation, an IETF standard, a certification program, a conformance program, a public trust anchor, or a production non-bypassability proof.
6. Use the exact release asset name `permit-receipt-ref-eval-v2_2_4-public-eval.zip`.
7. Use the exact checksum sidecar name `permit-receipt-ref-eval-v2_2_4-public-eval.zip.sha256`, and make the sidecar line name the ZIP exactly as `permit-receipt-ref-eval-v2_2_4-public-eval.zip`. Do not reuse older sidecar text such as `permit-receipt-main-v2_2_4-ietf126-hardened.zip`.

Pre-upload commands:

```bash
python -m pip install -r requirements.txt
make clean
python make_manifest.py
python verify_manifest.py
python tools/check_ietf126_release_pointers.py
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
make qa
make qa-full
```


Release-asset checksum sidecar:

```bash
sha256sum permit-receipt-ref-eval-v2_2_4-public-eval.zip > permit-receipt-ref-eval-v2_2_4-public-eval.zip.sha256
grep -F "permit-receipt-ref-eval-v2_2_4-public-eval.zip" permit-receipt-ref-eval-v2_2_4-public-eval.zip.sha256
```

Expected checksum sidecar shape:

```text
<64-hex-sha256>  permit-receipt-ref-eval-v2_2_4-public-eval.zip
```

Expected result:

```text
verify_manifest.py: PASS
make qa: PASS
make qa-full: PASS
run_vectors.py: PASS
pytest: PASS
ietf126/run_review_packet.py: PASS
ietf126/independent_recompute.py: PASS
release pointer check: PASS
```

IETF Hackathon page pointer (see `docs/IETF126_RELEASE_POINTER_LOCK.md`):

```text
https://github.com/meridianverity/permit-receipt/tree/main/ietf126
```

IETF release pointer after publishing:

```text
https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.4-public-eval
```

## Manual-upload friendly option

If you are using GitHub Web UI upload and cannot easily select dotfiles, do not block the public evaluation on `.github/` or `.gitignore`. The manifest excludes those optional repository-hygiene files. Upload the visible repository files, then optionally create GitHub Actions and issue templates from `github-ui-files/` using `docs/GITHUB_MANUAL_UPLOAD_GUIDE.md`.
