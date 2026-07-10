# Git Update Checklist — v2.2.6-public-eval

## Local preflight

```bash
git status --short
python run_vectors.py
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python ietf126/independent_crypto_verify.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONWARNINGS=error python -m pytest -q
make coverage
python tools/make_public_manifest.py
python verify_manifest.py
python tools/validate_public_eval_packet.py
python tools/check_release_lineage.py
python tools/check_ietf126_release_pointers.py
```

## Commit and immutable tag

```bash
git add .
git commit -m "v2.2.6 fail-closed profile and interoperability hardening"
git tag -a v2.2.6-public-eval -m "PermitReceipt public evaluation v2.2.6 — IETF 126 review artifact"
git push origin main
git push origin v2.2.6-public-eval
```

## Build and verify assets

```bash
python tools/build_release_asset.py --out-dir ../v226-release
python tools/verify_release_artifact.py \
  ../v226-release/permit-receipt-ref-eval-v2_2_6-public-eval.zip \
  ../v226-release/permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
```

Attach exactly:

```text
permit-receipt-ref-eval-v2_2_6-public-eval.zip
permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
```

After upload, download both public assets, verify the sidecar, and run the reviewer fast path from the downloaded ZIP.

## External pointer

Update the IETF 126 Hackathon entry to:

```text
https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

Reopen the rendered page to verify it. Do not infer success from repository-local files.

## No same-tag byte replacement

Do not force-update the tag or replace either asset after publication. A correction requires the next fresh public-evaluation tag.
