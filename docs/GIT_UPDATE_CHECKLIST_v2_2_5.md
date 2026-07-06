# Git Update Checklist — v2.2.5-public-eval

Use this when applying the v2.2.5 fresh-tag packet to the public repository.

## Local preflight

```bash
git status --short
python tools/make_public_manifest.py
python verify_manifest.py
python tools/validate_public_eval_packet.py
python tools/check_release_lineage.py
python tools/check_ietf126_release_pointers.py
make qa-full
```

## Commit and tag

```bash
git add .
git commit -m "v2.2.5 public evaluation release-lineage hardening"
git tag -a v2.2.5-public-eval -m "PermitReceipt public evaluation v2.2.5 — IETF 126 review artifact"
git push origin main
git push origin v2.2.5-public-eval
```

## Build release asset

```bash
python tools/build_release_asset.py --out-dir ../v225_out
python tools/verify_release_artifact.py ../v225_out/permit-receipt-ref-eval-v2_2_5-public-eval.zip ../v225_out/permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
```

## Release asset

Attach exactly:

```text
permit-receipt-ref-eval-v2_2_5-public-eval.zip
permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
```

Do not attach a ZIP or sidecar bearing a superseded asset name.

## No same-tag byte replacement

After publication, do not force-update the tag and do not replace the asset bytes while preserving the same canonical pointer. If a correction is needed, publish the next fresh public-evaluation tag.
