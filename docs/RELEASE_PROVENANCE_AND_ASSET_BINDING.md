# Release Provenance and Asset Binding — v2.2.6-public-eval

## Canonical immutable tuple

```text
Tag:        v2.2.6-public-eval
Asset:      permit-receipt-ref-eval-v2_2_6-public-eval.zip
Sidecar:    permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
Manifest:   permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json
Provenance: permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
Release:    https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

The reviewer pointer is this complete tuple, not the tag name alone. v2.2.6 supersedes v2.2.5 for active review-reference purposes; the older tag and assets remain immutable historical evidence.

## Verification after download

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
unzip -q permit-receipt-ref-eval-v2_2_6-public-eval.zip
cd permit-receipt-main
python tools/verify_release_artifact.py \
  ../permit-receipt-ref-eval-v2_2_6-public-eval.zip \
  ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256 \
  --manifest ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json \
  --provenance ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
python -m pip install -r requirements.txt
make qa-full
```

Expected high-level evidence:

```text
IETF review packet:           20 / 20 PASS
Independent recomputation:    17 / 17 PASS
Independent crypto:           19 / 19 PASS
Evaluation vectors:           76 / 76 PASS
Strict pytest:               323 / 323 PASS
```

## Immutable-publication rule

After publication, do not force-update the tag or replace any of the four assets. Every changed byte requires a fresh tag, asset names, sidecar, manifest, provenance statement, and external pointer update.

## Boundary

This note concerns public artifact reproducibility and review hygiene. It is not a certification program, conformance program, endorsement, production authorization, or patent-license grant.
