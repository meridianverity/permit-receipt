# Release Publishing Protocol — v2.2.6-public-eval

## 1. Verify the source tree

From a clean checkout:

```bash
python -m pip install --require-hashes -r requirements-lock-py313-linux-x86_64.txt
make clean
python run_vectors.py
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python ietf126/independent_crypto_verify.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONWARNINGS=error python -m pytest -q
python tools/check_core_coverage.py
python tools/make_public_manifest.py
python verify_manifest.py
python tools/validate_public_eval_packet.py
python tools/check_release_lineage.py
python tools/check_ietf126_release_pointers.py
```

## 2. Build the deterministic asset

```bash
python tools/build_release_asset.py --out-dir ../v226-release
python tools/verify_release_artifact.py \
  ../v226-release/permit-receipt-ref-eval-v2_2_6-public-eval.zip \
  ../v226-release/permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256 \
  --manifest ../v226-release/permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json \
  --provenance ../v226-release/permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
```

Build a second time in a separate directory and require byte equality.

## 3. Reverify the packaged public bytes

Extract the first ZIP into a fresh directory, install the locked QA environment, and rerun the full gate from the extraction. Verify that the source manifest and reviewer outputs pass without access to the original worktree.

## 4. Publish exactly this tuple

```text
Tag:        v2.2.6-public-eval
Asset:      permit-receipt-ref-eval-v2_2_6-public-eval.zip
Sidecar:    permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
Manifest:   permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json
Provenance: permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
Release:  https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

Leave the GitHub pre-release checkbox unchecked when this is the active public-evaluation entry point.

## 5. Verify the public download

After publication, download all four assets from the release page and verify:

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
```

Then extract and rerun the selected reviewer packet. Compare the public bytes with the locally verified asset.

## 6. Update external pointers

Update the IETF 126 Hackathon project entry to the exact release URL, then reopen the rendered public page and confirm the tag. Repository-local checks cannot prove an external wiki was edited.

## No same-tag replacement

After publication, any changed byte requires a new tag and a new four-asset tuple. Never refresh an existing public release asset under the same tag.

## Boundary

This protocol supports synthetic public technical review only. It does not create production authorization, certification, conformance-program status, commercial rights, or patent-license rights.
