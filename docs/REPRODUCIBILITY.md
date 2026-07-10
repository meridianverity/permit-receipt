# Reproducibility

The public evaluation slice is designed for deterministic source manifests, reproducible test evidence, and byte-identical release builds.

## Certified clean source-tree gate (CPython 3.13 / Linux x86_64)

```bash
python -m pip install --require-hashes -r requirements-lock-py313-linux-x86_64.txt
python -m pip install --no-build-isolation -e . --no-deps
python tools/generate_supply_chain_metadata.py
python tools/make_public_manifest.py
make clean
make qa-full
```

For other supported platforms, `requirements.txt` is the portable compatibility path and is not described as byte-for-byte hash locked.

Expected high-level outcomes:

```text
public evaluation harness: PASS
release, lineage, and pointer gates: PASS
static manifest verification: PASS
ORPRG evaluation vectors: 76 / 76 PASS
strict pytest: 323 / 323 PASS
security-core coverage gate: PASS
```

## Static manifest model

`MANIFEST.sha256.json` covers the static source and provenance slice. Generated run-output, cache, coverage, build, and distribution directories are excluded. `verify_manifest.py` checks both digest integrity and static-file completeness.

## Deterministic release tuple

Build twice in separate directories:

```bash
python tools/build_release_asset.py --out-dir /tmp/permit-a
python tools/build_release_asset.py --out-dir /tmp/permit-b
```

The ZIP, checksum sidecar, asset manifest, and provenance statement must be byte-identical between builds. The full ZIP digest is carried outside the archive to avoid circular self-reference.

After download:

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
```

## Boundary

Deterministic synthetic evidence does not imply production security, deployment non-bypassability, compliance approval, certification, IETF endorsement, or a patent-license grant.
