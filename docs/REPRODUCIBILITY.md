# Reproducibility

The public evaluation slice is designed for clean-extract reproducibility.

## Clean run

```bash
python -m pip install -r requirements.txt
make clean
make qa
```

Expected high-level outcomes:

```text
public evaluation harness: PASS
release gate: PASS
packet validation: PASS
strict manifest verification: PASS
ORPRG evaluation vectors: 65 / 65 PASS
pytest suite: PASS
```

## Manifest model

`MANIFEST.sha256.json` covers static source and provenance files. Generated run-output directories are intentionally excluded:

```text
checks/
results/
.pytest_cache/
__pycache__/
dist/
build/
tmp/
```

`verify_manifest.py` checks both hash integrity and static-file completeness for the included static scope.

## Determinism note

The vector expectations are deterministic for the synthetic inputs and included policy state. This does not imply production security, production compliance, certification, or production non-bypassability.


## Release asset verification

The full ZIP archive digest is carried outside the archive in the release sidecar, because embedding the full-archive digest inside the archive would be circular.

After download, verify the publication-time sidecar from the directory containing both files:

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
```

Expected sidecar line:

The generated `.sha256` file contains exactly one line: the final publication-time SHA-256 value, two spaces, and `permit-receipt-ref-eval-v2_2_5-public-eval.zip`. Copy the generated line exactly; do not publish a placeholder digest.
