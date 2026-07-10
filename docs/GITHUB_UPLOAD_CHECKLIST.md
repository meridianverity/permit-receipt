# GitHub Upload Checklist — v2.2.6-public-eval

## Exact publication identity

```text
Repository:   meridianverity/permit-receipt
Tag:          v2.2.6-public-eval
Title:        v2.2.6 Public Evaluation — IETF 126 Review Packet
ZIP:          permit-receipt-ref-eval-v2_2_6-public-eval.zip
Checksum:     permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
Manifest:     permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json
Provenance:   permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
Release URL:  https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

`v2.2.6-public-eval` is the intended active public-evaluation entry point. The pre-release checkbox should be **unchecked**. Marking it `Latest` is appropriate only after the four public assets have been downloaded and independently reverified.

## Before creating the tag

1. Apply the reviewed source tree at the repository root.
2. Materialize `.github/` from `github-ui-files/` when publishing through a workflow that omits dotfiles.
3. Confirm that no private annex, legal opinion, claim chart, customer data, production log, credential, live payment/processor material, regulated data, or commercial strategy is present.
4. Confirm that generated directories are absent: `__pycache__/`, `.pytest_cache/`, `checks/`, `results/`, `ietf126/results/`, `dist/`, `build/`, and coverage outputs.
5. Keep all boundary wording intact: this is not production software, an IETF standard, an official IETF reference implementation, a certification program, a conformance program, a public trust anchor, or a patent-license grant.
6. Run the release preflight from the hash-locked Python 3.13 Linux x86-64 environment where available.

```bash
python -m pip install --require-hashes -r requirements-lock-py313-linux-x86_64.txt
python -m pip install --no-build-isolation -e . --no-deps
python tools/generate_supply_chain_metadata.py
python tools/make_public_manifest.py
make clean
make qa-full
```

Expected evidence:

```text
Strict pytest:                       323 / 323 PASS
Evaluation vectors:                  76 / 76 PASS
IETF selected review packet:         20 / 20 PASS
Independent recomputation:           17 / 17 PASS
Independent crypto verification:     19 / 19 PASS
Critical-module line coverage:       >= 99%
Critical-module branch coverage:     >= 97.5%
Manifest, lineage, pointers:         PASS
```

## Build and verify the immutable tuple

```bash
rm -rf /tmp/permit-a /tmp/permit-b
python tools/build_release_asset.py \
  --source-repository https://github.com/meridianverity/permit-receipt \
  --source-commit "$(git rev-parse HEAD)" \
  --out-dir /tmp/permit-a
python tools/build_release_asset.py \
  --source-repository https://github.com/meridianverity/permit-receipt \
  --source-commit "$(git rev-parse HEAD)" \
  --out-dir /tmp/permit-b

for suffix in \
  .zip \
  .zip.sha256 \
  .zip.manifest.json \
  .zip.provenance.json; do
  cmp "/tmp/permit-a/permit-receipt-ref-eval-v2_2_6-public-eval${suffix}" \
      "/tmp/permit-b/permit-receipt-ref-eval-v2_2_6-public-eval${suffix}"
done

python tools/verify_release_artifact.py \
  /tmp/permit-a/permit-receipt-ref-eval-v2_2_6-public-eval.zip \
  /tmp/permit-a/permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256 \
  --manifest /tmp/permit-a/permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json \
  --provenance /tmp/permit-a/permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json \
  --require-source-revision \
  --expected-source-repository https://github.com/meridianverity/permit-receipt \
  --expected-source-commit "$(git rev-parse HEAD)"
```

The checksum sidecar must contain exactly one non-empty line and name the ZIP exactly. Do not hand-edit any generated asset.

## Publish and reverify

1. Tag the exact reviewed commit as `v2.2.6-public-eval`.
2. Create the release with the exact title above.
3. Attach all four generated assets: ZIP, checksum sidecar, asset manifest, and provenance statement.
4. Copy the final ZIP SHA-256 and byte size from the generated manifest into the release body.
5. Download all four assets in a clean directory while logged out.
6. Run `sha256sum -c`, `tools/verify_release_artifact.py`, extract the ZIP, install dependencies, and run `make qa-full` from the downloaded bytes.
7. Only after that succeeds, update the live IETF 126 Hackathon pointer to the exact release URL.
8. Reopen the GitHub release and IETF page while logged out and verify every link.

## Immutability rule

Never replace any asset under this tag. Any changed byte requires a fresh tag, fresh asset names, fresh sidecar, and a new checksum. Keep v2.2.5 and earlier tags available as historical evidence, but do not direct active reviewers to them after v2.2.6 is public and independently verified.
