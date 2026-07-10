# Pre-Release Audit Checklist — v2.2.6-public-eval

## Public-boundary review

- [ ] Public synthetic artifacts only.
- [ ] No customer data, regulated payment data, production logs, live credentials, live processor configuration, claim charts, non-public legal mapping, commercial strategy, or restricted annexes.
- [ ] README and release notes retain the non-production, non-IETF-endorsement, non-certification, non-conformance-program, and no-patent-license boundaries.
- [ ] No public text claims production non-bypassability, compliance approval, IETF endorsement, commercial commitment, certificate-registry operation, or production authorization.

## Source and supply-chain freeze

- [ ] `python tools/generate_supply_chain_metadata.py`
- [ ] `python tools/make_public_manifest.py`
- [ ] `python verify_manifest.py`
- [ ] Hash-locked install succeeds for `requirements-lock-py313-linux-x86_64.txt`.
- [ ] CycloneDX SBOM and source provenance match the current source tree.
- [ ] GitHub Actions are full-SHA pinned and declare `permissions: contents: read`.
- [ ] No generated cache, result, coverage, build, or distribution directory is included.

## Executable release gate

- [ ] `python tools/release_gate.py`
- [ ] `python tools/static_security_scan.py`
- [ ] `python tools/validate_public_eval_packet.py`
- [ ] `python tools/check_release_lineage.py`
- [ ] `python tools/check_ietf126_release_pointers.py`
- [ ] `python ietf126/run_review_packet.py`
- [ ] `python ietf126/independent_recompute.py`
- [ ] `python ietf126/independent_crypto_verify.py`
- [ ] `python run_vectors.py`
- [ ] `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONWARNINGS=error python -m pytest -q`
- [ ] `python tools/check_core_coverage.py`
- [ ] `make qa-full`

Expected source-tree evidence:

```text
Manifest verification:              PASS
Release gate and static scan:       PASS
Packet validation:                  PASS
Release lineage and pointers:       PASS
IETF selected review packet:        20 / 20 PASS
Independent recomputation:          17 / 17 PASS
Independent crypto verification:    19 / 19 PASS
Evaluation vectors:                 76 / 76 PASS
Strict pytest:                      323 / 323 PASS
Critical-module line coverage:      >= 99%
Critical-module branch coverage:    >= 97.5%
```

## Exact release tuple

- [ ] Tag: `v2.2.6-public-eval`
- [ ] ZIP: `permit-receipt-ref-eval-v2_2_6-public-eval.zip`
- [ ] Checksum: `permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256`
- [ ] Manifest: `permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json`
- [ ] Provenance: `permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json`
- [ ] Release URL: `https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval`
- [ ] Sidecar has one line and names the ZIP exactly.
- [ ] Active reviewer-facing text uses the exact tag and URL.
- [ ] Older release references appear only in clearly historical or superseded context.

## Reproducible build and public-byte verification

- [ ] Two clean builds produce byte-identical ZIPs.
- [ ] Their sidecars, manifests, and provenance statements are also byte-identical.
- [ ] `tools/verify_release_artifact.py` passes on the frozen tuple.
- [ ] ZIP CRC and source-inventory comparison pass.
- [ ] The downloaded public tuple—not the working tree—passes verification in a clean directory.
- [ ] The extracted public ZIP passes the reviewer fast path.
- [ ] GitHub and IETF links are rechecked while logged out.

## Fresh-tag rule

After publication, never replace an asset under `v2.2.6-public-eval`. Any changed byte requires a new tag and an entirely new immutable asset tuple.

## Human review

- [ ] Counsel/IP/trademark/public-disclosure review is complete.
- [ ] The public claims are no stronger than the executable evidence.

This checklist is technical release hygiene, not legal advice.
