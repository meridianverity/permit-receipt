# Release Lineage — v2.2.6-public-eval

## Canonical reviewer tuple

```text
Tag:         v2.2.6-public-eval
Asset:       permit-receipt-ref-eval-v2_2_6-public-eval.zip
Sidecar:     permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
Manifest:    permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json
Provenance:  permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
Release:  https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

## Lineage

`v2.2.6-public-eval` supersedes `v2.2.5-public-eval` for active review-reference purposes because v2.2.6 changes verifier behavior, schemas, vectors, independent verification, tests, and release evidence.

The older v2.2.5 pointer remains historical and immutable. Its assets must not be refreshed or replaced. This fresh tag also preserves the earlier rule adopted to remove same-tag asset-refresh ambiguity from the digest-bound review path.

## Immutable-publication rule

After the checksum is published or sent to reviewers:

1. do not force-update the tag;
2. do not replace the ZIP;
3. do not replace the sidecar;
4. do not silently revise the release body in a way that changes the stated digest tuple;
5. publish a new tag and checksum for every byte-level correction.

## Reviewer interpretation

A reviewer should trust the release tuple only when the downloaded asset digest, sidecar line, release-platform digest when available, and local recomputation agree. A name or tag alone is not evidence of byte identity.

## Public boundary

This lineage record concerns reproducible technical review. It does not create production authorization, IETF endorsement, certification, conformance-program status, commercial rights, or patent-license rights.
