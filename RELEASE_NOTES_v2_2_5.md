# Release Notes — v2.2.5-public-eval

## Purpose

`v2.2.5-public-eval` is a fresh-tag public evaluation packet for IETF 126 Hackathon coordination and reproducible reviewer execution.

This release preserves the v2.2.4 technical review posture while strengthening release-lineage hygiene after a same-tag asset-refresh ambiguity was flagged during reviewer preparation.

## What changed from the prior public-evaluation pointer

- Fresh canonical tag: `v2.2.5-public-eval`.
- Fresh canonical asset name: `permit-receipt-ref-eval-v2_2_5-public-eval.zip`.
- Fresh checksum sidecar name: `permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256`.
- Active IETF reviewer-facing pointers now lock to the v2.2.5 tag and asset name.
- Added release-lineage documentation for same-tag asset-refresh ambiguity.
- Added release-publishing protocol: do not replace release assets after checksum publication; issue a fresh tag for byte-level changes.
- Added `tools/check_release_lineage.py` to validate version, active pointer, and lineage-document consistency.
- Refreshed the synthetic evaluation attestation metadata to v2.2.5.
- Regenerated the static source manifest.

## Expected public checks

```text
Manifest:                    PASS
IETF review packet:           PASS — 17 / 17
Independent recomputation:    PASS — 17 / 17
Evaluation vectors:           PASS — 65 / 65
Pytest:                       PASS — 21 / 21
Release lineage check:        PASS
Release pointer check:        PASS
QA full:                      PASS
```

## Review scope

The scope remains unchanged: synthetic public evaluation artifacts only. This release does not process live payments, store payment credentials, call live processors, provide production authorization, provide certification, provide a conformance program, make an IETF adoption claim, or grant a patent license.
