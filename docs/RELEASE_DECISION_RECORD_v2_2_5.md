# Release Decision Record — v2.2.5-public-eval

## Decision

Publish `v2.2.5-public-eval` as the canonical GitHub public evaluation release for the Vienna/IETF 126 review path.

## Reason

A reviewer flagged that the prior public-evaluation tag had a same-tag asset-refresh ambiguity. Even when the current asset, sidecar, and local recomputation agree, a digest-binding review path should not rely on a pointer whose bytes changed after an earlier checksum reference.

The correct reviewer-friendly remedy is a fresh tag, fresh asset name, fresh sidecar, and fresh emailed checksum.

## Consequence

- `v2.2.5-public-eval` is the active reviewer-facing pointer.
- Prior public-evaluation tags remain historical references only.
- Release assets must not be replaced after checksum publication.
- Any byte-level change after publication requires a new tag and new checksum.

## Expected result

```text
IETF review packet:           17 / 17 PASS
Independent recomputation:    17 / 17 PASS
Evaluation vectors:           65 / 65 PASS
Pytest:                       21 / 21 PASS
QA full:                      PASS
```

## Boundary

This release is a synthetic public technical evaluation artifact. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, not a commercial commitment, and not a patent license grant.
