# IETF 126 Vector Index

Generated outputs are written to `ietf126/results/` and excluded from the static manifest.

Static seed file:

- `vectors/orprg-one-protected-action-seed.json`

Runnable packet:

```bash
python ietf126/run_review_packet.py
```

Generated artifacts:

- `ietf126/results/one-protected-action.json`
- `ietf126/results/canonical-request.bytes.txt`
- `ietf126/results/canonical-request.hex.txt`
- `ietf126/results/positive-path.json`
- `ietf126/results/negative-vector-results.json`
- `ietf126/results/interop-crossref-results.json`
- `ietf126/results/public-review-passport.json`
- `ietf126/results/review-summary.md`

Expected positive path:

```text
IETF126-ONE-PROTECTED-ACTION -> ALLOW
```

Expected selected negative paths include:

```text
KNEG-MISSING-RECEIPT -> DENY / DRC-000-MISSING_RECEIPT
KNEG-ACTION-DIGEST-MISMATCH -> DENY / DRC-009_ACTION_DIGEST_MISMATCH
KNEG-SCOPE-VIOLATION-TARGET -> DENY / DRC-005_SCOPE_VIOLATION
KNEG-VALIDITY-EXPIRED -> DENY / DRC-004_VALIDITY_WINDOW_EXPIRED
KNEG-REVOCATION-STATE-STALE -> DENY / DRC-008_REVOCATION_UNKNOWN_OR_STALE
KNEG-ANTI-REPLAY-NONCE-REUSE -> DENY / DRC-006_ANTI_REPLAY_FAILURE
KNEG-CANONICALIZATION-PROFILE-MISMATCH -> DENY / DRC-016_CANONICALIZATION_PROFILE_MISMATCH
```

