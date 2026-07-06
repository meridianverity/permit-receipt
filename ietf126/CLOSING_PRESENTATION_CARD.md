# IETF 126 Project-Results Card — PermitReceipt

## One-line result

We made the PermitReceipt pre-commit authorization question runnable: one protected external effect is canonicalized into exact bytes, bound to an `action_digest`, checked against a signed synthetic PermitReceipt, and denied fail-closed when proof is missing, stale, mismatched, replayed, unsupported, or unverifiable.

## Demo path

```bash
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
cat ietf126/results/review-summary.md
```

Expected selected packet posture:

```text
One protected-action positive path: PASS
Selected executable negative vectors: 9 / 9 PASS
Interop authorization_ref shape checks: 7 / 7 PASS
Overall selected packet: 17 / 17 PASS
Independent recomputation: 17 / 17 PASS
```

## What to show in 3-5 minutes

1. `canonical-request.bytes.txt` — the exact UTF-8 bytes hashed.
2. `one-protected-action.json` — `request`, `action_digest`, PermitReceipt core, and ALLOW result.
3. `negative-vector-results.json` — fail-closed DENY for missing receipt, digest mismatch, scope violation, constrained budget omission, expired validity, stale status, replay, unsupported canonicalization, and missing transparency proof.
4. `interop-crossref-results.json` — name-only references are non-authorizing; signature-covered cross-reference is the safe public-eval bridge when byte-identical digest equality is not proven.

## Reviewer asks

- Are the field names understandable to implementers from adjacent work?
- Which negative vectors are missing for future public evaluation?
- Should future draft work split requirements, architecture, data model, public evaluation vectors, and wire profiles?
- Is the `authorization_ref` shape sufficient for discussion of signature-covered cross-reference interop?

## Public boundary

Synthetic public review artifact only. Not production software, not an IETF standard, not an official IETF reference implementation, not a certification or conformance program, not a production authorization boundary, not a legal/commercial position, and not a patent license grant.
