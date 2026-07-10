# IETF 126 Project-Results Card — PermitReceipt v2.2.6

## One-line result

The packet makes one narrow pre-commit authorization question executable: does the attempted external effect have current, signature-bound PermitReceipt evidence for the exact canonicalized action before commit?

## Demo path

```bash
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python ietf126/independent_crypto_verify.py
cat ietf126/results/review-summary.md
```

Expected posture:

```text
One protected-action positive path:      PASS
Selected executable negative vectors:   9 / 9 PASS
Authorization-reference checks:        10 / 10 PASS
Overall selected packet:              20 / 20 PASS
Independent recomputation:            17 / 17 PASS
Independent crypto verification:      19 / 19 PASS
```

## What to show in 3–5 minutes

1. `canonical-request.bytes.txt` — the exact UTF-8 bytes hashed.
2. `one-protected-action.json` — the request, action commitment, signed receipt, signed authorization-reference carrier, and ALLOW result.
3. `negative-vector-results.json` — fail-closed behavior for missing, malformed, stale, mismatched, replayed, or unsupported evidence.
4. `interop-crossref-results.json` — name-only references are non-authorizing; schema-valid signature-covered references bind the protected action.
5. `independent-crypto-verification.json` — separately implemented Ed25519 verification and tamper negatives.

## Reviewer questions

- Are the profile semantics implementable without guessing?
- Which additional cross-language vectors would most improve interoperability review?
- Which requirements belong in architecture, data-model, evaluation-profile, and future wire-profile documents?

## Public boundary

Synthetic public review artifact only. Not production software, not an IETF standard, not an official IETF reference implementation, not a certification or conformance program, not a production authorization boundary, not a legal/commercial position, and not a patent license grant.
