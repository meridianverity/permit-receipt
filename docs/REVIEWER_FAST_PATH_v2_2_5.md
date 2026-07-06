# Reviewer Fast Path — v2.2.5-public-eval

This is the shortest useful path for a public IETF 126 reviewer.

## 1. Verify the asset before executing it

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
unzip -q permit-receipt-ref-eval-v2_2_5-public-eval.zip
cd permit-receipt-main 2>/dev/null || cd permit-receipt-ref-eval-v2_2_5-public-eval
```

## 2. Run the selected review packet

```bash
python -m pip install -r requirements.txt
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
cat ietf126/results/review-summary.md
```

Expected:

```text
IETF review packet:           17 / 17 PASS
Independent recomputation:    17 / 17 PASS
```

## 3. Inspect the evidence that matters

```text
ietf126/results/one-protected-action.json
ietf126/results/canonical-request.bytes.txt
ietf126/results/canonical-request.hex.txt
ietf126/results/negative-vector-results.json
ietf126/results/interop-crossref-results.json
ietf126/results/independent-recompute-results.json
ietf126/results/public-review-passport.json
```

Focus on:

- whether the canonical request bytes are reproducible;
- whether the `action_digest` binds the protected effect;
- whether negative vectors deny before commit;
- whether name-only references are non-authorizing;
- whether signature-covered cross-reference shape is understandable for public-safe interoperability review.

## 4. Optional full preflight

```bash
make qa-full
```

Expected:

```text
Public evaluation harness:    PASS
Packet validation:            PASS
Release lineage check:        PASS
Release pointer check:        PASS
Manifest verification:        PASS
IETF review packet:           17 / 17 PASS
Independent recomputation:    17 / 17 PASS
Evaluation vectors:           65 / 65 PASS
Pytest:                       21 / 21 PASS
```

## Boundary

This is a synthetic public review artifact. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and not a patent license grant.
