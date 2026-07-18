# Reviewer Fast Path — v2.2.6-public-eval

Canonical release:

```text
https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

## 1. Verify and extract

Download the complete immutable tuple:

```text
permit-receipt-ref-eval-v2_2_6-public-eval.zip
permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json
permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
```

Then run:

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
unzip -q permit-receipt-ref-eval-v2_2_6-public-eval.zip
cd permit-receipt-main
python tools/verify_release_artifact.py \
  ../permit-receipt-ref-eval-v2_2_6-public-eval.zip \
  ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256 \
  --manifest ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json \
  --provenance ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
```

## 2. Run the 10-minute evidence path

```bash
# Portable network-enabled path; use the certified lock below on CPython 3.13 / Linux x86_64.
python -m pip install -r requirements.txt
python -m pip install -e . --no-deps
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python ietf126/independent_crypto_verify.py
cat ietf126/results/review-summary.md
```

Expected:

```text
Selected review packet:             20 / 20 PASS
Independent recomputation:          17 / 17 PASS
Independent crypto verification:    19 / 19 PASS
```

Certified dependency path:

```bash
python -m pip install --require-hashes -r requirements-lock-py313-linux-x86_64.txt
python -m pip install --no-build-isolation -e . --no-deps
```

## 3. Inspect the load-bearing evidence

```text
ietf126/results/one-protected-action.json
ietf126/results/canonical-request.bytes.txt
ietf126/results/canonical-request.hex.txt
ietf126/results/negative-vector-results.json
ietf126/results/interop-crossref-results.json
ietf126/results/authorization-ref-carrier.json
ietf126/results/independent-recompute-results.json
ietf126/results/independent-crypto-verification.json
ietf126/results/public-review-passport.json
```

Review whether the exact protected action is committed, the reference object validates against its schema, malformed/replay/time/status/capability paths fail closed, and the independently verified signatures bind the same artifacts.

## 4. Full gate

```bash
make qa-full
```

Expected source-tree evidence:

```text
Evaluation vectors:                 76 / 76 PASS
Strict pytest:                     323 / 323 PASS
orprg_eval statement coverage:       99.33%
orprg_eval branch coverage:          98.44%
Security-core line coverage:         100.00%
Security-core branch coverage:       99.705%
Verifier branch coverage:            100.00%
Strict-schema branch coverage:       100.00%
Release, lineage, pointer findings:       0
```

## Boundary

This is a synthetic public review artifact. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and not a patent license grant.
