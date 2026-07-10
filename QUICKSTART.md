# Quickstart — v2.2.6-public-eval

Canonical release:

```text
https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
unzip -q permit-receipt-ref-eval-v2_2_6-public-eval.zip
cd permit-receipt-main
# Portable reviewer path
python -m pip install -r requirements.txt
python -m pip install --no-build-isolation -e . --no-deps
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python ietf126/independent_crypto_verify.py
cat ietf126/results/review-summary.md
```

Expected selected evidence:

```text
IETF review packet:               20 / 20 PASS
Independent recomputation:        17 / 17 PASS
Independent crypto verification:  19 / 19 PASS
```

Certified CPython 3.13 / Linux x86_64 dependency path:

```bash
python -m pip install --require-hashes -r requirements-lock-py313-linux-x86_64.txt
python -m pip install --no-build-isolation -e . --no-deps
```

Complete local gate, including the public tooling sweep:

```bash
make qa-full
```

Expected full evidence includes 76/76 vectors, 323/323 strict tests, 99.33% statement and 98.44% branch coverage across `orprg_eval`, 100.00% line and 99.705% branch coverage across the security-critical module set, 100.00% verifier branch coverage, and zero blocking release, lineage, or pointer findings.

The demo is fully synthetic and local. It does not call a live payment processor, store PAN/SAD, use real processor credentials, or move money. This package is not production software, not an IETF standard, not an official reference implementation, not a certification program, not a conformance program, and it grants no patent license.
