# Quickstart

```bash
unzip permit-receipt-ref-eval-v2_2_4-public-eval.zip
cd permit-receipt-main 2>/dev/null || cd permit-receipt-ref-eval-v2_2_4-public-eval
python -m pip install -r requirements.txt
python -m pip install -e . --no-deps  # optional editable-install smoke check
python -m paygate_hybrid.hybrid_demo
python tools/run_public_eval.py
python tools/validate_public_eval_packet.py
python tools/check_ietf126_release_pointers.py
python verify_manifest.py
```

The demo is fully synthetic and local. It does not call a live payment processor, does not store PAN/SAD, does not use real processor credentials, and does not move money.

This package is a public evaluation slice for standards discussion and reproducibility review. It is not production software, not an IETF standard, not an official reference implementation, not a certification program, not a conformance program, and it grants no patent license.


## IETF 126 packet

```bash
python -m pip install -r requirements.txt
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
cat ietf126/results/review-summary.md
```

The IETF 126 packet writes exact canonical bytes, the `action_digest`, selected fail-closed negative vectors, signature-covered authorization-reference interop checks, and an independent standard-library recomputation report under `ietf126/results/`.
