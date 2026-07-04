# Public Evaluation Vector Guide

Public vector groups:

- `evaluation_vectors/vectors.json`: ORPRG-style PermitReceipt allow/deny evaluation vectors.
- `test_vectors_paygate_domain/expected_results.json`: payment-domain expected results.
- `examples/`: scenario-level evidence objects for H01-H05 and PAYGATE-Ref reference scenarios.

Run:

```bash
python run_vectors.py
python -m paygate_poc.run_the_verifier test_vectors_paygate_domain/expected_results.json
python -m pytest -q
```

Negative tests are as important as the allow path. The public package emphasizes amount/cart/scope tamper, replay, revoked/stale status, missing evidence, and direct provider bypass.

These are public evaluation vectors for reproducibility and standards discussion. They are not a certification suite, conformance program, procurement approval, or production-readiness test.
