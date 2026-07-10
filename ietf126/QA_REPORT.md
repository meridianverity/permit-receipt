# IETF 126 v2.2.6 QA Report

The selected packet and full repository gate passed from the v2.2.6 source tree.

```text
python ietf126/run_review_packet.py             PASS — 20 / 20 selected packet checks
python ietf126/independent_recompute.py         PASS — 17 / 17 recomputation checks
python ietf126/independent_crypto_verify.py     PASS — 19 / 19 independent signature checks
python run_vectors.py                           PASS — 76 / 76 public evaluation vectors
strict pytest                                   PASS — 323 / 323 tests
security-core coverage                          PASS — 100.00% line / 99.705% branch
python tools/validate_public_eval_packet.py     PASS
python tools/check_ietf126_release_pointers.py  PASS — 0 findings
python verify_manifest.py                       PASS
```

The full-repository mode uses the hardened `orprg_eval` verifier. The standalone packet path remains a deliberately narrow standard-library reviewer aid; it is not a substitute for the full signature-verifying gate.

Generated IETF outputs are written under `ietf126/results/` and are intentionally excluded from the static manifest so reviewers can regenerate them from the immutable source bytes.

Public boundary: synthetic public artifact only. No production credentials, live payments, customer data, regulated data, standards-body implementation claim, certification service, conformance service, legal/commercial position, or patent license by publication.
