# IETF 126 V2 QA Report

Local QA status after applying the V2 public review packet overlay to the full repository:

```text
python ietf126/run_review_packet.py          PASS — 17 / 17 selected packet checks · full-repository mode
python run_vectors.py                        PASS — 65 / 65 public ORPRG vectors
python tools/run_public_eval.py              PASS — 6 / 6 harness steps
python tools/validate_public_eval_packet.py  PASS — 0 release-gate findings, release-pointer check PASS
python tools/check_ietf126_release_pointers.py PASS — 0 findings
python ietf126/independent_recompute.py      PASS — 17 / 17 recomputation checks · full-repository mode
python -m pytest -q                          PASS — 21 tests
python verify_manifest.py                    PASS — 181 / 181 static files
```

Standalone packet mode was also tested from an `ietf126/`-only extraction:

```text
python ietf126/run_review_packet.py          PASS — 17 / 17 selected packet checks · standalone-ietf-packet mode
python ietf126/independent_recompute.py       PASS — 17 / 17 recomputation checks · standalone-ietf-packet mode
```

Generated IETF 126 outputs are written under `ietf126/results/` and intentionally excluded from the static manifest. Reviewers can regenerate them locally.

Public boundary: synthetic public artifact only. No production credentials, no live payments, no customer data, no regulated data, no standards-body implementation claim, no certification service, no conformance service, no legal/commercial position, and no patent license by publication.
