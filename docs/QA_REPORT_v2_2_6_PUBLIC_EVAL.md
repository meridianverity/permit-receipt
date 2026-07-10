# QA Report — v2.2.6-public-eval

Status: PASS for the frozen source-tree gate. The publication asset must also pass byte-identical double-build, external sidecar verification, and clean-extraction reverification.

## Security and interoperability evidence

```text
Strict pytest (plugins disabled, warnings errors):  323 / 323 PASS
Deterministic evaluation vectors:                    76 / 76 PASS
IETF selected review packet:                         20 / 20 PASS
Independent recomputation:                           17 / 17 PASS
Independent Ed25519 verification:                    19 / 19 PASS
orprg_eval statement coverage:                        99.33%
orprg_eval branch coverage:                           98.44%
Security-core line coverage:                          100.00%
Security-core branch coverage:                        99.705%
Verifier branch coverage:                             100.00%
Strict-schema branch coverage:                        100.00%
```

Coverage gates are enforced by `python tools/check_core_coverage.py`: critical-module line coverage must be at least 99%, critical-module branch coverage at least 97.5%, and each listed security-critical module must satisfy its individual threshold.

## Required commands

```bash
python tools/generate_supply_chain_metadata.py
python tools/make_public_manifest.py
python run_vectors.py
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python ietf126/independent_crypto_verify.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONWARNINGS=error python -m pytest -q -p no:cacheprovider
python tools/check_core_coverage.py
python verify_manifest.py
python tools/release_gate.py
python tools/static_security_scan.py
python tools/validate_public_eval_packet.py
python tools/check_release_lineage.py
python tools/check_ietf126_release_pointers.py
```

## Release tuple

```text
Tag:        v2.2.6-public-eval
Asset:      permit-receipt-ref-eval-v2_2_6-public-eval.zip
Sidecar:    permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
Manifest:   permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json
Provenance: permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
Release:    https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

The final ZIP SHA-256 and byte size are recorded outside the ZIP in the generated sidecar and asset manifest.

## Gate interpretation

- Recognized malformed inputs produce structured DENY results rather than escaping exceptions.
- Generated authorization-reference objects validate under the canonical schema.
- Constrained ALLOW cannot bypass receipt replay or required capability checks.
- Naive timestamps, excessive drift, malformed status, malformed nonce, duplicate JSON keys, and mismatched receipt-capability binding fail closed.
- Rejected capability authorization does not consume the receipt nonce.
- The receipt, signed revocation list, and signed authorization-reference carrier are independently verified without importing the main verifier package.

## Boundary

This is synthetic public-evaluation evidence only. It is not production software, a security warranty, a certification service, a conformance program, an IETF endorsement, or a patent-license grant.
