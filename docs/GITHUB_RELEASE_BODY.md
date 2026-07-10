# v2.2.6 Public Evaluation — IETF 126 Review Packet

This release is the active canonical public-evaluation pointer for PermitReceipt / ORPRG IETF 126 Hackathon coordination and reproducible running-code review.

It asks one narrow question: **before a protected external effect commits, is there current permit evidence authorizing that exact effect?**

## What changed

v2.2.6 closes the adversarial findings disclosed for v2.2.5:

- one schema-valid `authorization_ref` field model across documentation, runner, generated sample, signed carrier, schemas, and independent verification;
- total fail-closed behavior for recognized malformed verifier inputs;
- required bounded receipt and capability nonces;
- replay reservations committed only after all mandatory semantic checks;
- replay namespaces scoped by issuer/profile/policy/epoch/tenant/audience;
- constrained mode that cannot bypass replay or a required downstream capability;
- strict timezone-aware RFC 3339 parsing and absolute drift limits;
- explicit revocation-status precedence, with `revoked` always denying;
- cryptographic capability-to-receipt binding;
- strict duplicate-key and resource-bounded JSON/HTTP ingress;
- bounded CP-JSON-2 canonicalization and strict Base64 decoding;
- independent Ed25519 verification with positive and tamper-negative checks; and
- a hash-locked QA and build environment, CycloneDX SBOM, deterministic asset manifest, and provenance statement;
- patched cryptographic/test dependencies and exact PEP 517 build-backend pins; and
- executable `make independent-crypto` plus explicit fail-closed replay-invariant handling.

## Measured release evidence

```text
Strict pytest:                         323 / 323 PASS
Evaluation vectors:                    76 / 76 PASS
IETF selected review packet:           20 / 20 PASS
Independent recomputation:             17 / 17 PASS
Independent crypto verification:       19 / 19 PASS
Critical-module line coverage:         >= 99%
Critical-module branch coverage:       >= 97.5%
```

The final release verification report records the exact observed coverage percentages, asset byte size, SHA-256 values, and clean-room extraction result.

## Immutable lineage

`v2.2.6-public-eval` supersedes `v2.2.5-public-eval` for active review-reference purposes. v2.2.5 remains immutable historical evidence. After publication, do not replace any v2.2.6 asset; any changed byte requires a fresh tag and asset tuple.

## Release tuple

```text
Tag:         v2.2.6-public-eval
ZIP:         permit-receipt-ref-eval-v2_2_6-public-eval.zip
Checksum:    permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
Manifest:    permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json
Provenance:  permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
Release:     https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

Copy the exact checksum line and asset byte size from the final generated sidecar/manifest into the public release after the assets are frozen.

## Reviewer fast path

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
unzip -q permit-receipt-ref-eval-v2_2_6-public-eval.zip
cd permit-receipt-main
python tools/verify_release_artifact.py \
  ../permit-receipt-ref-eval-v2_2_6-public-eval.zip \
  ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256 \
  --manifest ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json \
  --provenance ../permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
python -m pip install --require-hashes -r requirements-lock-py313-linux-x86_64.txt
python -m pip install --no-build-isolation -e . --no-deps
make qa-full
```

## Boundary

Public evaluation release. Not production software. This artifact does not process live payments, store payment credentials, call live processors, prove deployment non-bypassability, serve as a certification or conformance program, act as an official IETF reference implementation, state a legal/commercial position, or grant a patent license.
