# Release Notes — v2.2.6-public-eval

## Purpose

`v2.2.6-public-eval` is the fail-closed profile and interoperability-hardening release for PermitReceipt / ORPRG public evaluation at IETF 126.

It supersedes `v2.2.5-public-eval` as the active reviewer pointer while preserving every v2.2.5 tag and asset as immutable historical evidence.

## Security and interoperability changes

- Reconciled the generated `authorization_ref`, profile document, canonical Draft 2020-12 schema, alias schema, signed carrier schema, reviewer runner, and independent checks.
- Added strict typed validation for requests, receipts, scope constraints, capabilities, revocation evidence, policy state, context, timestamps, drift values, and nonce material.
- Made the public verifier a total fail-closed boundary: malformed recognized inputs return deterministic DENY results rather than leaking parser or canonicalization exceptions.
- Required bounded, nonempty string nonces for receipt and capability replay protection; booleans, numbers, nulls, containers, and empty strings deny.
- Moved receipt replay and required capability checks ahead of every constrained-mode ALLOW. Constrained mode can relax revocation freshness only; it cannot waive authenticity, action binding, scope, validity, replay, or required downstream evidence.
- Added strict, explicit-zone RFC 3339 parsing and absolute clock-drift checks, eliminating host-timezone-dependent naive timestamp behavior.
- Defined strict revocation-status precedence. `revoked`, conflicting, malformed, and unsupported status states fail closed.
- Cryptographically bound capability tokens to the active receipt digest.
- Added transactional replay reservations so a rejected capability does not consume a valid receipt nonce; failed multi-cache reservations are rolled back.
- Added duplicate-key-rejecting, float-rejecting, size-bounded JSON ingress and bounded HTTP request handling.
- Hardened CP-JSON-2 canonicalization against non-string keys, NFC collisions, floats, oversized/deep values, out-of-profile integers, and lone surrogate code points.
- Added strict base64 decoding and bounded thread-safe crypto caches.
- Closed SQLite replay connections under warnings-as-errors and added transaction/reopen/concurrency tests.
- Added independently implemented Ed25519 verification of the receipt, signed revocation list, and signed authorization-reference carrier, including tamper negatives.
- Added hash-locked QA dependencies for the reproducible CPython 3.13 Linux x86_64 evaluation environment.
- Updated the certified environment to `cryptography==49.0.0`, `pytest==9.1.1`, and `coverage==7.15.0`; pinned `setuptools==83.0.0` and `wheel==0.47.0` in the lock/SBOM; and disabled build isolation for certified editable installs.
- Added the missing `make independent-crypto` reviewer command and explicit fail-closed handling for impossible replay-spec invariants.

## Final prepublication release-engineering closure

- The complete public-tooling sweep is now part of `make qa-full`; every self-validating public runner returns nonzero on a failed result.
- KMS, persistent replay, benchmark, and schema-fuzz runners are aligned with the hardened request, replay, and canonicalization profiles.
- Final external provenance may be generated only from a clean worktree whose exact Git commit is resolved by `v2.2.6-public-eval`; publication verification can require that source revision material.
- The release gate rejects XML DTD/entity declarations in the bundled local draft parser.

## Measured release gates

```text
Strict pytest:                    323 / 323 PASS
Evaluation vectors:               76 / 76 PASS
IETF selected review packet:      20 / 20 PASS
Independent recomputation:        17 / 17 PASS
Independent crypto verification:  19 / 19 PASS
orprg_eval statement coverage:     99.33%
orprg_eval branch coverage:        98.44%
Security-core line coverage:       100.00%
Security-core branch coverage:     99.705%
Verifier branch coverage:          100.00%
Strict-schema branch coverage:     100.00%
Warnings-as-errors:               PASS
Release gate findings:             0 required
Release-lineage findings:          0 required
Reviewer-pointer findings:         0 required
```

The final ZIP digest and byte size are properties of the immutable publication asset and are carried by its `.sha256` sidecar and packaging manifest.

## Release tuple

```text
Tag:      v2.2.6-public-eval
Asset:    permit-receipt-ref-eval-v2_2_6-public-eval.zip
Sidecar:  permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256
Manifest: permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json
Provenance: permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json
Release:  https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval
```

After publication, do not replace any asset under this tag. Any byte change requires a new tag, asset name, sidecar, and checksum.

## Boundary

This remains synthetic, source-available evaluation software. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and it grants no patent license.
