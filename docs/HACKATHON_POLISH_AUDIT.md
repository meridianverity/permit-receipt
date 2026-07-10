# IETF 126 Hackathon Hardening Audit — v2.2.6

This note records the final public-review hardening applied after the immutable v2.2.5 evaluation snapshot exposed concrete interoperability and fail-closed gaps.

## Security and interoperability changes

- Unified the generated authorization reference, profile, canonical schema, compatibility alias, signed carrier, runner, and independent checks.
- Added strict typed validation, bounded canonicalization and JSON ingress, duplicate-key rejection, explicit-zone RFC 3339 parsing, symmetric clock-drift checks, and strict revocation-status precedence.
- Required bounded nonempty replay nonces and moved all non-waivable replay and capability checks ahead of constrained-mode ALLOW.
- Added receipt-capability digest binding and transactional replay reservations with rollback.
- Added strict Base64 handling, bounded crypto caches, closed SQLite resources, and broader Merkle fault-injection coverage.
- Added independent Ed25519 verification for the receipt, signed revocation list, and signed authorization-reference carrier.
- Added deterministic SBOM, source provenance, four-asset publication tuple, hash-locked evaluation environment, and full-SHA-pinned read-only CI workflows.

## Measured source-tree posture

```text
IETF selected review packet:       20 / 20 PASS
Independent recomputation:         17 / 17 PASS
Independent crypto verification:   19 / 19 PASS
Public evaluation vectors:         76 / 76 PASS
Strict pytest:                    323 / 323 PASS
Security-core line coverage:        100.00%
Security-core branch coverage:      99.705%
Release/lineage/pointer findings:        0
```

Generated `results/`, `checks/`, coverage outputs, caches, and distribution directories are excluded from the static source manifest and deterministic release slice.

## Public boundary

This remains a synthetic public evaluation and review artifact. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, not a production authorization boundary, not a legal/commercial position, and not a patent license grant.
