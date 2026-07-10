# Release Decision Record — v2.2.6-public-eval

## Decision

Publish `v2.2.6-public-eval` as the next immutable public-evaluation pointer after the complete v2.2.6 release gate passes against the final downloaded or freshly extracted asset bytes.

## Why a new tag is required

The v2.2.5 audit found packet-internal interoperability contradictions and fail-closed edge cases that require byte-level changes. The v2.2.5 tag and assets must remain untouched. A fresh tag, asset, sidecar, and digest provide a clean, auditable lineage.

## Security decision

The v2.2.6 selected public profile makes the following checks non-waivable before ALLOW:

- trusted issuer and valid signature;
- exact canonical protected-action commitment;
- active policy and epoch;
- explicit-zone validity window and trusted clock drift;
- strict scope and context binding;
- required permit provenance and selected assurance evidence;
- strict revocation-status semantics;
- receipt anti-replay;
- required downstream capability, including receipt binding and capability anti-replay.

Constrained mode may relax only unavailable or stale revocation freshness for an explicitly permitted effect type during a declared partition. It does not bypass the checks above.

## Evidence threshold

The release decision requires all 323 tests, all 76 vectors, the 20-check IETF packet, 17 independent recomputation checks, 19 independent cryptographic checks, warnings-as-errors, a 90% combined line-plus-branch floor and a 97.5% aggregate security-core branch floor, and zero blocking release/pointer/lineage findings.

## Consequence

- `v2.2.6-public-eval` becomes the active reviewer-facing pointer after publication.
- `v2.2.5-public-eval` remains immutable and historical.
- No same-tag asset replacement is permitted.
- Any later byte-level correction requires a new public-evaluation tag.

## Boundary

The decision covers a synthetic public technical evaluation artifact only. It does not establish production authorization, IETF endorsement, certification, conformance-program status, commercial rights, or a patent license.
