# IETF 126 Hackathon Polish Audit

This note records the final public-review polish applied after the v2.2.5 public-evaluation packet was already passing QA.

## Code hardening

- Merkle inclusion proof verification now binds `leaf_index`, `tree_size`, and audit-path direction. The public-eval Merkle root is size-bound, so a tampered tree size, leaf index, or impossible path direction no longer verifies.
- Merkle non-inclusion proof verification now requires adjacent predecessor/successor proofs or a proven tree edge for boundary absence. A proof cannot claim absence by selecting non-adjacent neighbors around a present entry.
- Merkle entry construction now rejects duplicate entry keys to avoid ambiguous sorted-set proofs.
- Scope checking now denies when a receipt scope constrains an optional field and the request omits that field. Omission is not treated as a bypass.
- Regression tests were added for Merkle proof hardening and scope-constrained optional-field omission.
- The synthetic evaluation attestation was refreshed to the current v2.2.5 file set, and release-gate validation now catches version or digest drift.
- Bare benchmark defaults are bounded for reviewer sandboxes; full benchmark sizes remain explicit through the aggregate runner.

## Hackathon reviewer UX

- The IETF 126 schedule text no longer contains a `TBD` marker; it now includes a proposed remote checkpoint slot that can be adjusted on the Team Schedule.
- Public-facing Hackathon text now uses `public evaluation vectors` instead of `conformance vectors` where the document is not specifying a formal conformance program.
- A compact `ietf126/CLOSING_PRESENTATION_CARD.md` was added for a project-results slot.
- The Makefile now includes `make ietf-preflight` as a one-command full Hackathon preflight alias.
- A reviewer-facing `HACKATHON_REVIEWER_BRIEF.md` was added. The older judge-named file is retained only as a compatibility alias because the IETF Hackathon is collaborative.

## Validation posture

The polished packet was validated with:

```bash
python tools/make_public_manifest.py
make ietf-preflight
```

Observed posture after the polish:

```text
public evaluation harness: PASS
public packet validation: PASS
static manifest verification: PASS
IETF 126 selected review packet: 17 / 17 PASS
IETF 126 independent recomputation: 17 / 17 PASS
ORPRG public evaluation vectors: 65 / 65 PASS
pytest: 21 passed
release gate findings: 0
```

Generated `results/`, `checks/`, `ietf126/results/`, and Python cache directories are intentionally excluded from the static manifest and should not be committed as source artifacts.

## Public boundary

This remains a synthetic public evaluation and review artifact. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, not a production authorization boundary, not a legal/commercial position, and not a patent license grant.
