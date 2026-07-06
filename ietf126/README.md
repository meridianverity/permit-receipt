# IETF 126 PermitReceipt Review Packet — V2

This is the public-safe remote review packet for `draft-lee-orprg-permit-receipts` and the accompanying PermitReceipt public evaluation slice.

The packet is intentionally small, runnable, and falsifiable. It asks one question:

> Can one protected external effect be canonicalized, bound to an `action_digest`, evaluated against a `PermitReceipt`, and denied fail-closed before commit when proof is missing, stale, mismatched, replayed, unsupported, or unverifiable?

## What changed in V2

- Champion contact is included in the submission text.
- The runner is dual-mode:
  - **full-repository mode** uses the repository `orprg_eval` package and vector corpus;
  - **standalone packet mode** uses only Python's standard library when the IETF packet is extracted without the full repository.
- Public language now says **signature-covered authorization reference** instead of overclaiming a production signature profile.
- Public-boundary language uses **legal/commercial position** instead of legal-claim-facing language.
- Remote schedule text includes a concrete proposed pre-closing checkpoint for the IETF 126 Hackathon weekend.
- The release hash is not hardcoded in reviewer-facing text; publish-time release assets should carry their own checksums.
- The packet now includes `independent_recompute.py`, a separate standard-library recomputation check for canonical bytes, digests, selected negative-vector pass flags, and authorization-reference commitments.

## The 5-minute reviewer path

From the repository root, or from a standalone extraction containing this `ietf126/` directory:

```bash
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
cat ietf126/results/review-summary.md
```

Then inspect:

```text
ietf126/results/review-summary.md
ietf126/results/one-protected-action.json
ietf126/results/canonical-request.bytes.txt
ietf126/results/canonical-request.hex.txt
ietf126/results/negative-vector-results.json
ietf126/results/interop-crossref-results.json
ietf126/results/independent-recompute-results.json
ietf126/results/public-review-passport.json
```

## The full-repository reviewer path

When this packet is applied to the full `permit-receipt` repository:

```bash
python -m pip install -r requirements.txt
python run_vectors.py
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python tools/run_public_eval.py
python tools/validate_public_eval_packet.py
python tools/check_ietf126_release_pointers.py
python verify_manifest.py
# or run the one-command preflight from the repository root:
make ietf-preflight
```

Expected posture:

```text
ORPRG public evaluation vectors: 65 / 65 PASS
IETF 126 selected review packet: positive path PASS, selected negative vectors PASS
Independent recomputation: canonical bytes, action digest, receipt-core digest, selected negative-vector flags, and authorization_ref commitments PASS
Signature-covered authorization_ref shape checks: PASS for the covered reference case; DENY for name-only, unsigned, mismatched, stale, and unsupported references
```

## What is deliberately tested

- exact canonical request bytes;
- `action_digest` binding;
- PermitReceipt signature and issuer evidence in full-repository mode;
- policy digest and policy epoch;
- validity interval;
- scope, tenant, purpose, and representation constraints where selected;
- revocation/status recency;
- anti-replay behavior;
- unsupported canonicalization profile behavior;
- fail-closed denial reason codes;
- standalone/full-repository DRC parity for the selected packet; and
- the difference between byte-identical digest equality and signature-covered cross-reference interoperability.

## What is deliberately not claimed

This packet is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, not a production authorization boundary, not an endorsement, not a legal/commercial position, and not a patent license grant.

Do not put customer data, credentials, regulated data, production logs, non-public implementation mapping, claim charts, evidence-of-use materials, valuation materials, or commercial-rights questions in public issues.

## Fast orientation

- `SUBMISSION_TEXT.md` — copy/paste project-page text.
- `TEAM_SCHEDULE_TEXT.md` — copy/paste remote checkpoint text.
- `HACKATHON_REVIEWER_BRIEF.md` — one-page technical framing for reviewers. `HACKATHON_JUDGES_BRIEF.md` is retained as a compatibility alias only.
- `CLOSING_PRESENTATION_CARD.md` — compact project-results presentation card.
- `../docs/HACKATHON_POLISH_AUDIT.md` — final hardening and QA summary for the polished packet.
- `ONE_PROTECTED_ACTION.md` — the synthetic request under test.
- `CANONICALIZATION_AND_DIGESTS.md` — byte-level digest rules.
- `AUTHORIZATION_REF_PROFILE.md` — signature-covered cross-reference shape for interop review.
- `DIGEST_INTEROP_NOTES.md` — two digest families, signature-covered pivot, no name-only binding.
- `NEGATIVE_VECTOR_PLAN.md` — executable and candidate fail-closed vectors.
- `REVIEWER_CHECKLIST.md` — review checklist.
- `RUNBOOK_10_MIN.md` — timed runbook for a remote slot.
- `STANDALONE_PACKET.md` — how to run the packet if extracted without the full repository.
- `independent_recompute.py` — standard-library recomputation check that does not import the main verifier package.
