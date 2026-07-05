# Compatibility Alias — Hackathon Reviewer Brief

This file is retained for older links. The reviewer-facing file is `HACKATHON_REVIEWER_BRIEF.md`. The IETF Hackathon is collaborative; this is not an awards, judging, certification, or endorsement request.

---

# Hackathon Reviewer Brief — PermitReceipt Reference Evaluation

This brief is written for IETF Hackathon reviewers, project-results listeners, and collaborators. The IETF Hackathon is collaborative; this file is not an awards, certification, or endorsement request.

## One sentence

PermitReceipt tests whether one AI-agent or workload external effect can be canonicalized, bound to an `action_digest`, and denied fail-closed before commit when required proof is missing, stale, mismatched, replayed, unsupported, or unverifiable.

## What to run

```bash
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
cat ietf126/results/review-summary.md
```

The runner is dual-mode. In the full repository it uses the `orprg_eval` package and vector corpus. If extracted as an IETF packet only, it runs a narrow standard-library evaluator so review can still proceed. The separate `independent_recompute.py` check rereads generated outputs and recomputes canonical bytes and digests without importing the verifier package.

## What to inspect

1. `canonical-request.bytes.txt` — the exact bytes hashed.
2. `one-protected-action.json` — the request, PermitReceipt, `action_digest`, and verifier result.
3. `negative-vector-results.json` — selected fail-closed failures.
4. `interop-crossref-results.json` — why name-only references are non-authorizing and why signature-covered cross-reference is the primary interop model.
5. `independent-recompute-results.json` — package-independent canonical-byte and digest recomputation.
6. `public-review-passport.json` — a compact run summary.

## Why it matters

Many agent and workload systems log after the fact. This packet tests the front-door predicate: no protected external effect should commit unless the exact effect is authorized now, under the current policy epoch, scope, validity, status/recency, and anti-replay requirements.

## What is intentionally not claimed

This is not production software, not an official IETF reference implementation, not a certification or conformance program, not a legal/commercial position, and not a patent license grant.
