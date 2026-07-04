# PermitReceipt Reference Evaluation for AI-Agent and Workload External Effects

## Champions

Yong Bok Lee, Meridian Verity Group, <scott@meridianverity.com>

## Project Info

This project provides a runnable synthetic public evaluation for PermitReceipt-based permit-before-commit authorization of AI-agent and workload external effects.

Related Internet-Draft:
https://datatracker.ietf.org/doc/draft-lee-orprg-permit-receipts/

Repository:
https://github.com/meridianverity/permit-receipt

Public evaluation release:
https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.4-public-eval

Remote review packet:
https://github.com/meridianverity/permit-receipt/tree/main/ietf126

The evaluation exercises deterministic canonicalization, action-digest binding, policy-epoch checks, scope checks, status and freshness checks, anti-replay handling, and fail-closed denial before a protected external effect is committed.

In a broader permit → mandate → record → attestation stack, this packet focuses on the front-door pre-commit authorization predicate: whether the protected external effect is authorized before it is allowed to commit.

The packet is intentionally narrow: one protected external effect, exact canonical request bytes, one `action_digest`, one PermitReceipt decision path, and executable negative vectors. It also includes a public-safe interoperability note for independently owned mandate, record, or attestation artifacts: digest equality is accepted only where byte-identical test vectors prove it; otherwise the bridge is an explicitly declared, verifier-readable, signature-covered cross-reference. Name-only references are non-authorizing.

The project includes a provider-neutral synthetic agentic-commerce profile as one example effect family. It does not process live payments, store payment credentials, call live processors, or provide production payment processing, wallet, issuer, PSP, network-token, or settlement-rail functionality.

## Hackathon goals

- Review whether the PermitReceipt field model is understandable and useful.
- Review canonicalization and `action_digest` binding behavior.
- Review negative vectors and fail-closed denial behavior.
- Review the proposed `authorization_ref` shape for signature-covered cross-reference interop.
- Identify missing public evaluation and interoperability vectors.
- Discuss whether future work should separate requirements, architecture, data model, public evaluation vectors, and wire-profile documents.
- Collect implementation and reviewer feedback for a future revision of the Internet-Draft.

## Suggested reviewer path

1. Run `python ietf126/run_review_packet.py`.
2. Inspect the canonical request bytes and `action_digest`.
3. Compare one allow path and at least three deny paths.
4. Inspect `interop-crossref-results.json` to see why name-only references are non-authorizing.
5. Open GitHub issues for unclear fields, missing negative vectors, or interoperability gaps.

The runner is dual-mode: it uses the full repository evaluation package when available, and otherwise falls back to a narrow standalone public packet using only Python's standard library.

## Expected outputs

- GitHub issues or pull requests for unclear fields, missing vectors, or implementation gaps.
- Candidate public evaluation-vector additions for future repository updates.
- Candidate field-shape feedback for signature-covered authorization cross-references.
- Input for a future revision of the Internet-Draft.

## Coordination

Remote/asynchronous coordination via GitHub Issues and IETF Hackathon communication channels.

Suggested remote checkpoint: Sunday, 19 July 2026, 11:00-11:25 GMT+2, before the 12:30 hacking stop; adjust in the Team Schedule if the team selects a different slot.

## Public boundary

This is public-artifact technical review only. It is not a partnership, endorsement, certification, production authorization, license grant, commercial commitment, merged protocol, IETF adoption claim, legal/commercial position, or patent license grant.
