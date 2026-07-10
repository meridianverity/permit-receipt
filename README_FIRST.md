# Read This First: PermitReceipt Public Evaluation Slice

This repository is a synthetic, provider-neutral public evaluation artifact for PermitReceipt-based permit-before-commit authorization of AI-agent and workload external effects.

Active immutable review tag: `v2.2.6-public-eval`.

It demonstrates a narrow running-code review question: can a protected external effect be canonicalized, bound to an `action_digest`, checked against a `PermitReceipt`, evaluated against policy epoch, scope, validity, status/recency, issuer evidence, and anti-replay state, and then allowed or fail-closed denied before commitment?

It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and it grants no patent license.

PayGate is included only as one optional synthetic agentic-commerce profile. It is not a live payment system and does not replace wallets, issuers, PSPs, payment networks, network tokens, or settlement rails.

## Read these files before review

1. `README.md` — main overview and local commands.
2. `GLOSSARY.md` — shared terms and public-boundary wording.
3. `NOTICE.md` — high-level limitations and release posture.
4. `LICENSE-EVALUATION.md` — source-available evaluation license notice.
5. `PATENT-NOTICE.md` — IPR boundary and no patent license grant.
6. `docs/SECURITY_AND_LIMITATIONS.md` — security and production limitations.
7. `docs/TERMINOLOGY_AND_BOUNDARY_GUIDE.md` — words to use and words to avoid.
8. `docs/EVALUATION_BOUNDARY.md` — what this public slice demonstrates and what it does not provide.
9. `docs/STANDARDS_STATUS_AND_IPR.md` — IETF status and no-patent-license boundary.
10. `docs/PUBLIC_REVIEWER_GUIDE.md` — what feedback is useful and what not to submit.
11. `docs/REPRODUCIBILITY.md` — clean-run and manifest expectations.
12. `docs/PRE_RELEASE_AUDIT_CHECKLIST.md` — public-release audit checklist; filename retained for continuity.
13. `docs/PUBLIC_STEWARDSHIP.md` — public-good posture.
14. `docs/RELEASE_LINEAGE_v2_2_6.md` — fresh-tag lineage and same-tag asset-refresh handling.
15. `docs/RELEASE_PUBLISHING_PROTOCOL_v2_2_6.md` — publish-time digest and no-replacement protocol.
16. `docs/RELEASE_PROVENANCE_AND_ASSET_BINDING.md` — active release tuple and sidecar-binding guidance.
17. `docs/REVIEWER_FAST_PATH_v2_2_6.md` — shortest useful reviewer path.
18. `docs/SECURITY_HARDENING_v2_2_6.md` — audit-finding-to-machine-control closure record.

## Quickstart

```bash
python -m pip install -r requirements.txt
python -m paygate_hybrid.hybrid_demo
python tools/run_public_eval.py
```

Expected summary: the allow path commits only in the synthetic adapter, while scope mismatch, missing domain evidence, direct adapter bypass, and evidence tamper produce fail-closed DENY outcomes.

## Public-good posture

The goal is to make standards discussion and technical review more honest by giving reviewers a runnable, bounded artifact. The goal is not to invite production copy/paste, false certification, or implied patent licensing.

Open enough running code to test the conversation. Protect enough mechanism to preserve production safety, accountability, and licensing clarity.
