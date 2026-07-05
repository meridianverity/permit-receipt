# PermitReceipt Reference Evaluation — Remote Review Checkpoint

Champion: Yong Bok Lee / Meridian Verity Group, <scott@meridianverity.com>

Mode: Remote / asynchronous first.

Suggested remote checkpoint: Sunday, 19 July 2026, 11:00-11:25 GMT+2, before the 12:30 hacking stop; adjust here if the team selects a different slot.

Purpose: Review one protected-action evaluation, exact canonical request bytes, `action_digest` binding, fail-closed negative vectors, and signature-covered authorization-reference interop shape.

Materials:

- Project page text: `ietf126/SUBMISSION_TEXT.md`
- Review packet: `https://github.com/meridianverity/permit-receipt/tree/main/ietf126`
- Runner: `python ietf126/run_review_packet.py` plus `python ietf126/independent_recompute.py`

Suggested flow:

1. Run the packet.
2. Inspect `ietf126/results/review-summary.md`.
3. Open `canonical-request.bytes.txt` and compare it to `action_digest`.
4. Review at least three fail-closed negative vectors.
5. Review `interop-crossref-results.json` for name-only and unsupported-profile failure behavior.
6. File GitHub issues for field ambiguity, missing vectors, or interop gaps.

Public boundary: technical public-artifact review only; no production data, no private implementation mapping, no claim charts, no legal/commercial position, and no patent license by publication.
