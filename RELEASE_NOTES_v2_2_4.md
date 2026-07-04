# Release Notes — v2.2.4-public-eval

Public-safe IETF 126 review update for the PermitReceipt public evaluation slice.

## What changed

- Integrated the `ietf126/` remote review packet into the main repository.
- Added a dual-mode IETF packet runner: full-repository mode when `orprg_eval` is available, and standalone packet mode when only the IETF packet is extracted.
- Added exact canonical request bytes, canonical request hex, `action_digest`, public review passport, positive path, fail-closed negative vectors, and signature-covered `authorization_ref` shape checks.
- Added IETF 126 project-page text, Team Schedule text, a 10-minute runbook, 90-second talk track, judges brief, reviewer checklist, and issue triage notes.
- Added a public-eval v2 `authorization_ref` schema for signature-covered cross-reference interop.
- Added GitHub issue templates for field-model review, negative-vector review, and cross-reference review.
- Added GitHub Actions workflows for public QA and IETF packet review.
- Regenerated the static source manifest after final file changes.

## Public boundary

This release remains a synthetic public evaluation artifact. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, not a production authorization boundary, not a legal/commercial position, and not a patent license grant.

## Reviewer path

```bash
python -m pip install -r requirements.txt
python ietf126/run_review_packet.py
cat ietf126/results/review-summary.md
```

Optional full QA:

```bash
make qa-full
```
