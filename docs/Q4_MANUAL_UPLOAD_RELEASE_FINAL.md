# Q4 Manual-Upload Friendly Release Final

This Q4 update finalizes `v2.2.4-public-eval` for GitHub manual upload and IETF 126 review.

## Decision

- GitHub release label: public evaluation release.
- Pre-release checkbox: unchecked.
- Production status: not production software.
- Hidden dot-path files: optional, not required for public evaluation manifest verification.
- GitHub Actions / Issue Templates: available as visible templates under `github-ui-files/` and may be materialized with `python tools/materialize_github_files.py`.

## Reviewer path

```bash
python -m pip install -r requirements.txt
python ietf126/run_review_packet.py
cat ietf126/results/review-summary.md
```

## Public boundary

This artifact is synthetic, public-safe, and non-production. It is not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, not a legal/commercial position, and not a patent license grant.

## Core message

One protected action. Exact bytes. One action digest. Fail-closed negatives. Signature-covered cross-reference. Public artifacts only.
