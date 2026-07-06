# v2.2.5 Public Evaluation — IETF 126 Review Packet

Synthetic source-available evaluation artifact for PermitReceipt-based permit-before-commit authorization of AI-agent and workload external effects.

This release is the `v2.2.5-public-eval` fresh-tag public evaluation packet for IETF 126 Hackathon coordination and reproducible running-code review. It demonstrates one protected action, exact canonical request bytes, an `action_digest`, PermitReceipt decision behavior, fail-closed negative vectors, signature-covered cross-reference shape checks, and a separate standard-library recomputation check for public-safe interoperability discussion.

## Release-lineage note

Canonical tag: `v2.2.5-public-eval`.


This fresh tag is the canonical reviewer-facing pointer for the current public-evaluation packet. It is published to remove same-tag asset-refresh ambiguity from the review path. After publication, do not replace the ZIP or sidecar under this tag. If any byte must change, publish a new tag and new checksum instead.

## Release status

Public evaluation release. Not production software. GitHub pre-release checkbox left unchecked. May be marked Latest when this tag is the active public-evaluation entry point.

## Scope

This is a synthetic public evaluation artifact only.

It does not process live payments, store payment credentials, call live processors, provide production non-bypassability, serve as a certification program, serve as a conformance program, act as an official IETF reference implementation, provide a public trust anchor, make a legal/commercial position, or grant a patent license.

## Quick start

```bash
python -m pip install -r requirements.txt
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
cat ietf126/results/review-summary.md
```

Optional full QA:

```bash
make qa-full
```

## Demonstrated behaviors

- deterministic canonicalization;
- exact canonical request bytes;
- `action_digest` binding;
- PermitReceipt verification;
- policy epoch and validity checks;
- status/recency handling;
- scope checks, including scoped `max_effect_budget` omission;
- anti-replay handling;
- fail-closed denial semantics;
- synthetic negative vectors;
- signature-covered `authorization_ref` shape checks for interop review;
- package-independent recomputation of reviewer-facing canonical bytes and digests; and
- explicit release-lineage handling for digest-bound review.

## Canonical related draft

IETF Internet-Draft:
https://datatracker.ietf.org/doc/draft-lee-orprg-permit-receipts/

Related IPR disclosure:
https://datatracker.ietf.org/ipr/7308/

## Verification

Attach a companion `.sha256` asset for the published ZIP checksum. Release asset hashes must be verified from the final release assets generated at publication time.

Release asset name:

`permit-receipt-ref-eval-v2_2_5-public-eval.zip`

Checksum sidecar name:

`permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256`

Publication-time digest and size:

The exact SHA-256 value and byte size are properties of the final ZIP bytes produced after this repository tree is packaged. Because this file is itself inside the ZIP whose bytes are hashed, this in-repository copy intentionally does not embed the final ZIP SHA-256 or a template sidecar line.

For the GitHub release page, use a post-build release body generated outside the ZIP and copy the exact sidecar line from the attached `.sha256` asset. Do not paste any template digest or other placeholder into the published release body.

Reviewer verification after download:

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
unzip -q permit-receipt-ref-eval-v2_2_5-public-eval.zip
cd permit-receipt-main
python tools/verify_release_artifact.py \
  ../permit-receipt-ref-eval-v2_2_5-public-eval.zip \
  ../permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
```

The sidecar line must name `permit-receipt-ref-eval-v2_2_5-public-eval.zip` exactly. Do not publish a sidecar that names any older staging artifact. Do not replace release assets after publication; publish a fresh tag for any byte-level change.
