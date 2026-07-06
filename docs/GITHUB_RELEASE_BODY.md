# v2.2.4 Public Evaluation — IETF 126 Review Packet

Synthetic source-available evaluation artifact for PermitReceipt-based permit-before-commit authorization of AI-agent and workload external effects.

This release integrates the IETF 126 remote review packet into the public evaluation slice. It demonstrates one protected action, exact canonical request bytes, an `action_digest`, PermitReceipt decision behavior, fail-closed negative vectors, signature-covered cross-reference shape checks, and a separate standard-library recomputation check for public-safe interoperability discussion.

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
- scope checks;
- anti-replay handling;
- fail-closed denial semantics;
- synthetic negative vectors;
- signature-covered `authorization_ref` shape checks for interop review.

## Canonical related draft

IETF Internet-Draft:
https://datatracker.ietf.org/doc/draft-lee-orprg-permit-receipts/

Related IPR disclosure:
https://datatracker.ietf.org/ipr/7308/

## Verification

Attach a companion `.sha256` asset for the published ZIP checksum. Release asset hashes should be verified from the release assets generated at publication time.

Release asset name:

`permit-receipt-ref-eval-v2_2_4-public-eval.zip`

Checksum sidecar name:

`permit-receipt-ref-eval-v2_2_4-public-eval.zip.sha256`

The sidecar line must name `permit-receipt-ref-eval-v2_2_4-public-eval.zip` exactly. Do not publish a sidecar that names an older staging artifact such as `permit-receipt-main-v2_2_4-ietf126-hardened.zip`.
