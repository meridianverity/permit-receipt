# Release Lineage — v2.2.5-public-eval

## Canonical reviewer pointer

```text
v2.2.5-public-eval
```

## Canonical asset name

```text
permit-receipt-ref-eval-v2_2_5-public-eval.zip
```

## Why this fresh tag exists

`v2.2.5-public-eval` is a fresh tag issued for release-lineage clarity after a same-tag asset-refresh ambiguity was identified on `v2.2.4-public-eval` during reviewer preparation.

The issue is not that the current bytes are suspicious. The issue is that, in a digest-binding review path, a reviewer cannot distinguish a benign same-tag asset refresh from any other byte change by name alone.

Therefore the public-review path treats the older pointer as historical and uses a fresh tag, fresh asset name, fresh sidecar, and fresh checksum for canonical review.

## Rule going forward

After the checksum for a public-evaluation release asset has been sent to reviewers or published in release notes, do not replace that asset under the same tag.

If any byte changes, publish a new tag and send a new checksum.

## Reviewer interpretation

- `v2.2.5-public-eval` is canonical for the current Vienna/IETF review path.
- `v2.2.4-public-eval` remains historical / superseded for review-reference purposes.
- Name-only references are non-authorizing.
- Digest equality is meaningful only when the exact asset, sidecar, and reviewer recomputation agree.

## Public-safe boundary

The technical scope is unchanged: synthetic public artifacts only; no endorsement, certification, production authorization, license grant, merged protocol, IETF adoption claim, commercial commitment, implied rights, or patent license grant.
