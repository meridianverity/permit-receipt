# IETF 126 V2 Packet Notes

V2 is a public-safe submission packet for IETF 126 Hackathon review.

## V2 fixes

- Adds champion contact to project-page text.
- Uses `signature-covered authorization_ref` language instead of overclaiming a production signature profile.
- Softens public-boundary language from legal-claim-facing wording to `legal/commercial position`.
- Adds a dual-mode runner:
  - full-repository mode uses the repository public evaluation package;
  - standalone packet mode runs from an `ietf126/`-only extraction using Python's standard library.
- Adds a concrete proposed remote checkpoint slot suitable for the Team Schedule.
- Removes hardcoded full-release ZIP hash from reviewer-facing README text; publish-time release assets should carry their own checksums.
- Adds a selected fail-closed negative for scoped `max_effect_budget` omission in both full-repository and standalone packet modes.

## V2 posture

One protected action. Exact canonical bytes. One `action_digest`. Fail-closed negative vectors. Signature-covered cross-reference for interop. Public artifacts only. No legal/commercial position and no patent license by publication.
