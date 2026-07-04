# Release Decision Record — v2.2.4-public-eval

## Decision

Publish `v2.2.4-public-eval` as the GitHub pre-release / IETF 126 public review update after applying the integrated IETF 126 packet and regenerating the static manifest.

## Why this release exists

The prior public evaluation slice proved the standalone ORPRG path. This release adds the IETF 126 remote review lane:

- one protected action;
- exact canonical request bytes;
- one `action_digest`;
- fail-closed negative vectors;
- signature-covered cross-reference interop shape;
- public-safe submission text and Team Schedule text.

## Boundary

This release does not include claim charts, legal opinions, private implementation mapping, customer data, live payment or processor materials, production credentials, field-of-use analysis, or commercial rights.

## Release tag

`v2.2.4-public-eval`
