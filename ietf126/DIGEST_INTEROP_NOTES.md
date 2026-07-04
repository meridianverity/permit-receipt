# Digest Interop Notes — Public-Safe IETF 126 Review

This packet keeps the ORPRG review narrow:

- PermitReceipt is the pre-commit authorization predicate at the protected-effect boundary.
- Delegation, mandate, record, and attestation artifacts may remain independently owned.
- Interop can use either byte-identical digest equality or a verifier-readable, signature-covered cross-reference.

## Two digest families

The safe model is not one digest through every layer.

1. **Request/action family:** canonical protected-action request → ORPRG `action_digest` → mandate/delegation commitment → record authorization reference.
2. **Outcome/response family:** signed record outcome/response digest → attestation or runtime evidence binding.

A record can be the pivot only if it carries both sides under signature or under a referenced artifact's signature-covered commitment.

## Equality is earned, not assumed

`sha256(json.dumps(...))`, `H_JCS(...)`, and `sha256:<hex>` strings are not automatically the same commitment.

Digest equality requires the same digest algorithm, domain-separation label if any, canonicalization profile, field set, exact canonical bytes, and encoding conventions. Otherwise the packet marks the handoff as a cross-reference.

## Name-only references are non-authorizing

`action_id`, `action_type`, route names, display labels, event names, or semantic descriptions are useful for humans and logs, but they do not authorize an ORPRG protected effect unless the signed or signature-covered payload also commits to the ORPRG `action_digest` or equivalent protected-action commitment.

## Freshness language

Static identifiers can provide replay evidence or uniqueness evidence. They are not verifier freshness. A quote, attestation, or runtime evidence path should be described as freshness-bound only when a fresh verifier challenge is carried in the signed or quoted data and checked by the verifier profile.

## Public boundary

Exploratory interoperability against the public ORPRG PermitReceipt draft. Public artifacts only. Software or emulated attestation must be labeled as such. No endorsement, certification, production authorization, license, merged protocol, legal/commercial position, or implied rights.
