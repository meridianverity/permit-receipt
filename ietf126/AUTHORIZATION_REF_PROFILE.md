# Authorization Reference Profile — Public Evaluation Shape

Status: exploratory public evaluation shape for IETF 126 review. This is not a wire-format standard and not a production signature profile.

## Design rule

For ORPRG interop, a name is not authorization.

A downstream record may carry `action_id`, `action_type`, or other human-readable labels, but those labels are non-authorizing unless the record also carries a verifier-readable, signature-covered reference to the protected-action commitment.

## Primary model

The primary model is a **signature-covered authorization reference**.

Byte-identical digest equality is an optimization only when a shared test vector proves all of the following are identical:

- digest algorithm;
- domain-separation label, if any;
- canonicalization profile;
- field set;
- exact canonical bytes; and
- representation of prefixes and encoded values.

If any of those are unproven, the bridge is a cross-reference, not digest equality.

## Minimum public-eval shape

For one sample handoff, a covered `authorization_ref` or equivalent object should identify or commit to, directly or by digest/reference, where applicable:

```json
{
  "ref_profile": "orprg.authorization-ref.public-eval.v2",
  "reference_kind": "PermitReceipt",
  "artifact_digest": "<digest of referenced authorization artifact or its covered core>",
  "issuer_id": "<issuer or signer identifier>",
  "digest_algorithm": "sha-256",
  "canonicalization_profile_ref": "CP-JSON-2",
  "domain_sep": null,
  "protected_action_commitment": "<ORPRG action_digest or equivalent commitment>",
  "scope": {
    "effect_type": "DATA_EGRESS",
    "interface_id": "egress-gateway-1",
    "target_id": "partner-api-submit",
    "tenant_id": "tenant-A",
    "purpose_id": "support"
  },
  "validity": {
    "valid_from": "2026-06-02T00:00:00Z",
    "valid_to": "2026-06-04T00:00:00Z"
  },
  "epoch_id": 47,
  "anti_replay": {"nonce": "nonce-IETF126-ONE-PROTECTED-ACTION"},
  "signature_coverage": true,
  "failure_behavior": "DENY when unsupported, mismatched, stale, replayed, or unverifiable"
}
```

The field name is not important for IETF 126. The covered semantics are important.

## Fail-closed checks

The review packet rejects:

- name-only `action_id` / `action_type` without protected-action commitment;
- out-of-band metadata not covered by a signature or by the referenced artifact's own signature;
- unsupported `authorization_ref` profile;
- unsupported canonicalization profile;
- mismatched protected-action commitment;
- stale referenced status/evidence; and
- missing required fields.

Public boundary: this is a public shape check and not a cryptographic signature implementation. Actual signature verification belongs to the carrying artifact and/or the referenced artifact.
