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

The canonical machine-readable field model is
`ietf126/schemas/authorization_ref.public-eval.v2.schema.json`. The unversioned
schema filename is a compatibility alias that resolves to that canonical schema.

For one sample handoff, the signature-covered `authorization_ref` is shaped as
follows (digest values abbreviated here for readability):

```json
{
  "ref_profile": "orprg.authorization-ref.public-eval.v2",
  "ref_kind": "PermitReceipt",
  "ref_artifact_digest": "sha256:<64 lowercase hex characters>",
  "issuer_or_signer": "issuer-operator-synth",
  "digest_algorithm": "sha-256",
  "canonicalization_profile_ref": "CP-JSON-2",
  "domain_sep": "PermitReceipt.authorization_ref.public-eval.v2",
  "action_commitment": "sha256:<64 lowercase hex characters>",
  "audience": "egress-gateway-1",
  "scope": {
    "effect_type": "DATA_EGRESS",
    "interface_id": "egress-gateway-1",
    "action_type": "POST",
    "target_id": "partner-api-submit",
    "tenant_id": "tenant-A",
    "purpose_id": "support",
    "representation_class_id": "json-v1",
    "max_effect_budget": 10
  },
  "valid_from": "2026-06-02T00:00:00Z",
  "valid_until": "2026-06-04T00:00:00Z",
  "policy_epoch": 47,
  "anti_replay": {
    "nonce_commitment": "sha256:<64 lowercase hex characters>"
  },
  "signature_coverage": true,
  "status": "valid",
  "verifier_behavior": {
    "on_unsupported_profile": "DENY",
    "on_mismatch": "DENY",
    "on_unverifiable": "DENY"
  }
}
```

The carrying object is separately described by
`authorization_ref_carrier.public-eval.v1.schema.json`. Its signature covers the
complete canonical `authorization_ref` object. The anti-replay field exposes a
commitment to the receipt nonce rather than the nonce itself.

Field names are fixed for this public-evaluation profile. A future experiment may
choose another model only under a new profile identifier and schema; mixing the
old descriptive names with the v2 schema is invalid.

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
