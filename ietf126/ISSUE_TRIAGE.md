# Issue Triage Guide

Use short issue titles that start with one of these labels:

- `[field-model]` unclear or missing PermitReceipt field
- `[canonicalization]` byte representation or digest question
- `[negative-vector]` missing DENY case
- `[cross-reference]` signature-covered authorization reference shape
- `[draft-split]` requirements / architecture / data model / conformance / wire-profile split
- `[security]` threat model or failure semantic issue
- `[privacy]` selective disclosure or minimization question

Good issue examples:

- `[canonicalization] Should profile IDs include domain_sep explicitly?`
- `[negative-vector] Add DENY for unsignature-covered authorization_ref metadata`
- `[cross-reference] Minimal field set for verifier-readable authorization_ref`

Do not include customer data, secrets, regulated data, production logs, claim charts, or commercial materials.

