# Version Taxonomy

The repository has distinct version axes:

- **Release package:** `v2.2.6-public-eval`; changes whenever any published asset byte changes.
- **Python distribution:** `2.2.6`; tracks the release package code revision.
- **Evaluator semantic family:** `ORPRG-Eval v3.2`; identifies the research/evaluation semantics and is not the package release number.
- **Canonicalization profile:** `CP-JSON-2`; changes only when canonical byte rules change.
- **Authorization-reference profile:** `orprg.authorization-ref.public-eval.v2`; identifies the selected cross-reference field model.
- **Authorization-reference carrier:** `PermitReceipt.authorization-ref.carrier.public-eval.v1`; identifies the signed carrier envelope.
- **Internet-Draft revision:** currently a separate `draft-lee-orprg-permit-receipts-*` revision axis controlled through the IETF process.

A package release does not imply a new Internet-Draft revision or a standards status change.
