# Evaluation Boundary

This repository is deliberately narrow.

It opens enough running code to make standards and interoperability discussion concrete. It does not open the production mechanism.

## This public slice demonstrates

- deterministic canonicalization of modeled external-effect requests;
- action-digest binding;
- PermitReceipt evaluation;
- policy epoch, validity, scope, status/recency, issuer-evidence, and anti-replay checks;
- fail-closed ALLOW / DENY outcomes in a synthetic harness;
- one optional provider-neutral agentic-commerce profile; and
- deterministic public evaluation vectors for reproducible review.

## This public slice does not provide

- No production software;
- No production non-bypassability;
- No production checkout, payment, PSP, issuer, network-token, or settlement integration;
- No live payment processing;
- No PAN/SAD handling;
- No real processor credentials;
- No production policy distribution;
- No production key management;
- No production status/revocation service design;
- No formal certification;
- No conformance program;
- No certificate registry;
- No official IETF reference implementation; or
- No patent license.

## Why this boundary matters

The public-good purpose is to let reviewers see and debate the core question: can a protected external effect be evaluated before commitment against current, scope-bound evidence?

The safety and rights-boundary purpose is to avoid misleading copycat deployments, false certification claims, and accidental disclosure of production or commercial implementation materials.

The release rule is:

```text
Open enough running code to make the conversation honest.
Protect enough mechanism to keep production safety, licensing, and accountability intact.
```
