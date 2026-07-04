# Glossary and Boundary Language

This glossary supports standards discussion, interoperability review, and reproducible running-code review for the PermitReceipt public evaluation slice.

It is not an API contract, not a wire format, not a formal standard, not a patent claim chart, not a legal opinion, not a compliance certification, not a conformance program, and not an implementation disclosure for production deployment.

## Core terms

### Protected external effect

An operation that crosses an execution boundary and may disclose information, change state, invoke a privileged operation, release output, delegate authority, or alter future effect semantics.

### Effect boundary

The logical or physical boundary between an execution substrate and an external interface at which a protected external effect would be committed.

### Permit-before-commit

A control-flow posture in which a protected external effect is not committed unless required verification succeeds before the effect boundary.

### PermitReceipt

A machine-verifiable authorization artifact that binds an external-effect request to policy, epoch, validity, scope, action binding, authenticity evidence, and required status evidence.

### Canonical request representation

A deterministic representation of an external-effect request containing effect-relevant fields selected for evaluation.

### `action_digest`

A digest computed over the canonical request representation. In this public evaluation slice, the `action_digest` is used to show action binding in deterministic examples.

### Policy epoch

A policy-state version or epoch used to evaluate whether authorization evidence is current for the attempted effect.

### Policy digest

A digest or identifier committing to the policy material relevant to the attempted effect.

### Scope

The effect constraints being evaluated, such as interface, action type, target, purpose, budget, jurisdiction, identity, or use-case bounds.

### Validity window

The time or sequence interval during which authorization evidence may be considered usable for a given effect.

### Status/recency evidence

Evidence used to determine whether relevant authorization, revocation, policy, or issuer state is current enough for the attempted effect.

### Issuer evidence

Evidence that a PermitReceipt or related artifact was issued by an acceptable authority for the relevant policy epoch and scope.

### Anti-replay state

State, counters, nonces, or equivalent checks used to prevent reuse of old authorization evidence for a materially new or stale effect attempt.

### Verifier

A component in the evaluation model that evaluates the request, PermitReceipt, policy state, revocation/status state, explicit context, and anti-replay evidence and returns an ALLOW or DENY outcome with evidence digests and reason codes when applicable.

### ALLOW

A synthetic evaluation outcome indicating that the modeled effect passed the public evaluation checks and may proceed to the synthetic provider adapter.

### DENY

A fail-closed synthetic evaluation outcome indicating that the modeled effect is not committed in the public evaluation artifact.

### Fail closed

The default behavior in which missing, stale, ambiguous, conflicting, malformed, revoked, replayed, unsupported, or unverifiable evidence results in DENY.

### Denial reason code

A machine-readable code explaining why the synthetic evaluation denied the attempted effect.

### DecisionReceipt / capability token

A synthetic artifact used by the demo flow to show that downstream provider-adapter commitment depends on a prior verification result. In this public evaluation slice, it is not a production token, not a public trust anchor, and not a deployment credential.

### Public evaluation vector

A deterministic example input and expected output used for reproducible public review of the synthetic evaluation behavior. It is not a certification vector, not a procurement acceptance test, and not a production conformance test.

### Synthetic evaluation attestation

A public, non-production evidence object showing that this package's synthetic evaluation checks were run. It is not a conformance certificate, not a compliance certificate, and not a certification result for a real implementation.

### Agentic-commerce profile

An optional provider-neutral synthetic effect family showing how a PermitReceipt-style evaluation can be applied to a modeled economic effect. It does not process live payments, store PAN/SAD, call live processors, or replace wallets, issuers, PSPs, payment networks, network tokens, or settlement rails.

### Provider adapter

A synthetic adapter used in examples to model a protected effect sink. It is not a live provider integration and does not represent production non-bypassability.

## Boundary terms

### Public evaluation artifact

Preferred. A bounded package for standards discussion, interoperability review, and reproducible running-code review.

### Running-code review

Preferred. A review activity in which deterministic examples can be executed locally to make the technical discussion more concrete.

### Source-available evaluation artifact

Preferred. The repository may be viewed and run for evaluation under the evaluation license. This should not be described as an open-source implementation unless a separate open-source license and patent posture are intentionally adopted.

### Avoid: reference implementation

Avoid. This repository is not an official IETF reference implementation and not a production reference implementation. Use `public evaluation artifact` or `synthetic evaluation slice` instead.

### Avoid: conformance suite

Avoid for this public repository. Use `public evaluation vectors` unless a separate private/licensed conformance program is intentionally launched.

### Avoid: certification program / certificate registry

Avoid. This public repository does not certify implementations and does not operate a certificate registry. Use `synthetic evaluation attestation` for public QA evidence.

### Production non-bypassability

Avoid unless negated. This public repository demonstrates synthetic fail-closed behavior only. It does not prove production non-bypassability.

### Avoid: IETF standard

Avoid unless negated. The related Internet-Draft is a work in progress, and this repository is not endorsed by the IETF.

## Preferred wording

| Avoid | Use instead |
|---|---|
| avoid: reference implementation | use: public evaluation artifact |
| avoid: open-source implementation | use: source-available evaluation artifact |
| avoid: conformance suite | use: public evaluation vectors |
| avoid: conformance certificate | use: synthetic evaluation attestation |
| avoid: certification program | use: no certification program; evaluation only |
| avoid: public trust anchor | use: no public trust anchor; local synthetic checks only |
| avoid: production-ready | use: non-production public evaluation slice |
| avoid: proves non-bypassability | use: demonstrates synthetic fail-closed denial semantics |
| avoid: official IETF implementation | use: companion artifact for IETF discussion |

## One-sentence public posture

Open enough running code to make the standardization conversation honest. Protect enough mechanism to keep production safety, licensing, and accountability intact.
