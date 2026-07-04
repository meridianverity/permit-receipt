# Side-Meeting One-Pager

## Problem

AI-agent and workload systems increasingly attempt external effects: tool calls, data egress, retrieval, credential or key release, provider-adapter calls, inter-agent messages, and output release. A session-level, credential-level, or prompt-level authorization check may be stale by the time a concrete effect is committed.

## Approach

This public evaluation slice uses a permit-before-commit control path. The requested effect is canonicalized and hashed into an action digest. A PermitReceipt must verify against the current policy epoch, validity window, scope, status/recency, issuer evidence, and anti-replay state. Optional domain profiles can add effect-specific checks while preserving the same core model.

## Running-code proof points

1. ALLOW: exact authorized effect commits through a synthetic provider adapter.
2. DENY: ORPRG scope mismatch stops before profile-specific checks.
3. DENY: domain evidence missing under a profile requirement.
4. DENY: direct provider-adapter call rejected without a decision token.
5. DENY: evidence tamper detected.

## Requested feedback

- Is the receipt-envelope vocabulary sufficiently small?
- Which fields should be mandatory for interoperability?
- Should domain predicates be separate profiles from the core PermitReceipt model?
- Which denial codes are most useful to implementers?
- Which negative evaluation vectors should be added?
