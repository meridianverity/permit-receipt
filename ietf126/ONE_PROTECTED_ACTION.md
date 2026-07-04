# One Protected Action

The IETF 126 packet starts with one synthetic protected external effect.

| Field | Synthetic value |
|---|---|
| Effect family | Synthetic data egress |
| Effect type | `DATA_EGRESS` |
| Interface | `egress-gateway-1` |
| Action type | `POST` |
| Target | `partner-api-submit` |
| Tenant | `tenant-A` |
| Purpose | `support` |
| Representation | `json-v1` |
| Budget | `10` synthetic effect units |
| Payload digest | Synthetic placeholder only |

The action is not a live payment, live API call, regulated record, production log, or customer transaction.

The evaluation question is whether the exact effect request is canonicalized, bound to an `action_digest`, evaluated against a PermitReceipt and current policy/status evidence, and allowed or denied before commit.

The positive path is deliberately narrow. The negative vectors are the core of the review.

## Why one action is enough

The packet is designed to make the security predicate falsifiable. If the same exact request bytes produce a different digest, the review should stop. If a different request can reuse the PermitReceipt, the review should fail. If missing, stale, unsupported, or unverifiable evidence can reach commit, the review should fail.

