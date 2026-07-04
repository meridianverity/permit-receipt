# Architecture

This repository models a permit-before-commit path for external-effect authorization.

```text
AI/workload attempted effect
  -> deterministic canonicalization
  -> action_digest computation
  -> PermitReceipt verification
  -> policy epoch / validity / scope / status-recency / anti-replay checks
  -> optional domain-profile checks
  -> ALLOW synthetic provider-adapter commit or DENY fail-closed
```

The core evaluation model is provider-neutral and domain-neutral. PayGate is included only as one optional agentic-commerce profile that exercises exact-effect checks for a synthetic economic effect.

The code is designed for reproducible discussion, not production deployment.
