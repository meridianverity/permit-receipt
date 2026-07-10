# Security Hardening Summary — v2.2.6

The selected public-evaluation profile now treats all external structures as bounded untrusted input. Parsing rejects duplicate JSON members (including NFC-normalized collisions), floats, non-finite values, non-string object names, lone surrogates, oversized strings/containers/documents, excessive nesting, and integers outside the signed 64-bit profile.

PermitReceipt verification validates strict request, receipt, policy, context, revocation, and capability shapes before semantic use. A defensive outer boundary maps any unanticipated verifier exception to a stable fail-closed denial. Time values require timezone-aware RFC 3339. Replay nonces are required bounded strings and are reserved transactionally only after all semantic checks. Constrained operation cannot waive signature, action binding, scope, replay, or required capability checks.

This is defense-in-depth for a synthetic evaluation implementation, not a production-security claim. Deployment concerns such as key governance, trusted time, revocation distribution, effect-boundary non-bypassability, availability, multi-process replay infrastructure, operational monitoring, and formal security review remain outside the artifact.



This record maps the aggressive v2.2.5 audit findings to executable v2.2.6 controls.

| Audit area | v2.2.6 control | Machine evidence |
|---|---|---|
| Authorization-reference schema contradiction | One canonical v2 object model, alias `$ref`, signed carrier schema, runtime and Draft 2020-12 validation | `test_ietf126_authorization_ref_schema.py`; 20/20 packet |
| Verifier exceptions | Strict typed ingress plus outer total fail-closed boundary | signed malformed-input tests and vectors |
| Optional/type-confused nonce | Required bounded nonempty string for receipts and capabilities | nonce type matrix tests/vectors |
| Constrained-mode early ALLOW | Revocation freshness may be relaxed, but replay and capability checks execute before final constrained ALLOW | constrained replay/capability tests |
| Naive timestamps and one-sided drift | Explicit-zone RFC 3339; bool-safe integers; absolute drift | timezone/drift tests |
| Revocation-status ambiguity | Strict status enum and precedence; `revoked` always denies | status conflict and malformed-status tests |
| Capability receipt binding | Signed `receipt_digest` compared with active receipt core digest | binding mismatch vector/test |
| Receipt nonce burn on bad capability | Transactional reserve/commit/release replay API | rollback and persistent replay tests |
| Duplicate JSON members | Strict duplicate/NFC-collision rejecting JSON loader | HTTP and JSON ingress tests |
| Canonicalization edge cases | Bounded CP-JSON-2 profile with key/type/depth/size/integer/Unicode limits | unit boundary and fuzz/fault tests |
| Partial independent verification | Separate recomputation and no-package-import Ed25519 verifier with tamper negatives | 17/17 and 19/19 reports |
| SQLite resource warnings | Explicit connection lifecycle and transactional reservation schema | warnings-as-errors and reopen tests |
| Test depth | 323 strict tests; 76 vectors; 100.00% security-core line coverage; 99.705% security-core branch coverage; 100.00% verifier branch coverage | coverage and QA report |
| Supply chain | Version-bounded normal requirements plus a hash-locked certified QA/build environment, exact PEP 517 backend pins, and `--no-build-isolation` in certified CI | `requirements-lock-py313-linux-x86_64.txt`; pinned workflows |
| HTTP resource ambiguity | Content-length, body-size, duplicate-key, UTF-8, and route/method controls | HTTP ingress tests |

## Residual boundary

This is still a compact synthetic evaluation implementation, not production software. The Merkle non-inclusion model documents its sorted-set construction assumption; production replay deployment, key management, distributed state, operational availability, and governance remain outside the public evaluation boundary.
