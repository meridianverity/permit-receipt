# 90-Second Talk Track

AI agents and automated workloads increasingly cross boundaries: network egress, data access, tool calls, key release, output release, and state changes.

The PermitReceipt draft treats each protected external effect as a commit event. Before commit, an interceptor captures the effect request, canonicalizes the effect-relevant fields, computes an `action_digest`, and asks a verifier for ALLOW or DENY.

This packet makes that narrow claim runnable. Reviewers can run one command, inspect the exact bytes that were hashed, see the PermitReceipt decision path, and compare representative fail-closed negative vectors.

The interop point is equally narrow: if another artifact uses the same exact bytes and profile, digest equality can be proven by a shared vector. If it uses different canonicalization, the safe bridge is a signature-covered authorization reference. A name-only action identifier is not authorization.

The goal is not to claim production non-bypassability or create a standard by demo. The goal is to make the boundary precise enough that IETF reviewers can say what belongs in requirements, data model, conformance vectors, and future wire profiles.

