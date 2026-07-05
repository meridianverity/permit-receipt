# Negative Vector Plan

The remote review should prioritize fail-closed behavior.

## Executable selected vectors in this packet

The runner selects representative vectors from the repository public vector set:

1. missing PermitReceipt fails;
2. action digest mismatch fails;
3. scope mismatch fails;
4. expired validity window fails;
5. stale revocation/status evidence fails;
6. anti-replay failure fails;
7. unsupported canonicalization profile fails; and
8. transparency proof missing fails with `DRC-053_TRANSPARENCY_PROOF_MISSING` where policy requires it.

## Interop shape checks in this packet

The runner also emits candidate interop checks for a signature-covered authorization reference profile:

1. signature-covered matching `authorization_ref` is bound;
2. name-only `action_id` / `action_type` without signature-covered authorization reference fails;
3. unsigned out-of-band reference fails;
4. protected-action commitment mismatch fails;
5. unsupported cross-reference profile fails; and
6. stale status or evidence marker fails.

## Candidate future public vectors

- selective-disclosure authorization proof;
- Merkle commitment to a subset of canonical request fields;
- delegated authority revocation propagation;
- quote freshness nonce once an attestation profile is in scope;
- multi-profile digest equality vector with declared domain separation; and
- downstream signed-record pivot carrying both action reference and outcome digest.

