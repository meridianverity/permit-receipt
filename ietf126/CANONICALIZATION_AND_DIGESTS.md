# Canonicalization and Digest Rules

The public packet uses the repository's current synthetic profile:

```text
canonicalization_profile_ref: CP-JSON-2
digest_algorithm: sha-256
domain_sep: null in the current synthetic profile
action_digest_input: exact canonical request bytes
```

`CP-JSON-2` is not claimed to be RFC 8785 JCS. It is a synthetic profile used by this public evaluation packet.

For this packet, digest equality requires all of the following:

1. same digest algorithm;
2. same domain-separation rule, including an explicit `null` if no domain separation is used;
3. same canonicalization profile;
4. same field set;
5. exact same canonical bytes; and
6. same representation of prefixes, encoded values, Unicode, numbers, and object ordering.

If any of those differ, the relation is an explicit signature-covered cross-reference, not digest equality.

A name-only or semantic reference is non-authorizing for ORPRG review purposes.

## Reviewer command

```bash
python ietf126/run_review_packet.py
cat ietf126/results/canonical-request.bytes.txt
cat ietf126/results/canonical-request.hex.txt
```

The packet intentionally writes both UTF-8 and hex views so reviewers can compare the exact digest input.

