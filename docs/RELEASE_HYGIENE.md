# Release Hygiene

Public release boundary:

- Include source code, schemas, synthetic examples, deterministic vectors, public docs, and validation scripts. Generated public-evaluation reports are produced locally by `make qa`; do not include stale generated reports in the clean source ZIP unless separately archived and manifested.
- Exclude non-public commercial materials, non-public legal-review drafts, non-public legal mapping materials, EoU materials, non-public business language, commercial strategy, production credentials, live processor configuration, PAN/SAD, and production checkout code.
- Use only provider-neutral simulated identifiers.
- Treat the repository as standards-discussion and interoperability-review material only.
- Do not make production non-bypassability, compliance, certification, or patent-license claims.


## Digest-bound release pointer rule

- Use a fresh tag and fresh asset name for each active digest-bound review packet.
- Once a tag, asset name, and SHA-256 have been emailed or wired into a reviewer matrix, do not replace bytes under that same tag.
- If bytes change, publish a new tag, new asset name, and new sidecar; preserve the earlier tag as historical / superseded rather than deleting the audit trail.
- Active IETF reviewer-facing pointers for this packet should use `v2.2.5-public-eval` and `permit-receipt-ref-eval-v2_2_5-public-eval.zip`.


Release-lineage discipline:

- Do not replace a public release asset after a checksum has been shared.
- If any byte changes, issue a fresh tag, fresh asset name, fresh sidecar, and fresh checksum.
- Keep older tags available as historical references unless a safety or policy reason requires removal.
- Reviewer-facing pages should point to exactly one current public-evaluation tag.
