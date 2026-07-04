# Release Hygiene

Public release boundary:

- Include source code, schemas, synthetic examples, deterministic vectors, public docs, and validation scripts. Generated public-evaluation reports are produced locally by `make qa`; do not include stale generated reports in the clean source ZIP unless separately archived and manifested.
- Exclude non-public commercial materials, non-public legal-review drafts, non-public legal mapping materials, EoU materials, non-public business language, commercial strategy, production credentials, live processor configuration, PAN/SAD, and production checkout code.
- Use only provider-neutral simulated identifiers.
- Treat the repository as standards-discussion and interoperability-review material only.
- Do not make production non-bypassability, compliance, certification, or patent-license claims.
