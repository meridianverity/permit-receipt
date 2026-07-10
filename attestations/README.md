# Public Evaluation Metadata

`synthetic_evaluation_attestation.json` binds the v2.2.6 validator components, the 76-vector corpus, independent-check counts, hash-locked dependency set, SBOM, policy input, and public limitations.

`source_provenance.json` is a deterministic in-toto/SLSA-shaped statement over the static source inventory. `../sbom.cdx.json` is the CycloneDX dependency inventory. The publication builder additionally emits an external provenance statement that binds the immutable ZIP digest, size, sidecar, asset manifest, source-tree digest, and release tag.

These files support reproducibility review. They are not production attestations, security warranties, compliance approvals, certificate-registry entries, public trust anchors, certification outputs, or conformance-program outputs.

No patent license, trademark license, service-mark license, product implementation right, certification right, conformance-program right, compliance approval, or endorsement is granted.
