---
name: IETF 126 authorization_ref interop review
description: Review signature-covered authorization-reference behavior for public ORPRG interop
title: "IETF126 interop: "
labels: [ietf126, interop, authorization-ref]
body:
  - type: markdown
    attributes:
      value: |
        Use this template for public-safe feedback on `authorization_ref` / cross-reference behavior. Do not include customer data, credentials, production logs, claim charts, or non-public implementation mapping.
  - type: textarea
    id: artifact
    attributes:
      label: Public artifact or synthetic vector
      description: Link or describe the public artifact, synthetic vector, or field shape.
    validations:
      required: true
  - type: textarea
    id: covered-fields
    attributes:
      label: Signature-covered or commitment-covered fields
      description: Which fields are covered by the carrying artifact's signature or by the referenced artifact's own signature/commitment?
    validations:
      required: true
  - type: dropdown
    id: failure-behavior
    attributes:
      label: Expected failure behavior
      options:
        - DENY on mismatch
        - DENY on unsupported profile
        - DENY on unverifiable reference
        - HOLD pending more evidence
        - Unsure / needs discussion
    validations:
      required: true
  - type: textarea
    id: notes
    attributes:
      label: Notes
      description: Public-safe notes only.
