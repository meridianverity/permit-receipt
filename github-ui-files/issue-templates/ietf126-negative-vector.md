---
name: IETF 126 negative-vector request
description: Suggest a fail-closed DENY vector or missing interop negative case
title: "[negative-vector] "
labels: ["ietf126", "negative-vector"]
body:
  - type: textarea
    id: invariant
    attributes:
      label: Invariant to test
      description: What must fail closed?
    validations:
      required: true
  - type: textarea
    id: trigger
    attributes:
      label: Trigger condition
      description: What exact mismatch, missing evidence, stale state, or unsupported profile should cause DENY?
  - type: textarea
    id: expected
    attributes:
      label: Expected outcome
      description: Expected decision and denial reason, if any.
  - type: checkboxes
    id: boundary
    attributes:
      label: Public boundary
      options:
        - label: This issue contains no customer data, credentials, regulated data, claim charts, or commercial material.
          required: true
