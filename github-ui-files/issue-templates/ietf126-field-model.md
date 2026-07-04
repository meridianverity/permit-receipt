---
name: IETF 126 field-model review
description: Field clarity or abstract data model feedback for the PermitReceipt review packet
title: "[field-model] "
labels: ["ietf126", "field-model"]
body:
  - type: textarea
    id: field
    attributes:
      label: Field or model concern
      description: Which field, relationship, or model concept is unclear?
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected clarification
      description: What would make it easier to implement or review?
  - type: checkboxes
    id: boundary
    attributes:
      label: Public boundary
      options:
        - label: This issue contains no customer data, credentials, regulated data, claim charts, or commercial material.
          required: true
