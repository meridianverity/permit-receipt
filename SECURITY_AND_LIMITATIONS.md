# Security and Limitations

This repository is a synthetic public evaluation artifact. It is intended for standards discussion, interoperability review, reproducible running-code review, and non-production technical evaluation.

## Not production software

This repository is not production authorization infrastructure. It does not provide a production security boundary, production non-bypassability, production payment controls, compliance certification, or operational hardening.

Do not use this repository to process real payments, store payment-card data, call live processors, modify production checkout flows, operate production authorization logic, or make production security claims.

## Payment and data limitations

This repository does not include and must not be used with:

- Live payment credentials.
- PAN/SAD or cardholder data.
- Real processor credentials.
- Production PSP, wallet, issuer, network, or settlement-rail integrations.
- Production checkout, refund, chargeback, dispute, or settlement flows.
- Production secrets, signing keys, API keys, customer data, or regulated data.

## Security assumptions

The included examples demonstrate synthetic PermitReceipt-style verification behavior, including canonicalization, action-digest binding, policy-epoch checks, scope checks, status/recency checks, anti-replay handling, and fail-closed denial.

The examples do not prove that any production deployment is non-bypassable. Production deployment would require independent architecture review, threat modeling, code review, key-management design, revocation/status service design, operational monitoring, incident-response design, compliance review, and environment-specific hardening.

## Reporting issues

Please use GitHub Issues only for reproducibility problems, documentation gaps, and non-production evaluation questions.

Do not submit secrets, credentials, customer data, regulated data, exploit payloads, or confidential business information in issues, pull requests, comments, or discussions.

## Standards discussion

This repository is a companion evaluation artifact only. IETF standards discussion should occur on the relevant IETF mailing list or other appropriate IETF venue, not in this repository.
