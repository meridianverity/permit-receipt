# Security and Limitations

This package demonstrates control-flow semantics, not production assurance.

It intentionally does not:

- move money;
- store cardholder data;
- call live processors;
- provide fraud scoring;
- implement PCI-scoped infrastructure;
- prove production non-bypassability;
- replace wallet, issuer, acquirer, network, PSP, merchant risk, or settlement controls;
- grant a patent license.

The security claim demonstrated by the synthetic artifact is narrow: without a verified PermitReceipt and a profile-specific DecisionReceipt/capability token, the synthetic provider adapter refuses to commit the modeled external effect.

Production hardening would require real threat modeling, HSM/KMS key custody, policy distribution security, status/revocation service design, split-brain handling, observability, incident response, processor integration review, and independent testing.
