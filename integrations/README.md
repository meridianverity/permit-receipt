# Production-adjacent integration contract examples

These files are review-only integration contract examples that show where ORPRG decisions sit in common enforcement stacks. They are not production Envoy, OPA, or Cedar configurations and are not evaluated as claims about those projects. The executable adapter tests in the artifact use the same ORPRG verifier and local HTTP boundary patterns.

- `envoy_ext_authz_bootstrap_fragment.yaml` sketches a fail-closed ext_authz cluster and filter shape.
- `opa_style_policy_baseline.rego` sketches a scope/token baseline that intentionally lacks receipt-bound proof obligations.
- `cedar_like_policy.cedar` sketches a Cedar-like policy shape for receipt-bound effect authorization.
