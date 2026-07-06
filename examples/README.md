# Synthetic Example JSON Files

These examples are generated from the v2.2.5 public evaluation code and contain no live payment data, PAN, SAD, merchant secrets, bank credentials, or live settlement tokens.

Key examples:

- `h01_allow_joint_orprg_paygate_provider.json` — ORPRG + provider-neutral profile + synthetic provider-adapter allow.
- `h02_deny_orprg_scope_before_paygate.json` — scope denial at ORPRG before profile-specific checks.
- `h03_deny_paygate_tsil_missing_after_orprg_allow.json` — domain-evidence denial after ORPRG allow.
- `h04_deny_direct_provider_bypass_without_gate_token.json` — provider commit fence denial.
- `h05_detect_tetpay_evidence_tamper.json` — evidence-only tamper detection.
- `paygate_ref_*.json` — provider-neutral profile in-scope, out-of-scope, revoked, replay, and dispute/recourse examples.

To generate fresh run-output files locally, run:

```bash
python -m paygate_hybrid.hybrid_demo --out checks
```

Generated `checks/` and `results/` outputs are intentionally excluded from the static manifest and release ZIP.
