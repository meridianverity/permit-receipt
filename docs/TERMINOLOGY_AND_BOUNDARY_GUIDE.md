# Terminology and Boundary Guide

The public evaluation slice should be easy to discuss and hard to misrepresent.

## Public posture

Use this posture consistently:

> Synthetic source-available evaluation artifact for PermitReceipt-based permit-before-commit authorization of AI-agent and workload external effects. Not production software. Not an IETF standard. Not an official IETF reference implementation. Not a certification or conformance program. No patent license.

## Required wording discipline

1. Say `public evaluation artifact`, `synthetic evaluation slice`, or `running-code review artifact`.
2. Avoid `reference implementation` unless the phrase is negated.
3. Say `public evaluation vectors`, not `conformance vectors`, in outward-facing materials.
4. Say `synthetic evaluation attestation`, not `conformance certificate`, in outward-facing materials.
5. Say `source-available evaluation artifact`, not `open-source implementation`.
6. Say `IETF discussion artifact`, not `IETF standard`.
7. Say `demonstrates synthetic fail-closed behavior`, not `proves production non-bypassability`.

## Why this matters

The public package contains real running code and deterministic examples. That makes the standards conversation more concrete, but it also creates a risk of overclaiming. The public artifact must not be confused with production enforcement, commercial licensing, certification, or official standards adoption.

## Public-private boundary

Public:

- bounded synthetic evaluation code;
- deterministic public evaluation vectors;
- public docs, glossary, and limitations;
- IETF discussion materials;
- local QA and manifest verification.

Private or separately licensed:

- production verifier service;
- receipt issuance service;
- production cryptographic key management;
- non-bypassable enforcement adapters;
- separately licensed signed test or interoperability suites;
- certificate or certification registries;
- partner-specific integrations;
- non-public legal mapping and claim charts;
- commercial deployment terms.

## Release-gate expectation

Every public release should pass:

```bash
make clean
python -m pip install -r requirements.txt
make eval
make validate
make manifest
make verify
```

Before public upload, also inspect generated `checks/release_gate_report.md` and confirm no positive overclaim patterns or restricted-publication markers appear.
