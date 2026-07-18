# PermitReceipt Public Evaluation Slice for AI-Agent External Effects

Synthetic source-available evaluation artifact for PermitReceipt-based permit-before-commit authorization of AI-agent and workload external effects.

This repository demonstrates how a protected external effect can be canonicalized, bound to an `action_digest`, checked against a `PermitReceipt` and policy epoch, evaluated for scope, validity, status/recency, issuer evidence, anti-replay state, and then either allowed or denied before commitment.

This repository is intended for standards discussion, interoperability review, and reproducible running-code review.

It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and it grants no patent license.

## IETF 126 remote review packet

For IETF 126 Hackathon review, start here:

```bash
python -m pip install -r requirements.txt
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python ietf126/independent_crypto_verify.py
```

Then inspect:

* `ietf126/results/review-summary.md`
* `ietf126/results/one-protected-action.json`
* `ietf126/results/canonical-request.bytes.txt`
* `ietf126/results/negative-vector-results.json`
* `ietf126/results/interop-crossref-results.json`
* `ietf126/results/independent-recompute-results.json`
* `ietf126/results/independent-crypto-verification.json`

The IETF 126 packet is under `ietf126/`. It is public-safe, synthetic, remote-reviewable, and designed around one protected action, exact canonical bytes, `action_digest` binding, fail-closed negative vectors, signature-covered cross-reference interop shape, a separate standard-library recomputation check that does not import the main verifier package, and independently implemented Ed25519 verification with tamper negatives.

## Current public-evaluation release

Current public evaluation tag:

`v2.2.6-public-eval`

Canonical release URL:

`https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.6-public-eval`

Current release asset:

`permit-receipt-ref-eval-v2_2_6-public-eval.zip`

Current checksum sidecar:

* `permit-receipt-ref-eval-v2_2_6-public-eval.zip.sha256`
* `permit-receipt-ref-eval-v2_2_6-public-eval.zip.manifest.json`
* `permit-receipt-ref-eval-v2_2_6-public-eval.zip.provenance.json`

Release status:

Public evaluation release. Not production software.

Release-lineage hygiene: this fresh tag is the canonical reviewer-facing pointer for the current public-evaluation packet. Do not replace release assets under this tag after checksum publication. If any byte changes, issue a fresh tag and fresh checksum.

Release asset hashes should be verified from the GitHub release assets generated at publication time. Do not treat an overlay ZIP hash as the full release artifact hash. Active IETF reviewer-facing release pointers are checked by `python tools/check_ietf126_release_pointers.py` and must point to `v2.2.6-public-eval`.

### Separate IETF 126 payment-composition input

A separate frozen pre-execution input for the scoped synthetic EUR payment-composition exercise is documented at [`docs/IETF126_PAYMENT_COMPOSITION_INPUT_v0_1.md`](docs/IETF126_PAYMENT_COMPOSITION_INPUT_v0_1.md). It does not modify or supersede `v2.2.6-public-eval` and is not a composition or interoperability result.

### v2.2.6 hardening profile

This release reconciles the authorization-reference schema, makes malformed-input behavior total and fail closed, requires strictly typed anti-replay material, makes constrained mode preserve all non-waivable checks, uses timezone-invariant validity parsing, binds capabilities to the active receipt, applies transactional replay reservations, rejects duplicate JSON keys, and adds independent signature verification. See `docs/SECURITY_HARDENING_v2_2_6.md`.

Measured source-tree evidence: 76/76 vectors, 323/323 tests with warnings treated as errors and third-party pytest plugins disabled, 20/20 IETF packet checks, 17/17 independent recomputation checks, 19/19 independent cryptographic checks, 99.33% statement and 98.44% branch coverage across the full `orprg_eval` package, 100.00% line and 99.705% branch coverage across the explicitly listed security-critical module set, 100.00% verifier branch coverage, and 100.00% strict-schema branch coverage.

## Related public materials

Related IETF Internet-Draft:
https://datatracker.ietf.org/doc/draft-lee-orprg-permit-receipts/

Related IETF IPR disclosure:
https://datatracker.ietf.org/ipr/7308/

## Terminology and public-boundary guide

Before interpreting this repository as a technical or standards artifact, review:

* `GLOSSARY.md`
* `docs/TERMINOLOGY_AND_BOUNDARY_GUIDE.md`
* `docs/EVALUATION_BOUNDARY.md`
* `docs/STANDARDS_STATUS_AND_IPR.md`
* `docs/PUBLIC_REVIEWER_GUIDE.md`
* `docs/REPRODUCIBILITY.md`
* `docs/VERSION_TAXONOMY.md`
* `docs/SECURITY_HARDENING_v2_2_6.md`
* `docs/PRE_RELEASE_AUDIT_CHECKLIST.md`
* `docs/PUBLIC_STEWARDSHIP.md`
* `docs/IETF126_RELEASE_POINTER_LOCK.md`
* `docs/RELEASE_PUBLISHING_PROTOCOL_v2_2_6.md`
* `docs/RELEASE_LINEAGE_v2_2_6.md`
* `docs/RELEASE_PROVENANCE_AND_ASSET_BINDING.md`
* `docs/REVIEWER_FAST_PATH_v2_2_6.md`

## IETF status

This repository is a companion public evaluation artifact for discussion around the individual Internet-Draft `draft-lee-orprg-permit-receipts`.

The draft is a work in progress. It is not an IETF standard, is not endorsed by the IETF, and has no formal standing in the IETF standards process.

## IPR and licensing status

A related IETF IPR disclosure exists for `draft-lee-orprg-permit-receipts`.

This repository does not grant a patent license, implied patent license, trademark license, standards commitment, production deployment right, certification right, or commercial implementation right. Any patent, trademark, production, commercial, or standards-licensing rights must be handled separately in writing by the applicable rights holder.

## Core idea

A protected external effect is not committed merely because an agent can call a tool or because a credential can be used.

A verifier must establish that the specific effect being attempted is authorized now, under the applicable policy epoch, scope, validity window, status/recency state, issuer evidence, and anti-replay requirements.

## Agentic-commerce profile

This repository includes a provider-neutral synthetic agentic-commerce profile as one example effect family.

The profile evaluates whether an AI-agent economic effect matches current authorization evidence before a synthetic provider adapter commits.

It does not process live payments, store PAN/SAD, call live processors, provide production non-bypassability, or replace wallets, issuers, PSPs, payment networks, network tokens, or settlement rails.

## 3-minute local demo

```bash
python -m pip install -r requirements.txt
python -m pip install -e . --no-deps  # portable editable-install smoke check
python -m paygate_hybrid.hybrid_demo
python tools/run_public_eval.py
```

Expected scenario outcomes:

```text
H01_ALLOW_joint_orprg_paygate_provider                    ALLOW  stage=COMMIT
H02_DENY_orprg_scope_before_paygate                       DENY   stage=ORPRG
H03_DENY_paygate_tsil_missing_after_orprg_allow           DENY   stage=PAYGATE_DOMAIN
H04_DENY_direct_provider_bypass_without_gate_token        DENY   stage=PROVIDER_ADAPTER
H05_DETECT_tetpay_evidence_tamper                         DENY   stage=AUDIT_ONLY_EVIDENCE_VALIDATION
```

## What is included

* Synthetic Python evaluation code.
* ORPRG-style external-effect evaluation components.
* Optional provider-neutral agentic-commerce profile.
* Deterministic canonicalization and action-digest binding.
* Policy epoch, validity, scope, anti-replay, status/recency, and evidence checks.
* Deterministic public evaluation vectors and verifier harness.
* Public evaluation examples for ALLOW and fail-closed DENY outcomes.
* IETF Hackathon project-page draft and release-hygiene materials.
* Public terminology and boundary guidance for avoiding false production, certification, conformance-program, or standards claims.

## What is not included

* No live payments.
* No PAN/SAD.
* No real processor credentials.
* No production checkout integration.
* No production authorization boundary.
* No production security claim.
* No official IETF reference implementation.
* No compliance certification.
* No certification program.
* No conformance program.
* No certificate registry.
* No public trust anchor.
* No non-public review annexes, legal mapping materials, commercial strategy materials, production credentials, or restricted business materials.
* No claim that this synthetic artifact proves production non-bypassability.
* No patent license grant.

## Local commands

```bash
make demo       # hybrid PermitReceipt + agentic-commerce profile demo
make paygate    # provider-neutral agentic-commerce profile scenarios
make ref        # provider-neutral reference-profile scenarios
make vectors    # deterministic ORPRG public evaluation vectors
make tests      # strict pytest suite; plugins disabled and warnings treated as errors
make gate       # public release hygiene gate
make eval       # public evaluation harness
make manifest   # regenerate static source manifest
make verify     # verify static source manifest
make validate   # validate required public-evaluation packet files
make release-pointers # verify active IETF reviewer-facing release links
make release-lineage # verify v2.2.6 release-lineage tuple
make ietf126    # IETF Hackathon selected review packet
make independent-interop # recompute canonical bytes/digests without importing the verifier package
make independent-crypto # independently verify receipt, revocation, and carrier signatures
make coverage   # combined coverage and security-core branch gates
make extended   # complete public-tooling reproducibility sweep; any self-reported failure exits nonzero
make ietf-preflight # full Hackathon preflight: eval + validate + verify + IETF packet + vectors + tests
make qa         # eval + packet validation + lineage/pointer/manifest + independent IETF checks
make artifact   # build and verify the deterministic four-asset release tuple
make package    # alias for the verified four-asset release build under dist/
```

## Verification

The v2.2.6 public-evaluation release is expected to pass:

```bash
python verify_manifest.py
python tools/validate_public_eval_packet.py
python tools/check_release_lineage.py
python tools/check_ietf126_release_pointers.py
make ietf-preflight
```

Expected results:

```text
verify_manifest.py: PASS
validate_public_eval_packet.py: PASS
check_release_lineage.py: PASS
IETF 126 selected review packet: 20 / 20 PASS
IETF 126 independent recomputation: 17 / 17 PASS
IETF 126 independent crypto verification: 19 / 19 PASS
ORPRG public evaluation vectors: 76 / 76 PASS
strict pytest: 323 / 323 PASS
orprg_eval statement coverage: 99.33%
orprg_eval branch coverage: 98.44%
security-critical line coverage: 100.00% (minimum 99%)
security-critical branch coverage: 99.705% (minimum 97.5%)
verifier branch coverage: 100.00%
strict-schema branch coverage: 100.00%
release pointer check findings: 0
release gate findings: 0
```

## Release boundary

This repository is a public technical evaluation slice only. It is intended for standards discussion, interoperability review, and reproducible running-code review.

It intentionally excludes non-public business, legal mapping, production, certification, conformance-program, or commercial-strategy materials.

Before using this artifact, review:

* `NOTICE.md`
* `LICENSE-EVALUATION.md`
* `PATENT-NOTICE.md`
* `docs/SECURITY_AND_LIMITATIONS.md`
* `GLOSSARY.md`
* `docs/TERMINOLOGY_AND_BOUNDARY_GUIDE.md`
* `docs/EVALUATION_BOUNDARY.md`
* `docs/STANDARDS_STATUS_AND_IPR.md`
* `docs/PUBLIC_REVIEWER_GUIDE.md`
* `docs/REPRODUCIBILITY.md`
* `docs/PRE_RELEASE_AUDIT_CHECKLIST.md`
* `docs/PUBLIC_STEWARDSHIP.md`
* `docs/RELEASE_PROVENANCE_AND_ASSET_BINDING.md`


## GitHub Web UI / manual upload note

This release is manual-upload friendly. The public evaluation manifest does not require `.github/` or `.gitignore` dotfiles, because browser and Finder upload flows often hide them. Optional GitHub Actions and issue-template files are provided as visible templates under `github-ui-files/`. See `docs/GITHUB_MANUAL_UPLOAD_GUIDE.md`. To materialize the optional dot-path files in a local checkout, run `python tools/materialize_github_files.py`.

## GitHub update / IETF 126 review

For the GitHub update, publish this as `v2.2.6-public-eval` with the GitHub pre-release checkbox left unchecked. The IETF Hackathon project page should point reviewers to:

```text
https://github.com/meridianverity/permit-receipt/tree/main/ietf126
```

Expected public checks:

```text
python ietf126/run_review_packet.py: PASS
python ietf126/independent_recompute.py: PASS
python ietf126/independent_crypto_verify.py: PASS
python run_vectors.py: PASS
python tools/run_public_eval.py: PASS
python tools/validate_public_eval_packet.py: PASS
python tools/check_release_lineage.py: PASS
python tools/check_ietf126_release_pointers.py: PASS
python verify_manifest.py: PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONWARNINGS=error python -m pytest -q: PASS
coverage report --fail-under=90: PASS
```
