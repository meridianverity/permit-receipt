# Pre-Release Audit Checklist

Use this checklist before publishing any public evaluation slice. The filename is retained for continuity with earlier review packets; the current active public-evaluation release is `v2.2.5-public-eval` with the GitHub pre-release checkbox unchecked.

## Boundary check

- [ ] Public synthetic artifacts only.
- [ ] No customer data, PAN/SAD, regulated payment data, production logs, live credentials, live processor configuration, claim charts, non-public legal mapping, commercial strategy, or restricted annexes.
- [ ] README and release notes say the artifact is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and not a patent license grant.
- [ ] No public text claims production non-bypassability, certification, compliance approval, IETF endorsement, commercial commitment, certificate-registry operation, or production authorization.

## Reproducibility check

- [ ] `python tools/make_public_manifest.py`
- [ ] `python verify_manifest.py`
- [ ] `python tools/release_gate.py`
- [ ] `python tools/validate_public_eval_packet.py`
- [ ] `python tools/check_release_lineage.py`
- [ ] `python tools/check_ietf126_release_pointers.py`
- [ ] `python ietf126/run_review_packet.py`
- [ ] `python ietf126/independent_recompute.py`
- [ ] `python run_vectors.py`
- [ ] `python -m pytest -q`
- [ ] `make qa-full`

Expected public checks:

```text
Manifest verification:        PASS
Release gate:                 PASS
Packet validation:            PASS
Release lineage check:        PASS
Release pointer check:        PASS
IETF review packet:           17 / 17 PASS
Independent recomputation:    17 / 17 PASS
Evaluation vectors:           65 / 65 PASS
Pytest:                       21 / 21 PASS
QA full:                      PASS
```

## Release pointer check

- [ ] GitHub release tag is `v2.2.5-public-eval`.
- [ ] Release title is `v2.2.5 Public Evaluation — IETF 126 Review Packet`.
- [ ] Release asset is `permit-receipt-ref-eval-v2_2_5-public-eval.zip`.
- [ ] Sidecar asset is `permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256`.
- [ ] Sidecar line names `permit-receipt-ref-eval-v2_2_5-public-eval.zip` exactly.
- [ ] Active reviewer-facing text uses `https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.5-public-eval`.
- [ ] Superseded prior public-evaluation references appear only in historical / superseded context.

## Fresh-tag rule

Once the release tag, asset name, and digest have been emailed or wired into a reviewer matrix, do not replace the bytes under that same tag. If the release asset changes, publish a fresh tag, fresh asset name, fresh sidecar, and fresh emailed checksum.

## Upload posture

GitHub release: leave the pre-release checkbox **unchecked** for `v2.2.5-public-eval`.

`Latest` is a release-manager choice; it is acceptable once this tag is intended to be the active public-evaluation entry point.

Attach the ZIP and SHA-256 sidecar only. ZIP: `permit-receipt-ref-eval-v2_2_5-public-eval.zip`. Sidecar: `permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256`.

## Human review gate

Before broader promotion, perform counsel/IP/trademark/public-disclosure review. This checklist is not legal advice.
