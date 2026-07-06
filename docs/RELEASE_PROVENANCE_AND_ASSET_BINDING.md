# Release Provenance and Asset Binding — v2.2.5-public-eval

This file is the reviewer-facing provenance note for the active public evaluation pointer.

## Canonical tuple

```text
Tag:      v2.2.5-public-eval
Asset:    permit-receipt-ref-eval-v2_2_5-public-eval.zip
Sidecar:  permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
Release:  https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.5-public-eval
```

The review pointer is the tuple above, not the tag name alone.

## Why this exists

This release is a fresh-tag review pointer. It supersedes `v2.2.4-public-eval` for active review-reference purposes because same-tag asset refresh ambiguity is exactly the kind of ambiguity a digest-binding exercise should avoid.

A benign asset refresh and an unintended byte change are not distinguishable from a name-only pointer. The public review path therefore uses a fresh tag, a fresh asset name, a sidecar that names that asset exactly, and local verification commands.

## Reviewer verification after download

From the directory containing the downloaded ZIP and sidecar:

```bash
sha256sum -c permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
unzip -q permit-receipt-ref-eval-v2_2_5-public-eval.zip
cd permit-receipt-main 2>/dev/null || cd permit-receipt-ref-eval-v2_2_5-public-eval
python -m pip install -r requirements.txt
python verify_manifest.py
python tools/validate_public_eval_packet.py
python tools/check_release_lineage.py
python tools/check_ietf126_release_pointers.py
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
python run_vectors.py
python -m pytest -q
```

Expected results:

```text
sha256sum -c:                 OK
Manifest verification:        PASS
Packet validation:            PASS
Release lineage check:        PASS
Release pointer check:        PASS
IETF review packet:           17 / 17 PASS
Independent recomputation:    17 / 17 PASS
Evaluation vectors:           65 / 65 PASS
Pytest:                       21 / 21 PASS
```

## Publisher rule

If bytes behind an active review pointer need to change after publication, do not replace the active asset in place. Publish a fresh tag and a fresh asset name, then update this lock file and reviewer-facing pointers.

## Boundary

This note is about public artifact reproducibility and review hygiene. It is not a certification program, not a conformance program, not an endorsement, not production authorization, and not a patent license grant.
