# QA Report — v2.2.5-public-eval

Status: PASS.

This report records the local checks run before packaging the v2.2.5 public evaluation packet.

## Commands

```text
make clean                                      PASS
python make_manifest.py                         PASS — 192 static entries
python verify_manifest.py                       PASS — 192 / 192 static files
python tools/check_release_lineage.py           PASS — finding_count=0
python tools/check_ietf126_release_pointers.py  PASS — finding_count=0
make qa-full                                    PASS
```

## make qa-full summary

```text
tools/run_public_eval.py              PASS — 6 / 6 harness steps
tools/validate_public_eval_packet.py  PASS — ok=true, release_gate_exit=0, release_lineage_check_exit=0, release_pointer_check_exit=0
tools/check_release_lineage.py         PASS — ok=true, finding_count=0
tools/check_ietf126_release_pointers.py PASS — ok=true, finding_count=0
verify_manifest.py                    PASS — ok=true, 192 / 192
ietf126/run_review_packet.py          PASS — runner_mode=full-repository, 17 / 17
ietf126/independent_recompute.py       PASS — 17 / 17
run_vectors.py                        PASS — 65 / 65
python -m pytest -q                   PASS — 21 / 21
```

## Release-lineage checks

The v2.2.5 packet adds an explicit release-lineage check so that active reviewer-facing files point to the fresh canonical tag and asset name.

```text
canonical tag:      v2.2.5-public-eval
canonical asset:    permit-receipt-ref-eval-v2_2_5-public-eval.zip
canonical sidecar:  permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
```

## Boundary check

The release gate scans for restricted-publication markers, embedded ZIP files, unexpected binary files, and positive overclaim patterns. The observed result was zero findings.

Public boundary: synthetic public evaluation artifact only. No production data, no customer data, no regulated data, no live payment or processor materials, no claim charts, no legal/commercial position, and no patent license by publication.
