# QA Report — v2.2.4-public-eval

Status: PASS.

This revision includes the scope-constrained `max_effect_budget` omission hardening check: a request that omits `max_effect_budget` while the receipt scope constrains it fails closed with `DRC-005_SCOPE_VIOLATION`.

This report records the local checks run before packaging the Git-ready v2.2.4 public evaluation update.

## Commands

```text
make clean                                      PASS
python make_manifest.py                         PASS — 181 static entries
python verify_manifest.py                       PASS — 181 / 181 static files
make qa                                         PASS
make ietf-preflight                              PASS
python run_vectors.py                           PASS — 65 / 65 vectors
python -m pytest -q                             PASS — 21 / 21 tests
python ietf126/run_review_packet.py             PASS — 17 / 17 selected packet checks
python ietf126/independent_recompute.py          PASS — 17 / 17 recomputation checks
tools/release_gate.py                          PASS — attestation version/digest drift check included
```

## make qa summary

```text
tools/run_public_eval.py              PASS — 6 / 6 harness steps
tools/validate_public_eval_packet.py  PASS — ok=true, release_gate_exit=0, release_pointer_check_exit=0
tools/check_ietf126_release_pointers.py PASS — ok=true, finding_count=0
verify_manifest.py                    PASS — ok=true, 181 / 181
ietf126/run_review_packet.py          PASS — runner_mode=full-repository, 17 / 17
ietf126/independent_recompute.py       PASS — 17 / 17
```

## Public boundary

Synthetic public evaluation artifact only. No production data, no customer data, no regulated data, no live payment or processor materials, no claim charts, no legal/commercial position, and no patent license by publication.

## Reviewer path

```bash
python -m pip install -r requirements.txt
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
cat ietf126/results/review-summary.md
```

## Manual-upload friendly release hygiene

The manifest intentionally excludes optional GitHub dotfiles (`.github/` and `.gitignore`) so browser/Finder upload flows do not break reproducibility checks. Visible templates are provided under `github-ui-files/`, and `tools/materialize_github_files.py` can recreate the dot-path files in a local checkout.
