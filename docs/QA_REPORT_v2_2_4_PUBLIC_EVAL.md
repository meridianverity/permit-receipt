# QA Report — v2.2.4-public-eval

Status: PASS.

This report records the local checks run before packaging the Git-ready v2.2.4 public evaluation update.

## Commands

```text
make clean                                      PASS
python make_manifest.py                         PASS — 170 static entries
python verify_manifest.py                       PASS — 170 / 170 static files
make qa                                         PASS
python run_vectors.py                           PASS — 64 / 64 vectors
python -m pytest -q                             PASS — 11 / 11 tests
python ietf126/run_review_packet.py             PASS — 16 / 16 selected packet checks
```

## make qa summary

```text
tools/run_public_eval.py              PASS — 6 / 6 harness steps
tools/validate_public_eval_packet.py  PASS — ok=true, release_gate_exit=0
verify_manifest.py                    PASS — ok=true
ietf126/run_review_packet.py          PASS — runner_mode=full-repository, 16 / 16
```

## Public boundary

Synthetic public evaluation artifact only. No production data, no customer data, no regulated data, no live payment or processor materials, no claim charts, no legal/commercial position, and no patent license by publication.

## Reviewer path

```bash
python -m pip install -r requirements.txt
python ietf126/run_review_packet.py
cat ietf126/results/review-summary.md
```

## Manual-upload friendly release hygiene

The manifest intentionally excludes optional GitHub dotfiles (`.github/` and `.gitignore`) so browser/Finder upload flows do not break reproducibility checks. Visible templates are provided under `github-ui-files/`, and `tools/materialize_github_files.py` can recreate the dot-path files in a local checkout.
