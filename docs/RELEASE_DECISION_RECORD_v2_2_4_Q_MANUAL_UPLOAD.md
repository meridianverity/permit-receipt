# Release Decision Addendum — v2.2.4 manual-upload-friendly Q profile

## Decision

Keep the IETF 126 public evaluation packet runnable without requiring hidden dot-path files in the source archive or GitHub Web UI upload flow.

## Rationale

GitHub Actions and issue templates conventionally live under `.github/`, and ignore rules conventionally live in `.gitignore`. Those names are useful for a Git checkout, but they are often inconvenient for manual upload through browser or Finder flows.

The public evaluation evidence does not depend on those files. Therefore:

- `.github/` and `.gitignore` are excluded from the static public evaluation manifest;
- visible template copies are provided under `github-ui-files/`;
- `tools/materialize_github_files.py` can recreate the optional dot-path files when a local checkout is available;
- `python verify_manifest.py`, `python ietf126/run_review_packet.py`, `python ietf126/independent_recompute.py`, `python tools/check_ietf126_release_pointers.py`, and `make qa` remain the core public review checks.

## Boundary

This addendum does not change the ORPRG protocol posture, IETF status, public evaluation boundary, licensing/IP posture, or production/non-production disclaimer.
