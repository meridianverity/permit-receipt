# Git Update Checklist — v2.2.4-public-eval

Use this checklist for the GitHub update.

```bash
git checkout main
git pull --ff-only
# apply this repository state
python -m pip install -r requirements.txt
make clean
python make_manifest.py
python verify_manifest.py
make qa
python run_vectors.py
python -m pytest -q
git status --short
git add .
git commit -m "Add IETF 126 PermitReceipt review packet"
git tag -a v2.2.4-public-eval -m "PermitReceipt public evaluation v2.2.4 — IETF 126 review artifact"
git push origin main
git push origin v2.2.4-public-eval
```

Publish the GitHub release as a **pre-release** and attach the ZIP plus `.sha256` sidecar.
