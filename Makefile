.PHONY: demo paygate ref vectors tests coverage eval gate manifest verify validate release-pointers release-lineage ietf126 independent-interop independent-crypto extended package artifact ietf-preflight clean qa qa-full

PYTEST_ENV = PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONWARNINGS=error
ASSET = permit-receipt-ref-eval-v2_2_6-public-eval.zip
SIDECAR = $(ASSET).sha256
ASSET_MANIFEST = $(ASSET).manifest.json
ASSET_PROVENANCE = $(ASSET).provenance.json

demo:
	python -m paygate_hybrid.hybrid_demo

paygate:
	python -m paygate_poc.demo

ref:
	python scripts/run_paygate_ref.py

vectors:
	python run_vectors.py

tests:
	$(PYTEST_ENV) python -m pytest -q

coverage:
	python tools/coverage_gate.py
	python tools/check_core_coverage.py

gate:
	python tools/release_gate.py

eval:
	python tools/run_public_eval.py

manifest:
	python tools/make_public_manifest.py

verify:
	python verify_manifest.py

validate:
	python tools/validate_public_eval_packet.py

release-pointers:
	python tools/check_ietf126_release_pointers.py

release-lineage:
	python tools/check_release_lineage.py

ietf126:
	python ietf126/run_review_packet.py

independent-interop: ietf126
	python ietf126/independent_recompute.py

independent-crypto: ietf126
	python ietf126/independent_crypto_verify.py

artifact:
	python tools/build_release_asset.py --out-dir dist
	python tools/verify_release_artifact.py dist/$(ASSET) dist/$(SIDECAR) --manifest dist/$(ASSET_MANIFEST) --provenance dist/$(ASSET_PROVENANCE)

package: artifact

qa: eval validate release-lineage release-pointers verify ietf126 independent-interop independent-crypto

extended:
	$(PYTEST_ENV) python run_all.py

qa-full: qa vectors tests coverage extended

ietf-preflight: qa-full

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ */*/*/__pycache__ results checks ietf126/results tmp .mypy_cache .ruff_cache htmlcov *.egg-info
	rm -f .coverage coverage.json coverage.xml coverage-core.json
