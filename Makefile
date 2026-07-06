.PHONY: demo paygate ref vectors tests eval gate manifest verify validate release-pointers release-lineage ietf126 independent-interop package ietf-preflight clean qa qa-full

demo:
	python -m paygate_hybrid.hybrid_demo

paygate:
	python -m paygate_poc.demo

ref:
	python scripts/run_paygate_ref.py

vectors:
	python run_vectors.py

tests:
	python -m pytest -q

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

artifact:
	python tools/build_release_asset.py
	python tools/verify_release_artifact.py dist/permit-receipt-ref-eval-v2_2_5-public-eval.zip dist/permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256

package:
	python tools/build_release_asset.py --out-dir dist

ietf-preflight: qa-full

qa: eval validate release-lineage release-pointers verify ietf126

qa-full: eval validate release-lineage release-pointers verify ietf126 independent-interop vectors tests

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ results checks ietf126/results tmp .mypy_cache *.egg-info
