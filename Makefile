.PHONY: demo paygate ref vectors tests eval gate manifest verify validate ietf126 ietf-preflight clean qa qa-full

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

ietf126:
	python ietf126/run_review_packet.py

ietf-preflight: qa-full

qa: eval validate verify ietf126

qa-full: eval validate verify ietf126 vectors tests

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ results checks ietf126/results tmp .mypy_cache
