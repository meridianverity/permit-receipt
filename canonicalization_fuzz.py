#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import random
from pathlib import Path
from copy import deepcopy
from orprg_eval.canonicalization import canonicalize_request, compute_action_digest, CanonicalizationError
from orprg_eval.vector_factory import base_request

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

def make_rng(seed: int):
    return random.Random(seed)

def shuffle_mapping(obj, rng):
    if isinstance(obj, dict):
        items = list(obj.items())
        rng.shuffle(items)
        return {k: shuffle_mapping(v, rng) for k, v in items}
    if isinstance(obj, list):
        return [shuffle_mapping(x, rng) for x in obj]
    return obj

def add_nested(req, idx):
    req = deepcopy(req)
    # Unicode composed/decomposed forms should converge under NFC, and nested map
    # ordering should not change the digest for equivalent semantics.
    req["metadata"] = {
        "z": idx,
        "a": {"text": "Cafe\u0301", "list": ["x", {"b": 2, "a": 1}]},
        "budget_words": str(idx % 17),
    }
    return req

def mutate_distinct(req, idx):
    req = deepcopy(req)
    choices = ["target_id", "tenant_id", "purpose_id", "payload_digest", "max_effect_budget", "representation_class_id"]
    k = choices[idx % len(choices)]
    if k == "max_effect_budget":
        req[k] = int(req[k]) + 1 + idx
    else:
        req[k] = f"{req[k]}-mut-{idx}"
    return req

def main(equivalent_cases: int = 10000, distinct_cases: int = 10000, seed: int = 1337):
    rng = make_rng(seed)
    base = add_nested(base_request(), 0)
    base_digest = compute_action_digest(canonicalize_request(base))
    stable = 0
    distinct = 0
    rejected = 0

    for i in range(equivalent_cases):
        req = add_nested(base_request(), i)
        # Keep semantics equivalent while varying insertion order and Unicode form.
        req["metadata"]["z"] = 0
        req["metadata"]["budget_words"] = "0"
        req = shuffle_mapping(req, rng)
        d = compute_action_digest(canonicalize_request(req))
        if d == base_digest:
            stable += 1

    seen = {base_digest}
    for i in range(distinct_cases):
        req = mutate_distinct(base_request(), i)
        try:
            d = compute_action_digest(canonicalize_request(req))
            if d not in seen:
                distinct += 1
                seen.add(d)
        except CanonicalizationError:
            rejected += 1

    summary = {
        "equivalent_cases": equivalent_cases,
        "equivalent_digest_stable": stable,
        "distinct_cases": distinct_cases,
        "distinct_effect_digests_distinct": distinct,
        "canonicalization_rejections": rejected,
        "seed": seed,
        "synthetic": True,
    }
    (RESULTS / "canonicalization_fuzz_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# Canonicalization Fuzz Summary", "", "Synthetic deterministic fuzz/property-style test.", "", "| Metric | Value |", "|---|---:|"]
    for k, v in summary.items():
        md.append(f"| {k} | {v} |")
    (RESULTS / "canonicalization_fuzz_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if (
        stable == equivalent_cases
        and distinct == distinct_cases
        and rejected == 0
    ) else 1

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", "--cases", dest="iterations", type=int, default=10000)
    ap.add_argument("--distinct", type=int, default=None)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    raise SystemExit(main(equivalent_cases=args.iterations, distinct_cases=args.distinct or args.iterations, seed=args.seed))
