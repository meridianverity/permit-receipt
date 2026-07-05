#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import json
import statistics
import time
from pathlib import Path
from orprg_eval.vector_factory import base_request, base_policy, make_receipt, make_revocation_state, add_merkle_proofs
from orprg_eval.verifier import verify_permit_receipt

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

def percentile(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = (len(xs)-1) * p / 100.0
    f = int(k)
    c = min(f+1, len(xs)-1)
    if f == c:
        return xs[f]
    return xs[f] + (xs[c]-xs[f]) * (k-f)

def bench_warm(n, merkle=False):
    pol = base_policy()
    pol["require_merkle_revocation_proof"] = merkle
    pol["require_transparency"] = merkle
    req = base_request()
    rec = make_receipt(req, policy=pol, nonce="bench-warm")
    rev = make_revocation_state()
    if merkle:
        rev = add_merkle_proofs(rev, rec)
    # Warm crypto caches.
    verify_permit_receipt(req, rec, pol, rev, {"now": pol["now"], "jurisdiction":"US", "resolved_tenant_id":"tenant-A"})
    lat = []
    canon = []
    sig = []
    revlat = []
    start = time.perf_counter()
    for _ in range(n):
        r = verify_permit_receipt(req, rec, pol, rev, {"now": pol["now"], "jurisdiction":"US", "resolved_tenant_id":"tenant-A"})
        if r.decision != "ALLOW":
            raise RuntimeError(r.to_dict())
        lat.append(r.timings_ns["total_ns"] / 1e6)
        canon.append(r.timings_ns.get("canonicalization_and_digest_ns", 0) / 1e6)
        sig.append(r.timings_ns.get("signature_verification_ns", 0) / 1e6)
        revlat.append(r.timings_ns.get("revocation_check_ns", 0) / 1e6)
    elapsed = time.perf_counter() - start
    return {
        "mode": "warm_merkle" if merkle else "warm_signed_list",
        "n": n,
        "elapsed_seconds": elapsed,
        "throughput_ops_per_sec": n / elapsed,
        "p50_ms": percentile(lat, 50),
        "p95_ms": percentile(lat, 95),
        "p99_ms": percentile(lat, 99),
        "canonicalization_p50_ms": percentile(canon, 50),
        "signature_p50_ms": percentile(sig, 50),
        "revocation_p50_ms": percentile(revlat, 50),
    }

def bench_cold(n):
    pol = base_policy()
    lat = []
    start = time.perf_counter()
    for i in range(n):
        req = base_request(); req["payload_digest"] = f"payload-{i}"
        rec = make_receipt(req, policy=pol, nonce=f"bench-cold-{i}")
        rev = make_revocation_state()
        r = verify_permit_receipt(req, rec, pol, rev, {"now": pol["now"], "jurisdiction":"US", "resolved_tenant_id":"tenant-A"})
        if r.decision != "ALLOW":
            raise RuntimeError(r.to_dict())
        lat.append(r.timings_ns["total_ns"] / 1e6)
    elapsed = time.perf_counter() - start
    return {
        "mode": "cold_unique_receipts",
        "n": n,
        "elapsed_seconds": elapsed,
        "throughput_ops_per_sec": n / elapsed,
        "p50_ms": percentile(lat, 50),
        "p95_ms": percentile(lat, 95),
        "p99_ms": percentile(lat, 99),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--warm-sizes", nargs="*", type=int, default=[1000], help="warm-path iteration counts; defaults are bounded for reviewer sandboxes")
    ap.add_argument("--cold-sizes", nargs="*", type=int, default=[100], help="cold-path iteration counts; defaults are bounded for reviewer sandboxes")
    ap.add_argument("--merkle-size", type=int, default=1000, help="Merkle-path iteration count; defaults are bounded for reviewer sandboxes")
    args = ap.parse_args()
    rows = []
    for n in args.warm_sizes:
        rows.append(bench_warm(n, merkle=False))
    rows.append(bench_warm(args.merkle_size, merkle=True))
    for n in args.cold_sizes:
        rows.append(bench_cold(n))
    (RESULTS / "benchmark_summary.json").write_text(json.dumps({"synthetic": True, "rows": rows}, indent=2, sort_keys=True), encoding="utf-8")
    with (RESULTS / "benchmark.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=sorted({k for r in rows for k in r}))
        writer.writeheader(); writer.writerows(rows)
    md = ["# Benchmark Summary", "", "Synthetic microbenchmark. Latency is environment-specific and not a production claim.", "", "| Mode | n | Throughput ops/s | p50 ms | p95 ms | p99 ms |", "|---|---:|---:|---:|---:|---:|"]
    for r in rows:
        md.append(f"| {r['mode']} | {r['n']} | {r['throughput_ops_per_sec']:.2f} | {r['p50_ms']:.4f} | {r['p95_ms']:.4f} | {r['p99_ms']:.4f} |")
    (RESULTS / "benchmark_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"synthetic": True, "rows": rows}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
