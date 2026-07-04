#!/usr/bin/env python3
"""HTTP-envelope canonicalization differential fuzzing for ORPRG-Eval v3.2.

This adds a second representation family beyond the strict JSON object profile:
HTTP-like method/path/query/header/body envelopes. Equivalent envelopes vary
header case/order, query ordering, and JSON body field order; distinct envelopes
mutate effect-relevant method, path, query, body, tenant, and destination fields.
"""
from __future__ import annotations

import hashlib
import json
import random
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
SEED = 20260604


def _canonical_body(body: Any) -> str:
    if isinstance(body, (dict, list)):
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if body is None:
        return ""
    return str(body)


def canonical_http(envelope: Dict[str, Any]) -> Dict[str, Any]:
    headers = envelope.get("headers", {}) or {}
    canonical_headers = {str(k).strip().lower(): str(v).strip() for k, v in headers.items() if str(k).strip().lower() not in {"date", "x-request-id"}}
    query = envelope.get("query", []) or []
    if isinstance(query, dict):
        items = [(str(k), str(v)) for k, v in query.items()]
    else:
        items = [(str(k), str(v)) for k, v in query]
    return {
        "method": str(envelope.get("method", "")).upper(),
        "scheme": str(envelope.get("scheme", "https")).lower(),
        "authority": str(envelope.get("authority", "")).lower(),
        "path": str(envelope.get("path", "/")),
        "query": sorted(items),
        "headers": dict(sorted(canonical_headers.items())),
        "body": _canonical_body(envelope.get("body")),
        "tenant_id": envelope.get("tenant_id"),
        "purpose_id": envelope.get("purpose_id"),
        "effect_type": envelope.get("effect_type", "DATA_EGRESS"),
    }


def digest_http(envelope: Dict[str, Any]) -> str:
    c = canonical_http(envelope)
    b = json.dumps(c, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def base_envelope() -> Dict[str, Any]:
    return {
        "method": "POST",
        "scheme": "https",
        "authority": "api.partner.example",
        "path": "/submit",
        "query": [("ticket", "123"), ("mode", "support")],
        "headers": {"Content-Type": "application/json", "X-Request-Id": "ignored", "Date": "ignored"},
        "body": {"amount": 10, "recipient": "partner", "nested": {"ok": True, "tags": ["a", "b"]}},
        "tenant_id": "tenant-A",
        "purpose_id": "support",
        "effect_type": "DATA_EGRESS",
    }


def equivalent_variant(rng: random.Random, env: Dict[str, Any]) -> Dict[str, Any]:
    e = deepcopy(env)
    # Shuffle query pairs and represent as list or dict when keys are unique.
    q = list(e["query"])
    rng.shuffle(q)
    e["query"] = dict(q) if rng.random() < 0.5 else q
    # Header order/case changes and ignored request-id/date values.
    headers = list(e["headers"].items())
    rng.shuffle(headers)
    e["headers"] = {("CONTENT-TYPE" if k.lower() == "content-type" and rng.random() < 0.5 else k.lower()): v for k, v in headers}
    e["headers"]["X-Request-Id"] = f"ignored-{rng.randrange(10**9)}"
    e["headers"]["Date"] = "Tue, 01 Jan 2030 00:00:00 GMT"
    # JSON body key order variations via dump/load.
    e["body"] = json.loads(json.dumps(e["body"], sort_keys=rng.random() < 0.5))
    e["method"] = e["method"].lower() if rng.random() < 0.5 else e["method"].upper()
    e["scheme"] = e["scheme"].upper() if rng.random() < 0.5 else e["scheme"]
    e["authority"] = e["authority"].upper() if rng.random() < 0.5 else e["authority"]
    return e


def distinct_variant(rng: random.Random, env: Dict[str, Any]) -> Dict[str, Any]:
    e = deepcopy(env)
    choice = rng.randrange(8)
    if choice == 0:
        e["method"] = "PUT"
    elif choice == 1:
        e["path"] = "/admin/submit"
    elif choice == 2:
        e["authority"] = "evil.example"
    elif choice == 3:
        e["query"] = [("ticket", "999"), ("mode", "support")]
    elif choice == 4:
        e["body"]["amount"] = 11
    elif choice == 5:
        e["body"]["recipient"] = "other-partner"
    elif choice == 6:
        e["tenant_id"] = "tenant-B"
    else:
        e["purpose_id"] = "marketing"
    return e


def main() -> int:
    rng = random.Random(SEED)
    base = base_envelope()
    base_digest = digest_http(base)
    equivalent_cases = 5000
    distinct_cases = 5000
    stable = 0
    distinct = 0
    for _ in range(equivalent_cases):
        if digest_http(equivalent_variant(rng, base)) == base_digest:
            stable += 1
    for _ in range(distinct_cases):
        if digest_http(distinct_variant(rng, base)) != base_digest:
            distinct += 1
    summary = {
        "synthetic": True,
        "representation_family": "http-envelope-v1",
        "seed": SEED,
        "equivalent_cases": equivalent_cases,
        "equivalent_digest_stable": stable,
        "distinct_cases": distinct_cases,
        "distinct_effect_digests_distinct": distinct,
        "failed": (equivalent_cases - stable) + (distinct_cases - distinct),
    }
    (RESULTS / "http_canonicalization_fuzz_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    md = ["# HTTP-Envelope Canonicalization Fuzz Summary", "", "Synthetic differential canonicalization checks over HTTP-like envelopes.", "", "| Metric | Value |", "|---|---:|"]
    for k in ["representation_family", "equivalent_cases", "equivalent_digest_stable", "distinct_cases", "distinct_effect_digests_distinct", "seed", "failed"]:
        md.append(f"| {k} | {summary[k]} |")
    (RESULTS / "http_canonicalization_fuzz_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
