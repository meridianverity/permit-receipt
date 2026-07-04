from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scenario import run_scenarios, write_demo_outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Provider-Neutral PayGate PoC scenarios.")
    parser.add_argument("--out", default=None, help="Optional output directory for demo_results.json and demo_ledger.jsonl")
    parser.add_argument("--json", action="store_true", help="Print full JSON instead of a compact table")
    args = parser.parse_args()
    if args.out:
        result = write_demo_outputs(Path(args.out))
    else:
        result = run_scenarios()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("Provider-Neutral PayGate PoC")
    print(f"policy_epoch: {result['policy_epoch']}")
    print(f"policy_digest: {result['policy_digest']}")
    print(f"base_action_digest: {result['base_action_digest']}")
    print("")
    for s in result["scenarios"]:
        codes = ",".join(s.get("reason_codes", [])) or "-"
        provider = s.get("provider_adapter_id", "-")
        print(f"{s['scenario']:<55} {s['outcome']:<5} provider={provider:<11} codes={codes}")
    print("")
    print(f"ledger_verified: {result['ledger_verified']} chain_tip={result['ledger_chain_tip']}")


if __name__ == "__main__":
    main()
