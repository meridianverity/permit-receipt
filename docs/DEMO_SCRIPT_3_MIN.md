# 3-Minute Demo Script

## 0:00-0:30 — Thesis

Payment authorization shows a credential can pay. This synthetic PayGate profile demonstrates whether the AI agent was authorized to cause this exact modeled economic effect.

## 0:30-1:10 — Allow path

Run:

```bash
python -m paygate_hybrid.hybrid_demo
```

Highlight H01: exact cart, merchant, amount, policy epoch, validity, anti-replay, TSIL/S2 evidence reference, PayGate domain predicate, provider adapter decision token, and synthetic commit.

## 1:10-1:50 — Fail-closed moment

Highlight H02 and H03. ORPRG catches scope mismatch before PayGate. Then show that even if ORPRG passes, PayGate denies when required TSIL/S2 evidence is missing.

## 1:50-2:30 — Synthetic adapter token moment

Highlight H04. A direct provider call without the PayGate decision token is denied by the adapter.

## 2:30-3:00 — Evidence integrity moment

Highlight H05. TETpay/evidence tamper is detected as audit-only evidence validation without changing TSIL ingress semantics.
