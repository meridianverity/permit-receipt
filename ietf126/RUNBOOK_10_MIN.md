# 10-Minute Remote Runbook

## Minute 0-1: clone and install

```bash
git clone https://github.com/meridianverity/permit-receipt.git
cd permit-receipt
python -m pip install -r requirements.txt
```

## Minute 1-3: run the packet

```bash
python ietf126/run_review_packet.py
```

## Minute 3-5: inspect the proof surface

```bash
cat ietf126/results/review-summary.md
cat ietf126/results/canonical-request.bytes.txt
```

## Minute 5-7: inspect fail-closed behavior

```bash
cat ietf126/results/negative-vector-results.json
```

## Minute 7-9: inspect interop reference behavior

```bash
cat ietf126/results/interop-crossref-results.json
```

## Minute 9-10: open one issue

Open a GitHub issue for one unclear field, one missing vector, or one interop profile question.

