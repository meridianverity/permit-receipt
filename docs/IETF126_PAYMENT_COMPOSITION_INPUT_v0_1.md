# IETF 126 Synthetic EUR Payment Composition Input v0.1

Status: **FROZEN PRE-EXECUTION INPUT — NOT A RESULT**  
Public posture: **HOLD**

This is a separate release artifact for the scoped ORPRG payment-composition exercise. It does not modify, replace, or supersede `v2.2.6-public-eval`, which remains the frozen Deliverable-A external-replay target.

## Canonical release

- Release: https://github.com/meridianverity/permit-receipt/releases/tag/ietf126-payment-composition-v0.1
- Tag: `ietf126-payment-composition-v0.1`
- Tag target commit: `5c2de6c3f98a9deb2055f0d72d4d6aeef17a7ec9`
- Base release dependency: `permit-receipt-ref-eval-v2_2_6-public-eval.zip`
- Base release SHA-256: `e5c40eca74fe2f451a0723db915c64b201e1d52f382cee24062e4dfc61fc632f`

## Canonical explicit assets

Use only the four explicitly uploaded release assets:

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `orprg-ietf126-payment-composition-v0.1.zip` | 279408 | `d13c740c47710e4b28a1d2d511aa63574200256ce310f0e03ec618b383583c2f` |
| `orprg-ietf126-payment-composition-v0.1.zip.sha256` | 109 | `7208b9c199c8c78d760a01a7c11757ae72cd48502bce9df338bfba0429505913` |
| `orprg-ietf126-payment-composition-v0.1.zip.manifest.json` | 23317 | `d4794b024055da9570ed32e2b66c4c763c66e1c17ecd94428347d360c1bf5c00` |
| `orprg-ietf126-payment-composition-v0.1.zip.provenance.json` | 2626 | `a9137f8561302c2153fd2f9f5dc151bec7666b6a616cd7b6cc211d40a973c436` |

Do not copy these generated assets into the `main` source tree. Do not use GitHub's automatically generated source archives as composition inputs. The release page and the four explicit assets are the canonical distribution surface.

## Verification

```bash
sha256sum -c orprg-ietf126-payment-composition-v0.1.zip.sha256
unzip orprg-ietf126-payment-composition-v0.1.zip
cd orprg-ietf126-payment-composition-v0.1
python -m pip install -r requirements.txt
python verify-tuple.py
python independent-verify.py
```

Expected summaries:

```text
PASS: 203/203 checks; positive=ORPRG ALLOW; mandate-over-limit=ORPRG ALLOW (spend DENY expected downstream)
PASS: 74/74 independent checks
```

These are package-level appraisal results only. They do not establish MachineMandate execution, AAC/SCITT record generation, PCR16 outcome binding, an external effect, independent certification, or successful interoperability.
