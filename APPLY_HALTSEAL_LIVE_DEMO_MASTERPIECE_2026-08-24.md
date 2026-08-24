# HALTSEAL Live Demo — MASTERPIECE Copy Overlay

Date: 2026-08-24
Target: the current CSP-safe `/haltseal/demo/` deployment (the version with external `demo.css` and `demo.js`).

## What this overlay changes

Only the public investor-facing copy and one small presentation style are changed:

1. Hero is aligned to the Antler deck:
   - `Final execution control before AI moves money.`
   - `One buyer-defined economic obligation stays authoritative even as agents, providers, routes, and retries change.`
2. Adds a one-line pre-click danger statement under the guided-demo controls:
   - Provider A goes UNKNOWN; a fresh Route B can still look valid; HALTSEAL holds the second dispatch until the first outcome is resolved.
3. Reframes the closing proof from a self-evaluative statement to a measurable milestone:
   - `NEXT VALIDATION MILESTONE`
   - `One buyer. Two execution routes. Zero kernel fork.`
   - The existing `Zero kernel fork target` qualifier remains visible.
4. Simplifies the footer while retaining the top synthetic/no-funds disclosure and the detailed technical-drawer boundaries.
5. Updates Open Graph / Twitter title copy to match the new hero.

## What this overlay does NOT change

- `haltseal/demo/demo.js` is intentionally NOT included or modified.
- No state-machine semantics change.
- No timing changes to the 90-second guided mode.
- No ACCEPT / HOLD / REFUSE logic changes.
- No tampered-payee behavior changes.
- No technical evidence claims are added.
- No site-wide CSP changes.
- No `unsafe-inline` relaxation.
- No existing `/haltseal/` or site-wide files are touched.

## Apply

From the website repository root:

```bash
unzip -oq MVG_HALTSEAL_LIVE_DEMO_MASTERPIECE_OVERLAY_2026-08-24.zip
bash VERIFY_HALTSEAL_LIVE_DEMO_MASTERPIECE_2026-08-24.sh
```

Expected final line:

```text
HALTSEAL LIVE DEMO MASTERPIECE VERIFY: PASS
```

Then commit only the overlay files you want to keep. Runtime changes are limited to:

```text
haltseal/demo/index.html
haltseal/demo/demo.css
```

Recommended commit:

```bash
git add haltseal/demo/index.html haltseal/demo/demo.css \
  APPLY_HALTSEAL_LIVE_DEMO_MASTERPIECE_2026-08-24.md \
  VERIFY_HALTSEAL_LIVE_DEMO_MASTERPIECE_2026-08-24.sh \
  HALTSEAL_LIVE_DEMO_MASTERPIECE_MANIFEST_2026-08-24.json

git commit -m "Polish HALTSEAL investor demo copy"
git push
```

## Post-deploy browser QA

Open an incognito/private window at:

`https://meridianverity.com/haltseal/demo/`

Confirm:

1. Hero reads `Final execution control before AI moves money.`
2. The pre-click UNKNOWN / fresh Route B / second-dispatch sentence is visible.
3. Guided mode starts and Pause / Next / Exit work.
4. Route A timeout produces UNKNOWN / HOLD.
5. Fresh Route B remains HOLD with 0 second dispatch.
6. Reconciliation restores eligibility without automatic dispatch.
7. Fresh authorized release produces one bounded release.
8. Tampered payee produces REFUSE before network write.
9. Technical evidence drawer still opens.
10. Closing milestone reads `One buyer. Two execution routes. Zero kernel fork.`

Once those pass, freeze this investor demo and direct further effort to named-buyer / Route 1 → Route 2 validation.
