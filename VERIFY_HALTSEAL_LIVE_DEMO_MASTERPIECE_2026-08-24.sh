#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
HTML="$ROOT/haltseal/demo/index.html"
CSS="$ROOT/haltseal/demo/demo.css"
JS="$ROOT/haltseal/demo/demo.js"
HEADERS="$ROOT/_headers"

fail(){ echo "FAIL: $*" >&2; exit 1; }
pass(){ echo "PASS: $*"; }

[[ -f "$HTML" ]] || fail "missing $HTML"
[[ -f "$CSS" ]] || fail "missing $CSS"
[[ -f "$JS" ]] || fail "missing existing CSP-safe runtime $JS"
[[ -f "$HEADERS" ]] || fail "missing site-wide _headers"

# Runtime is intentionally unchanged from the CSP click-fix baseline.
EXPECTED_JS_SHA="8c95806d83f526a4ddb6d3db4657ac0de278e7792b7042c9d229621728cb68ef"
ACTUAL_JS_SHA="$(sha256sum "$JS" | awk '{print $1}')"
[[ "$ACTUAL_JS_SHA" == "$EXPECTED_JS_SHA" ]] || fail "demo.js changed unexpectedly ($ACTUAL_JS_SHA)"
pass "interaction runtime unchanged"

# Strict-CSP compatibility: external assets only.
! grep -Eq '<style([ >])' "$HTML" || fail "inline <style> reintroduced"
! grep -Eq '<script([^>]*>)[[:space:]]*[^<[:space:]]' "$HTML" || fail "inline executable script reintroduced"
grep -Fq 'href="./demo.css?v=20260824-masterpiece"' "$HTML" || fail "masterpiece external stylesheet reference missing"
grep -Fq 'src="./demo.js?v=20260824-cspfix"' "$HTML" || fail "external JS reference missing"
grep -Fq "script-src 'self'" "$HEADERS" || fail "site CSP no longer permits same-origin external JS"
grep -Fq "style-src 'self'" "$HEADERS" || fail "site CSP no longer permits same-origin external CSS"
pass "strict CSP posture preserved"

# Investor-facing copy.
grep -Fq 'Final execution control<br><span>before AI moves money.</span>' "$HTML" || fail "hero headline missing"
grep -Fq 'One buyer-defined economic obligation stays authoritative even as agents, providers, routes, and retries change.' "$HTML" || fail "hero subhead missing"
grep -Fq 'Provider A goes UNKNOWN.</strong> A fresh Route B can still look valid. HALTSEAL holds the second dispatch until the first outcome is resolved.' "$HTML" || fail "pre-click failure punchline missing"
grep -Fq 'NEXT VALIDATION MILESTONE' "$HTML" || fail "validation milestone label missing"
grep -Fq 'One buyer. Two execution routes. Zero kernel fork.' "$HTML" || fail "validation milestone headline missing"
grep -Fq 'Zero kernel fork target' "$HTML" || fail "zero-kernel-fork qualifier missing"
! grep -Fq 'Route 2 tests whether it is a product.' "$HTML" || fail "old self-evaluative closing copy remains"
pass "investor-facing copy updated"

# Required credibility / semantic anchors remain.
grep -Fq 'LIVE DEMO' "$HTML" || fail "top LIVE DEMO disclosure missing"
grep -Fq 'SYNTHETIC' "$HTML" || fail "top SYNTHETIC disclosure missing"
grep -Fq 'NO FUNDS MOVE' "$HTML" || fail "top NO FUNDS MOVE disclosure missing"
grep -Fq 'A new technical path is not a new economic obligation.' "$HTML" || fail "core invariant missing"
grep -Fq 'NO LLM DECIDES ACCEPTANCE' "$HTML" || fail "deterministic acceptance signal missing"
grep -Fq 'Locally valid ≠ economically eligible' "$HTML" || fail "proof card 1 missing"
grep -Fq 'UNKNOWN does not become success' "$HTML" || fail "proof card 2 missing"
grep -Fq 'Truth never dispatches money' "$HTML" || fail "proof card 3 missing"
grep -Fq 'Outcome truth may change eligibility. It never creates release authority.' "$HTML" || fail "outcome-truth invariant missing"
grep -Fq 'Not buyer-validated. Not production.' "$HTML" || fail "technical-drawer boundary disclosure missing"
pass "credibility and semantic anchors preserved"

# Footer intentionally de-duplicated.
grep -Fq 'Deterministic synthetic demonstration · no generative model in the acceptance path.' "$HTML" || fail "simplified footer missing"
FOOTER_BLOCK="$(sed -n '/<footer>/,/<\/footer>/p' "$HTML")"
! grep -Fq 'Not buyer-validated' <<<"$FOOTER_BLOCK" || fail "footer still repeats buyer-validation disclaimer"
! grep -Fq 'no funds move' <<<"$FOOTER_BLOCK" || fail "footer still repeats no-funds disclosure"
pass "footer de-duplicated"

# New styling is present and no JS selectors were affected.
grep -Fq '.hero-punch {' "$CSS" || fail "hero punch style missing"
node --check "$JS" >/dev/null || fail "demo.js syntax check failed"
pass "CSS addition + JS syntax"

# DOM/JS ID contract check (all getElementById-style references must exist in HTML).
python3 - "$HTML" "$JS" <<'PY'
import re, sys
from pathlib import Path
html=Path(sys.argv[1]).read_text()
js=Path(sys.argv[2]).read_text()
ids=set(re.findall(r'id="([^"]+)"', html))
refs=set(re.findall(r"\$\('([^']+)'\)", js))
missing=sorted(refs-ids)
if missing:
    print('FAIL: JS references missing DOM ids:', ', '.join(missing), file=sys.stderr)
    raise SystemExit(1)
print(f'PASS: DOM/JS ID contract ({len(refs)} referenced ids present)')
PY

# Guided mode stays exactly 90 seconds in the unchanged runtime.
python3 - "$JS" <<'PY'
import re, sys
from pathlib import Path
js=Path(sys.argv[1]).read_text()
block=re.search(r'const guidedScenes = \[(.*?)\n  \];', js, re.S)
if not block:
    print('FAIL: guidedScenes block not found', file=sys.stderr); raise SystemExit(1)
ms=[int(x) for x in re.findall(r'duration:\s*(\d+)', block.group(1))]
if sum(ms)!=90000:
    print(f'FAIL: guided mode duration is {sum(ms)} ms, expected 90000', file=sys.stderr); raise SystemExit(1)
print(f'PASS: guided mode remains exactly {sum(ms)//1000} seconds across {len(ms)} scenes')
PY

# Strong post-overlay hashes for the two runtime files actually shipped by this overlay.
EXPECTED_HTML_SHA="64b981b09aa1714dd8a8a8cc46d55ac279ce3f204fb9d5325297d8e3365bdd35"
EXPECTED_CSS_SHA="38745eccf58a1a859361837d661ae8a09dfd005610e2f037e7190a1043ed5042"
[[ "$(sha256sum "$HTML" | awk '{print $1}')" == "$EXPECTED_HTML_SHA" ]] || fail "index.html hash mismatch"
[[ "$(sha256sum "$CSS" | awk '{print $1}')" == "$EXPECTED_CSS_SHA" ]] || fail "demo.css hash mismatch"
pass "overlay runtime hashes match"

echo "HALTSEAL LIVE DEMO MASTERPIECE VERIFY: PASS"
