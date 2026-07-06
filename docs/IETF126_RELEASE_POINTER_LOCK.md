# IETF 126 Release Pointer Lock

This file is the copy/paste source for reviewer-facing IETF 126 links.

Current public evaluation tag:

```text
v2.2.4-public-eval
```

Current public evaluation release URL:

```text
https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.4-public-eval
```

Current remote review packet URL:

```text
https://github.com/meridianverity/permit-receipt/tree/main/ietf126
```

Current release asset name:

```text
permit-receipt-ref-eval-v2_2_4-public-eval.zip
```

Current SHA-256 sidecar name:

```text
permit-receipt-ref-eval-v2_2_4-public-eval.zip.sha256
```

Sidecar content must name the ZIP exactly as `permit-receipt-ref-eval-v2_2_4-public-eval.zip`. Older staging names such as `permit-receipt-main-v2_2_4-ietf126-hardened.zip` are stale and must not be published as the checksum target.

Preflight check:

```bash
python tools/check_ietf126_release_pointers.py
```

Reviewer-facing project pages should not point to earlier public-evaluation tags such as `v2.2.1-public-eval`, `v2.2.2-public-eval`, or `v2.2.3-public-eval`. Historical release notes may still mention older tags, but active IETF reviewer-facing text should use the current tag above.

External publication check: after publishing or updating the release, re-open the public IETF 126 Hackathon project page and confirm its PermitReceipt entry uses the current release URL and remote review packet URL above. If the public wiki still points to an older tag, replace that section with `docs/IETF_HACKATHON_PROJECT_PAGE.md` / `ietf126/SUBMISSION_TEXT.md`.

Boundary: this is a synthetic public review artifact. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and not a patent license grant.
