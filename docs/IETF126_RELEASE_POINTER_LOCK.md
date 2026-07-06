# IETF 126 Release Pointer Lock

This file is the copy/paste source for reviewer-facing IETF 126 links.

Current public evaluation tag:

```text
v2.2.5-public-eval
```

Current public evaluation release URL:

```text
https://github.com/meridianverity/permit-receipt/releases/tag/v2.2.5-public-eval
```

Current remote review packet URL:

```text
https://github.com/meridianverity/permit-receipt/tree/main/ietf126
```

Current release asset name:

```text
permit-receipt-ref-eval-v2_2_5-public-eval.zip
```

Current SHA-256 sidecar name:

```text
permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
```

Sidecar content must name the ZIP exactly as `permit-receipt-ref-eval-v2_2_5-public-eval.zip`.

Fresh-tag rule: after the checksum has been shared publicly or by email, do not replace this tag's ZIP or sidecar. If any byte changes, publish a new tag with a new sidecar and update this pointer lock.

Preflight check:

```bash
python tools/check_release_lineage.py
python tools/check_ietf126_release_pointers.py
```

Reviewer-facing project pages should not point to earlier public-evaluation tags. Historical release notes may still mention older tags, but active IETF reviewer-facing text should use the current tag above.

External publication check: after publishing or updating the release, re-open the public IETF 126 Hackathon project page and confirm its PermitReceipt entry uses the current release URL and remote review packet URL above. If the public wiki still points to an older tag, replace that section with `docs/IETF_HACKATHON_PROJECT_PAGE.md` / `ietf126/SUBMISSION_TEXT.md`.

Boundary: this is a synthetic public review artifact. It is not production software, not an IETF standard, not an official IETF reference implementation, not a certification program, not a conformance program, and not a patent license grant.
