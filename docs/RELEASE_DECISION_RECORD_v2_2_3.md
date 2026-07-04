# Release Decision Record — v2.2.3-public-eval

## Decision

Publish `v2.2.3-public-eval` as a GitHub pre-release and IETF discussion artifact.

Do not mark it as latest. Do not call it stable. Do not describe it as open-source production software, official IETF reference implementation, certification program, conformance program, certificate registry, or public trust anchor.

## Why v2.2.3 exists

This patch strengthens long-term public-review hygiene after v2.2.3 by adding:

- `GLOSSARY.md` for consistent terminology;
- explicit standards/IPR boundary documentation;
- explicit evaluation-boundary documentation;
- a public reviewer guide;
- reproducibility notes;
- stricter packet validation for required public-boundary files;
- README and Quickstart alignment; and
- updated release body and upload checklist language.

## Core posture

```text
Synthetic source-available public evaluation artifact.
Not production software.
Not an IETF standard.
Not an official IETF reference implementation.
Not a certification program.
Not a conformance program.
No patent license.
```

## Release gate

Release only if all pass:

```bash
make clean
python tools/make_public_manifest.py
python verify_manifest.py
make qa
```
