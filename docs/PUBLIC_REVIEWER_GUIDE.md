# Public Reviewer Guide

Use this repository to review behavior, not to certify production readiness.

## Suggested review questions

1. Does the canonicalization step bind the exact modeled effect reviewers expect?
2. Do negative vectors fail closed for scope mismatch, stale status, replay, evidence tamper, and provider-adapter bypass?
3. Are the demonstrated evidence categories clear enough for standards discussion?
4. Are any terms confusing or likely to imply certification, production readiness, or official standards-body endorsement?
5. Are there additional public negative vectors that would improve interoperability review without disclosing production mechanisms?

## Recommended commands

```bash
python -m pip install -r requirements.txt
make qa
python run_vectors.py
python -m pytest -q
```

## What feedback is useful

- reproducibility failures;
- unclear terminology;
- missing negative cases;
- interoperability questions;
- places where the README or docs could overclaim; and
- suggestions for public evaluation vectors.

## What not to submit publicly

- production architecture;
- live credentials;
- payment data;
- private implementation details;
- unpublished legal mappings;
- patent claim charts;
- commercial strategy; or
- security-sensitive exploit material.
