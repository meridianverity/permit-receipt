# Reviewer Checklist

## Run

- [ ] `python ietf126/run_review_packet.py`
- [ ] `python run_vectors.py`
- [ ] `python tools/run_public_eval.py`
- [ ] `python tools/validate_public_eval_packet.py`

## Inspect

- [ ] exact protected-action request object
- [ ] exact canonical bytes
- [ ] `canonicalization_profile_ref`
- [ ] `domain_sep` handling
- [ ] `action_digest`
- [ ] PermitReceipt `receipt_core`
- [ ] policy digest and epoch
- [ ] validity interval
- [ ] scope fields
- [ ] anti-replay material
- [ ] status/recency evidence
- [ ] denial reason codes
- [ ] `authorization_ref` shape and signature-coverage rule

## Open issues for

- unclear fields;
- missing negative vectors;
- unsupported profile behavior;
- signature-covered cross-reference field shape;
- privacy-preserving or selective-disclosure requirements;
- how to represent domain separation across profiles;
- whether future drafts should split requirements, architecture, data model, evaluation vectors, and wire profiles.

## Do not submit in public issues

- customer diagrams;
- production logs;
- credentials or secrets;
- regulated data;
- non-public implementation mapping;
- claim charts;
- evidence-of-use materials;
- valuation materials; or
- commercial-rights requests.

