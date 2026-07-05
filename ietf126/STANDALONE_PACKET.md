# Standalone Packet Mode

The IETF 126 packet is designed to be useful even if a reviewer receives only the `ietf126/` directory.

Run:

```bash
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
```

If the repository package `orprg_eval` is not importable, the runner switches to **standalone packet mode**. In that mode it uses only Python's standard library and executes a narrow synthetic evaluator that demonstrates:

- exact canonical bytes;
- one `action_digest`;
- one positive permit-before-commit path;
- selected fail-closed negative vectors; and
- signature-covered `authorization_ref` shape checks.

Standalone mode is deliberately not a substitute for the full repository vector corpus. The full repository mode remains the stronger review path and should be used for full public evaluation, release QA, and reviewer reproduction.

Public boundary: standalone mode is a public technical review aid. It is not production software, not a conformance program, not an official IETF reference implementation, not a legal/commercial position, and not a patent license grant.
