# Release Publishing Protocol — v2.2.5-public-eval

This protocol exists to keep the public-evaluation review path digest-bound and reviewer-reproducible.

## Before tagging

```bash
make clean
python make_manifest.py
python verify_manifest.py
python tools/check_release_lineage.py
python tools/check_ietf126_release_pointers.py
python ietf126/run_review_packet.py
python ietf126/independent_recompute.py
make qa-full
```

## Tag and release

Use this tag:

```text
v2.2.5-public-eval
```

Use this asset name:

```text
permit-receipt-ref-eval-v2_2_5-public-eval.zip
```

Use this sidecar name:

```text
permit-receipt-ref-eval-v2_2_5-public-eval.zip.sha256
```

## After publishing

1. Download the ZIP from the public release page.
2. Recompute SHA-256 locally.
3. Compare local SHA-256 with the sidecar.
4. Compare local SHA-256 with the release-platform asset digest when exposed.
5. Run the IETF packet and independent recomputation from a clean extraction.
6. Email the final release URL, asset name, sidecar name, SHA-256, and expected pass counts.

## No same-tag replacement

Do not replace the ZIP or sidecar after publication. If a file, note, vector, or checksum must change, issue a fresh tag and fresh sidecar.

## Public boundary

This protocol supports public technical review only. It does not create production authorization, certification, conformance-program status, commercial rights, or patent-license rights.
