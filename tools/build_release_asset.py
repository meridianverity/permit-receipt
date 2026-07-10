#!/usr/bin/env python3
"""Build the deterministic v2.2.6 public-evaluation ZIP and sidecars.

The archive deliberately uses ZIP STORE rather than DEFLATE.  That removes
zlib-version variance and makes the bytes reproducible across conforming Python
runtimes, provided the input tree is byte-identical.
"""
from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import zipfile
from pathlib import Path

try:  # script and package import compatibility
    from release_config import (
        ARTIFACT_LABEL,
        ASSET_NAME,
        BUILD_DATE,
        MANIFEST_NAME,
        PROVENANCE_NAME,
        NORMALIZED_ZIP_TIME,
        ROOT_DIR_NAME,
        SIDECAR_NAME,
        TAG,
    )
    from source_inventory import (
        EXCLUDE_DIRS,
        EXCLUDE_FILES,
        EXCLUDE_SUFFIXES,
        digest_entries,
        iter_source_files,
        sha256_bytes,
        sha256_file,
    )
except ImportError:  # pragma: no cover
    from tools.release_config import (
        ARTIFACT_LABEL,
        ASSET_NAME,
        BUILD_DATE,
        MANIFEST_NAME,
        PROVENANCE_NAME,
        NORMALIZED_ZIP_TIME,
        ROOT_DIR_NAME,
        SIDECAR_NAME,
        TAG,
    )
    from tools.source_inventory import (
        EXCLUDE_DIRS,
        EXCLUDE_FILES,
        EXCLUDE_SUFFIXES,
        digest_entries,
        iter_source_files,
        sha256_bytes,
        sha256_file,
    )

ROOT = Path(__file__).resolve().parents[1]


def add_directory_entries(zf: zipfile.ZipFile, relative_paths: list[Path]) -> None:
    dirs = {ROOT_DIR_NAME}
    for rel in relative_paths:
        current = ROOT_DIR_NAME
        for part in rel.parts[:-1]:
            current = f"{current}/{part}"
            dirs.add(current)
    for name in sorted(dirs):
        info = zipfile.ZipInfo(name.rstrip("/") + "/", NORMALIZED_ZIP_TIME)
        info.create_system = 3
        info.external_attr = (stat.S_IFDIR | 0o755) << 16
        info.flag_bits |= 0x800
        info.compress_type = zipfile.ZIP_STORED
        zf.writestr(info, b"")


def _git_text(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def verify_source_revision_binding(source_repository: str, source_commit: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("source_commit must be one lowercase 40-hex Git object ID")
    observed_head = _git_text("rev-parse", "HEAD")
    if observed_head != source_commit:
        raise ValueError(f"source commit mismatch: expected {source_commit}, observed {observed_head}")
    observed_tag = _git_text("rev-parse", f"{TAG}^{{commit}}")
    if observed_tag != source_commit:
        raise ValueError(f"tag {TAG} does not resolve to source commit {source_commit}")
    if _git_text("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("source worktree must be clean before a commit-bound release build")
    remote = _git_text("remote", "get-url", "origin")
    normalized = remote.removesuffix(".git")
    if normalized.startswith("git@github.com:"):
        normalized = "https://github.com/" + normalized.split(":", 1)[1]
    if normalized != source_repository.removesuffix(".git"):
        raise ValueError(f"source repository mismatch: expected {source_repository}, observed {remote}")


def build_zip(
    out_dir: Path,
    asset_name: str = ASSET_NAME,
    *,
    source_repository: str | None = None,
    source_commit: str | None = None,
) -> dict[str, object]:
    if (source_repository is None) != (source_commit is None):
        raise ValueError("source_repository and source_commit must be supplied together")
    if source_repository and source_commit:
        verify_source_revision_binding(source_repository, source_commit)
    if asset_name != ASSET_NAME:
        raise ValueError(
            f"active release asset name is immutable: expected {ASSET_NAME!r}, observed {asset_name!r}"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / asset_name
    sidecar_path = out_dir / SIDECAR_NAME
    metadata_path = out_dir / MANIFEST_NAME
    provenance_path = out_dir / PROVENANCE_NAME
    for path in (zip_path, sidecar_path, metadata_path, provenance_path):
        path.unlink(missing_ok=True)

    files = list(iter_source_files(ROOT))
    relative_paths = [rel for rel, _ in files]
    source_entries: list[dict[str, object]] = []
    for rel, path in files:
        data = path.read_bytes()
        source_entries.append(
            {
                "path": rel.as_posix(),
                "archive_path": f"{ROOT_DIR_NAME}/{rel.as_posix()}",
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "mode": "0644",
            }
        )

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED, strict_timestamps=True) as zf:
        add_directory_entries(zf, relative_paths)
        for (_, path), entry in zip(files, source_entries, strict=True):
            info = zipfile.ZipInfo(str(entry["archive_path"]), NORMALIZED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.flag_bits |= 0x800
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_STORED)

    digest = sha256_file(zip_path)
    sidecar_path.write_text(f"{digest}  {asset_name}\n", encoding="utf-8", newline="\n")
    metadata: dict[str, object] = {
        "artifact": ARTIFACT_LABEL,
        "manifest_format": "permit-receipt-release-asset-manifest-v2",
        "tag": TAG,
        "build_date": BUILD_DATE,
        "asset_name": asset_name,
        "asset_sha256": digest,
        "asset_size_bytes": zip_path.stat().st_size,
        "sidecar_name": sidecar_path.name,
        "sidecar_sha256": sha256_file(sidecar_path),
        "provenance_name": PROVENANCE_NAME,
        "root_dir_name": ROOT_DIR_NAME,
        "file_count": len(source_entries),
        "source_tree_sha256": digest_entries(source_entries),
        "zip_timestamp_policy": "all entries normalized to 2026-07-10T00:00:00 in the ZIP timestamp field",
        "file_mode_policy": "directories 0755; regular files 0644; symbolic links forbidden",
        "path_order_policy": "UTF-8 POSIX relative paths in ascending lexical order",
        "compression": "ZIP STORE (no compression) to eliminate zlib-version variance",
        "excluded_dirs": sorted(EXCLUDE_DIRS),
        "excluded_files": sorted(EXCLUDE_FILES),
        "excluded_suffixes": sorted(EXCLUDE_SUFFIXES),
        "entries": source_entries,
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    materials = []
    for rel in ("MANIFEST.sha256.json", "sbom.cdx.json", "requirements-lock-py313-linux-x86_64.txt"):
        source = ROOT / rel
        if source.exists():
            materials.append({"uri": rel, "digest": {"sha256": sha256_file(source)}, "annotations": {"bytes": source.stat().st_size}})
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": asset_name, "digest": {"sha256": digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://meridianverity.com/buildtypes/permit-receipt-deterministic-zip/v2",
                "externalParameters": {
                    "tag": TAG,
                    "asset_name": asset_name,
                    "normalized_zip_time": list(NORMALIZED_ZIP_TIME),
                },
                "internalParameters": {
                    "compression": "ZIP STORE (no compression)",
                    "source_tree_sha256": metadata["source_tree_sha256"],
                },
                "resolvedDependencies": materials + (
                    [{
                        "uri": source_repository,
                        "digest": {"sha1": source_commit},
                        "annotations": {"ref": TAG},
                    }]
                    if source_repository and source_commit
                    else []
                ),
            },
            "runDetails": {
                "builder": {"id": "permit-receipt/tools/build_release_asset.py"},
                "metadata": {
                    "invocationId": metadata["source_tree_sha256"],
                    "startedOn": BUILD_DATE + "T00:00:00Z",
                    "finishedOn": BUILD_DATE + "T00:00:00Z",
                },
                "byproducts": [
                    {"name": SIDECAR_NAME, "digest": {"sha256": sha256_file(sidecar_path)}},
                    {"name": MANIFEST_NAME, "digest": {"sha256": sha256_file(metadata_path)}},
                ],
            },
        },
        "boundary": (
            "synthetic public evaluation provenance; not a production attestation or certification; "
            + (
                "source revision bound"
                if source_repository and source_commit
                else "prepublication source revision not bound"
            )
        ),
    }
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    metadata["provenance_sha256"] = sha256_file(provenance_path)
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the deterministic v2.2.6 public-evaluation release asset.")
    parser.add_argument("--out-dir", default="dist", help="Output directory for ZIP, sidecar, and asset manifest.")
    parser.add_argument("--asset-name", default=ASSET_NAME, help="Must match the immutable v2.2.6 asset name.")
    parser.add_argument("--source-repository", help="Canonical source repository URI; requires --source-commit.")
    parser.add_argument("--source-commit", help="Exact lowercase 40-hex Git commit; requires --source-repository.")
    args = parser.parse_args()
    metadata = build_zip(
        Path(args.out_dir),
        args.asset_name,
        source_repository=args.source_repository,
        source_commit=args.source_commit,
    )
    print(json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
