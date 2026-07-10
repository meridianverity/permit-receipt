#!/usr/bin/env python3
"""Verify the v2.2.6 release ZIP, checksum, structure, and asset manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from release_config import (
        ASSET_NAME,
        MANIFEST_NAME,
        NORMALIZED_ZIP_TIME,
        PROVENANCE_NAME,
        ROOT_DIR_NAME,
        SIDECAR_NAME,
        TAG,
    )
except ImportError:  # pragma: no cover
    from tools.release_config import (
        ASSET_NAME,
        MANIFEST_NAME,
        NORMALIZED_ZIP_TIME,
        PROVENANCE_NAME,
        ROOT_DIR_NAME,
        SIDECAR_NAME,
        TAG,
    )

HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_sidecar(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    if b"\r" in raw:
        raise ValueError("sidecar must use LF line endings")
    lines = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"sidecar must contain exactly one non-empty line, observed {len(lines)}")
    parts = lines[0].split()
    if len(parts) != 2:
        raise ValueError("sidecar must contain SHA-256, two-space separator, and asset name")
    digest, name = parts
    if not HEX64_RE.fullmatch(digest):
        raise ValueError("sidecar digest is not a 64-character hexadecimal SHA-256 value")
    expected_line = f"{digest}  {name}\n".encode("utf-8")
    if raw != expected_line:
        raise ValueError("sidecar bytes are not in the canonical '<digest>  <asset>\\n' form")
    return digest.lower(), name


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and "" not in path.parts
        and "\\" not in name
        and not re.match(r"^[A-Za-z]:", name)
    )


def _verify_manifest(
    manifest_path: Path,
    *,
    zip_path: Path,
    archive_entries: dict[str, tuple[int, str]],
    findings: list[dict[str, str]],
) -> dict[str, Any] | None:
    if not manifest_path.exists():
        findings.append({"kind": "missing_asset_manifest", "detail": str(manifest_path)})
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append({"kind": "asset_manifest_parse_error", "detail": type(exc).__name__})
        return None
    checks = {
        "tag": TAG,
        "asset_name": ASSET_NAME,
        "asset_sha256": sha256(zip_path),
        "asset_size_bytes": zip_path.stat().st_size,
        "sidecar_name": SIDECAR_NAME,
        "root_dir_name": ROOT_DIR_NAME,
    }
    for field, expected in checks.items():
        if manifest.get(field) != expected:
            findings.append(
                {
                    "kind": "asset_manifest_field_mismatch",
                    "detail": f"{field}: expected {expected!r}, observed {manifest.get(field)!r}",
                }
            )
    manifest_entries = manifest.get("entries")
    if not isinstance(manifest_entries, list):
        findings.append({"kind": "asset_manifest_entries_invalid", "detail": "entries must be a list"})
        return manifest
    observed_paths: set[str] = set()
    for item in manifest_entries:
        if not isinstance(item, dict):
            findings.append({"kind": "asset_manifest_entry_invalid", "detail": repr(item)[:120]})
            continue
        archive_path = item.get("archive_path")
        if not isinstance(archive_path, str):
            findings.append({"kind": "asset_manifest_entry_path_invalid", "detail": repr(archive_path)})
            continue
        observed_paths.add(archive_path)
        observed = archive_entries.get(archive_path)
        expected = (item.get("bytes"), item.get("sha256"))
        if observed != expected:
            findings.append(
                {
                    "kind": "asset_manifest_entry_mismatch",
                    "detail": f"{archive_path}: expected {expected!r}, observed {observed!r}",
                }
            )
    if observed_paths != set(archive_entries):
        missing = sorted(set(archive_entries) - observed_paths)
        extra = sorted(observed_paths - set(archive_entries))
        findings.append(
            {
                "kind": "asset_manifest_path_set_mismatch",
                "detail": f"unmanifested={missing[:5]!r}; absent={extra[:5]!r}",
            }
        )
    if manifest.get("file_count") != len(archive_entries):
        findings.append(
            {
                "kind": "asset_manifest_file_count_mismatch",
                "detail": f"expected {len(archive_entries)}, observed {manifest.get('file_count')}",
            }
        )
    return manifest


def _verify_provenance(
    provenance_path: Path,
    *,
    zip_path: Path,
    sidecar_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any] | None,
    findings: list[dict[str, str]],
    require_source_revision: bool = False,
    expected_source_repository: str | None = None,
    expected_source_commit: str | None = None,
) -> dict[str, Any] | None:
    if not provenance_path.exists():
        findings.append({"kind": "missing_provenance", "detail": str(provenance_path)})
        return None
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append({"kind": "provenance_parse_error", "detail": type(exc).__name__})
        return None
    subjects = provenance.get("subject")
    expected_subject = {"name": ASSET_NAME, "digest": {"sha256": sha256(zip_path)}}
    if not isinstance(subjects, list) or expected_subject not in subjects:
        findings.append({"kind": "provenance_subject_mismatch", "detail": repr(subjects)[:240]})
    predicate = provenance.get("predicate")
    if not isinstance(predicate, dict):
        findings.append({"kind": "provenance_predicate_invalid", "detail": "predicate must be an object"})
        return provenance
    build_definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
        findings.append({"kind": "provenance_structure_invalid", "detail": "buildDefinition/runDetails missing"})
        return provenance
    if build_definition.get("buildType") != "https://meridianverity.com/buildtypes/permit-receipt-deterministic-zip/v2":
        findings.append({"kind": "provenance_build_type_mismatch", "detail": repr(build_definition.get("buildType"))})
    external = build_definition.get("externalParameters") or {}
    if external.get("tag") != TAG or external.get("asset_name") != ASSET_NAME:
        findings.append({"kind": "provenance_release_tuple_mismatch", "detail": repr(external)[:240]})
    internal = build_definition.get("internalParameters") or {}
    if manifest and internal.get("source_tree_sha256") != manifest.get("source_tree_sha256"):
        findings.append({"kind": "provenance_source_tree_mismatch", "detail": repr(internal.get("source_tree_sha256"))})
    materials = build_definition.get("resolvedDependencies") or []
    source_materials = [
        item
        for item in materials
        if isinstance(item, dict)
        and isinstance(item.get("digest"), dict)
        and "sha1" in item["digest"]
    ]
    if require_source_revision:
        if len(source_materials) != 1:
            findings.append({"kind": "provenance_source_revision_missing", "detail": repr(source_materials)[:240]})
        else:
            source = source_materials[0]
            commit = source["digest"].get("sha1")
            if not isinstance(commit, str) or HEX40_RE.fullmatch(commit) is None:
                findings.append({"kind": "provenance_source_commit_invalid", "detail": repr(commit)})
            if expected_source_repository and source.get("uri") != expected_source_repository:
                findings.append({"kind": "provenance_source_repository_mismatch", "detail": repr(source.get("uri"))})
            if expected_source_commit and commit != expected_source_commit:
                findings.append({"kind": "provenance_source_commit_mismatch", "detail": repr(commit)})
    byproducts = (run_details.get("byproducts") if isinstance(run_details, dict) else None) or []
    expected_byproducts = {
        SIDECAR_NAME: sha256(sidecar_path),
        MANIFEST_NAME: sha256(manifest_path),
    }
    observed = {
        item.get("name"): (item.get("digest") or {}).get("sha256")
        for item in byproducts
        if isinstance(item, dict) and isinstance(item.get("digest"), dict)
    }
    for name, digest in expected_byproducts.items():
        if observed.get(name) != digest:
            findings.append({"kind": "provenance_byproduct_mismatch", "detail": f"{name}: expected {digest}, observed {observed.get(name)}"})
    return provenance


def verify(
    zip_path: Path,
    sidecar_path: Path,
    manifest_path: Path,
    provenance_path: Path,
    *,
    expected_name: str = ASSET_NAME,
    require_source_revision: bool = False,
    expected_source_repository: str | None = None,
    expected_source_commit: str | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    for kind, path in (
        ("missing_zip", zip_path),
        ("missing_sidecar", sidecar_path),
        ("missing_asset_manifest", manifest_path),
        ("missing_provenance", provenance_path),
    ):
        if not path.exists():
            findings.append({"kind": kind, "detail": str(path)})
    if findings:
        return {"ok": False, "findings": findings}

    try:
        sidecar_digest, sidecar_name = parse_sidecar(sidecar_path)
    except Exception as exc:
        return {
            "ok": False,
            "findings": [{"kind": "sidecar_parse_error", "detail": str(exc)}],
        }

    observed_digest = sha256(zip_path)
    if zip_path.name != expected_name:
        findings.append(
            {"kind": "zip_name_mismatch", "detail": f"expected {expected_name}, observed {zip_path.name}"}
        )
    if sidecar_path.name != SIDECAR_NAME:
        findings.append(
            {
                "kind": "sidecar_name_mismatch",
                "detail": f"expected {SIDECAR_NAME}, observed {sidecar_path.name}",
            }
        )
    if sidecar_name != expected_name:
        findings.append(
            {
                "kind": "sidecar_asset_name_mismatch",
                "detail": f"expected {expected_name}, observed {sidecar_name}",
            }
        )
    if sidecar_digest != observed_digest:
        findings.append(
            {"kind": "sha256_mismatch", "detail": f"sidecar {sidecar_digest}, observed {observed_digest}"}
        )

    archive_entries: dict[str, tuple[int, str]] = {}
    directory_count = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            bad_crc = zf.testzip()
            if bad_crc is not None:
                findings.append({"kind": "zip_crc_failure", "detail": bad_crc})
            names = [info.filename for info in zf.infolist()]
            if len(names) != len(set(names)):
                findings.append({"kind": "duplicate_zip_member", "detail": "archive contains duplicate names"})
            for info in zf.infolist():
                name = info.filename
                if not _safe_member(name):
                    findings.append({"kind": "unsafe_zip_path", "detail": name})
                if not name.startswith(ROOT_DIR_NAME + "/"):
                    findings.append({"kind": "wrong_archive_root", "detail": name})
                if tuple(info.date_time) != NORMALIZED_ZIP_TIME:
                    findings.append({"kind": "zip_timestamp_mismatch", "detail": name})
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    findings.append({"kind": "zip_symlink_forbidden", "detail": name})
                if info.is_dir():
                    directory_count += 1
                    if stat.S_IMODE(mode) != 0o755:
                        findings.append({"kind": "directory_mode_mismatch", "detail": name})
                    continue
                if stat.S_IMODE(mode) != 0o644:
                    findings.append({"kind": "file_mode_mismatch", "detail": name})
                if info.compress_type != zipfile.ZIP_STORED:
                    findings.append({"kind": "zip_compression_mismatch", "detail": name})
                data = zf.read(info)
                archive_entries[name] = (len(data), sha256_bytes(data))
    except (zipfile.BadZipFile, OSError) as exc:
        findings.append({"kind": "zip_parse_error", "detail": type(exc).__name__})

    manifest = _verify_manifest(
        manifest_path,
        zip_path=zip_path,
        archive_entries=archive_entries,
        findings=findings,
    )
    provenance = _verify_provenance(
        provenance_path,
        zip_path=zip_path,
        sidecar_path=sidecar_path,
        manifest_path=manifest_path,
        manifest=manifest,
        findings=findings,
        require_source_revision=require_source_revision,
        expected_source_repository=expected_source_repository,
        expected_source_commit=expected_source_commit,
    )
    return {
        "ok": not findings,
        "tag": TAG,
        "asset_name": zip_path.name,
        "asset_size_bytes": zip_path.stat().st_size,
        "observed_sha256": observed_digest,
        "sidecar_name": sidecar_path.name,
        "sidecar_sha256_value": sidecar_digest,
        "asset_manifest_name": manifest_path.name,
        "provenance_name": provenance_path.name,
        "provenance_sha256": sha256(provenance_path) if provenance_path.exists() else None,
        "archive_file_count": len(archive_entries),
        "archive_directory_count": directory_count,
        "manifest_file_count": manifest.get("file_count") if manifest else None,
        "finding_count": len(findings),
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the v2.2.6 public-evaluation ZIP, sidecar, and asset manifest."
    )
    parser.add_argument("zip_path", help=f"Path to {ASSET_NAME}")
    parser.add_argument("sidecar_path", help=f"Path to {SIDECAR_NAME}")
    parser.add_argument(
        "--manifest",
        dest="manifest_path",
        help=f"Path to {MANIFEST_NAME}; defaults beside the ZIP.",
    )
    parser.add_argument(
        "--provenance",
        dest="provenance_path",
        help=f"Path to {PROVENANCE_NAME}; defaults beside the ZIP.",
    )
    parser.add_argument("--expected-name", default=ASSET_NAME)
    parser.add_argument("--require-source-revision", action="store_true")
    parser.add_argument("--expected-source-repository")
    parser.add_argument("--expected-source-commit")
    args = parser.parse_args()
    if args.expected_source_commit and HEX40_RE.fullmatch(args.expected_source_commit) is None:
        parser.error("--expected-source-commit must be one lowercase 40-hex Git object ID")
    zip_path = Path(args.zip_path)
    sidecar_path = Path(args.sidecar_path)
    manifest_path = Path(args.manifest_path) if args.manifest_path else zip_path.with_name(MANIFEST_NAME)
    provenance_path = Path(args.provenance_path) if args.provenance_path else zip_path.with_name(PROVENANCE_NAME)
    report = verify(
        zip_path,
        sidecar_path,
        manifest_path,
        provenance_path,
        expected_name=args.expected_name,
        require_source_revision=args.require_source_revision,
        expected_source_repository=args.expected_source_repository,
        expected_source_commit=args.expected_source_commit,
    )
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
