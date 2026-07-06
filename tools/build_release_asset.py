#!/usr/bin/env python3
"""Build the public-evaluation ZIP asset and SHA-256 sidecar.

The output ZIP is intentionally outside the repository root by default or under
an excluded `dist/` directory so that packaging outputs are not embedded back
into the public evaluation slice.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TAG = "v2.2.5-public-eval"
DEFAULT_ASSET_NAME = "permit-receipt-ref-eval-v2_2_5-public-eval.zip"
ROOT_DIR_NAME = "permit-receipt-main"
NORMALIZED_ZIP_TIME = (2026, 7, 6, 0, 0, 0)
EXCLUDE_DIRS = {
    ".git",
    ".github",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "tmp",
    "dist",
    "build",
    "results",
    "checks",
}
EXCLUDE_SUFFIXES = {".pyc"}
EXCLUDE_FILES = {".gitignore"}
EXCLUDE_GENERATED_DIR_SUFFIXES = (".egg-info",)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def included_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        rel_s = rel.as_posix()
        if any(part in EXCLUDE_DIRS or part.endswith(EXCLUDE_GENERATED_DIR_SUFFIXES) for part in rel.parts):
            continue
        if path.suffix in EXCLUDE_SUFFIXES:
            continue
        if rel_s in EXCLUDE_FILES:
            continue
        files.append(path)
    return files


def add_directory_entries(zf: zipfile.ZipFile, files: list[Path]) -> None:
    dirs = {ROOT_DIR_NAME}
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        parts = rel.split("/")[:-1]
        current = ROOT_DIR_NAME
        for part in parts:
            current = f"{current}/{part}"
            dirs.add(current)
    for name in sorted(dirs):
        info = zipfile.ZipInfo(name.rstrip("/") + "/", NORMALIZED_ZIP_TIME)
        info.external_attr = (stat.S_IFDIR | 0o755) << 16
        zf.writestr(info, b"")


def build_zip(out_dir: Path, asset_name: str) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / asset_name
    sidecar_path = out_dir / f"{asset_name}.sha256"
    metadata_path = out_dir / f"{asset_name}.manifest.json"
    files = included_files()
    if zip_path.exists():
        zip_path.unlink()
    if sidecar_path.exists():
        sidecar_path.unlink()
    if metadata_path.exists():
        metadata_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        add_directory_entries(zf, files)
        for path in files:
            rel = path.relative_to(ROOT).as_posix()
            arcname = f"{ROOT_DIR_NAME}/{rel}"
            info = zipfile.ZipInfo(arcname, NORMALIZED_ZIP_TIME)
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with path.open("rb") as f:
                zf.writestr(info, f.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = sha256(zip_path)
    sidecar_path.write_text(f"{digest}  {asset_name}\n", encoding="utf-8")
    metadata = {
        "asset_name": asset_name,
        "asset_sha256": digest,
        "asset_size_bytes": zip_path.stat().st_size,
        "file_count": len(files),
        "root_dir_name": ROOT_DIR_NAME,
        "tag": DEFAULT_TAG,
        "sidecar_name": sidecar_path.name,
        "sidecar_sha256": sha256(sidecar_path),
        "zip_timestamp_policy": "all entries normalized to 2026-07-06T00:00:00 local ZIP timestamp",
        "excluded_dirs": sorted(EXCLUDE_DIRS),
        "excluded_files": sorted(EXCLUDE_FILES),
        "excluded_suffixes": sorted(EXCLUDE_SUFFIXES),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the v2.2.5 public-evaluation release asset and sidecar.")
    parser.add_argument("--out-dir", default="dist", help="Output directory for ZIP, sidecar, and packaging metadata.")
    parser.add_argument("--asset-name", default=DEFAULT_ASSET_NAME, help="Release ZIP asset name.")
    args = parser.parse_args()
    metadata = build_zip(Path(args.out_dir), args.asset_name)
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
