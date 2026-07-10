"""Canonical source-slice inventory rules for manifests and release packaging."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable, Iterator

ROOT = Path(__file__).resolve().parents[1]

EXCLUDE_DIRS = frozenset(
    {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        "tmp",
        "dist",
        "build",
        "results",
        "checks",
        "htmlcov",
    }
)
EXCLUDE_SUFFIXES = frozenset(
    {".pyc", ".pyo", ".sqlite", ".sqlite3", ".db", ".log"}
)
EXCLUDE_FILES = frozenset({".coverage", "coverage.json", "coverage.xml", "coverage-core.json"})
EXCLUDE_GENERATED_DIR_SUFFIXES = (".egg-info",)
STATIC_MANIFEST_FILES = frozenset({"MANIFEST.json", "MANIFEST.sha256.json"})


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def excluded(rel: Path, path: Path) -> bool:
    return (
        any(
            part in EXCLUDE_DIRS or part.endswith(EXCLUDE_GENERATED_DIR_SUFFIXES)
            for part in rel.parts
        )
        or path.suffix.lower() in EXCLUDE_SUFFIXES
        or rel.as_posix() in EXCLUDE_FILES
    )


def iter_source_files(
    root: Path = ROOT,
    *,
    extra_exclude_files: Iterable[str] = (),
    reject_symlinks: bool = True,
) -> Iterator[tuple[Path, Path]]:
    excluded_files = set(extra_exclude_files)
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root)
        if path.is_symlink():
            if reject_symlinks and not excluded(rel, path):
                raise ValueError(f"symbolic links are forbidden in the release slice: {rel.as_posix()}")
            continue
        if not path.is_file() or excluded(rel, path) or rel.as_posix() in excluded_files:
            continue
        yield rel, path


def source_entries(
    root: Path = ROOT,
    *,
    extra_exclude_files: Iterable[str] = (),
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for rel, path in iter_source_files(root, extra_exclude_files=extra_exclude_files):
        entries.append(
            {
                "path": rel.as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return entries


def digest_entries(entries: Iterable[dict[str, object]]) -> str:
    h = hashlib.sha256()
    for entry in entries:
        h.update(str(entry["path"]).encode("utf-8"))
        h.update(b"\0")
        h.update(str(entry["bytes"]).encode("ascii"))
        h.update(b"\0")
        h.update(str(entry["sha256"]).encode("ascii"))
        h.update(b"\0")
    return h.hexdigest()
