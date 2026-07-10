#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

try:
    from release_config import ARTIFACT_LABEL
except ImportError:  # pragma: no cover
    from tools.release_config import ARTIFACT_LABEL

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE_DIRS = {
    ".git", ".github", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".venv", "venv", "tmp", "dist", "build", "results", "checks", "htmlcov",
}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".sqlite", ".sqlite3", ".db", ".log"}
EXCLUDE_FILES = {
    "MANIFEST.json", "MANIFEST.sha256.json", ".gitignore", ".coverage",
    "coverage.json", "coverage.xml", "coverage-core.json",
}
EXCLUDE_GENERATED_DIR_SUFFIXES = (".egg-info",)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def included_paths() -> list[Path]:
    paths: list[Path] = []
    for path in sorted(ROOT.rglob("*"), key=lambda item: item.relative_to(ROOT).as_posix()):
        if path.is_symlink():
            raise ValueError(f"symbolic links are forbidden: {path}")
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS or part.endswith(EXCLUDE_GENERATED_DIR_SUFFIXES) for part in rel.parts):
            continue
        if path.suffix.lower() in EXCLUDE_SUFFIXES or rel.as_posix() in EXCLUDE_FILES:
            continue
        paths.append(path)
    return paths


def main() -> int:
    entries = [
        {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": sha256(path)}
        for path in included_paths()
    ]
    manifest = {
        "artifact": ARTIFACT_LABEL,
        "manifest_format": "static-sha256-list-v3",
        "scope": "static source, tests, schemas, documentation, and provenance files; generated run-output directories are excluded",
        "excludes": sorted(EXCLUDE_FILES) + sorted(EXCLUDE_DIRS) + sorted(EXCLUDE_SUFFIXES) + ["*.egg-info/"],
        "entries": entries,
    }
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (ROOT / "MANIFEST.json").write_text(payload, encoding="utf-8", newline="\n")
    (ROOT / "MANIFEST.sha256.json").write_text(payload, encoding="utf-8", newline="\n")
    print(json.dumps({"ok": True, "entries": len(entries)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
