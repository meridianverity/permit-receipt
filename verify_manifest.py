from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "MANIFEST.sha256.json"
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


def included_paths() -> list[str]:
    output: list[str] = []
    for path in sorted(ROOT.rglob("*"), key=lambda item: item.relative_to(ROOT).as_posix()):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS or part.endswith(EXCLUDE_GENERATED_DIR_SUFFIXES) for part in rel.parts):
            continue
        if path.suffix.lower() in EXCLUDE_SUFFIXES or rel.as_posix() in EXCLUDE_FILES:
            continue
        output.append(rel.as_posix())
    return output


def main() -> int:
    if not MANIFEST.exists():
        print(json.dumps({"ok": False, "error": "missing_manifest"}, indent=2))
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = manifest.get("entries", [])
    entry_map = {entry["path"]: entry for entry in entries}
    expected = set(included_paths())
    listed = set(entry_map)
    problems: list[dict[str, object]] = []
    for rel, entry in sorted(entry_map.items()):
        path = ROOT / rel
        if not path.exists():
            problems.append({"path": rel, "problem": "missing"})
            continue
        observed_digest = sha256(path)
        observed_bytes = path.stat().st_size
        if observed_digest != entry.get("sha256"):
            problems.append({"path": rel, "problem": "sha256_mismatch", "expected": entry.get("sha256"), "observed": observed_digest})
        if observed_bytes != entry.get("bytes"):
            problems.append({"path": rel, "problem": "size_mismatch", "expected": entry.get("bytes"), "observed": observed_bytes})
    for rel in sorted(expected - listed):
        problems.append({"path": rel, "problem": "not_listed_in_manifest"})
    for rel in sorted(listed - expected):
        problems.append({"path": rel, "problem": "listed_but_excluded_or_unexpected"})
    report = {"ok": not problems, "entries": len(entries), "expected_static_files": len(expected), "problems": problems[:100]}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not problems else 2


if __name__ == "__main__":
    sys.exit(main())
