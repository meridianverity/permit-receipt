from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / 'MANIFEST.sha256.json'
EXCLUDE_DIRS = {'.git', '.github', '__pycache__', '.pytest_cache', '.mypy_cache', 'tmp', 'dist', 'build', 'results', 'checks'}
EXCLUDE_SUFFIXES = {'.pyc'}
EXCLUDE_FILES = {'MANIFEST.json', 'MANIFEST.sha256.json', '.gitignore'}

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def included_paths():
    paths=[]
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT)
        rel_s = rel.as_posix()
        if any(part in EXCLUDE_DIRS for part in rel.parts):
            continue
        if p.suffix in EXCLUDE_SUFFIXES:
            continue
        if rel_s in EXCLUDE_FILES:
            continue
        paths.append(rel_s)
    return paths

def main() -> int:
    if not MANIFEST.exists():
        print(json.dumps({'ok': False, 'error': 'missing_manifest'}, indent=2)); return 1
    manifest=json.loads(MANIFEST.read_text(encoding='utf-8'))
    entries=manifest.get('entries', [])
    entry_map={e['path']: e for e in entries}
    expected=set(included_paths())
    listed=set(entry_map)
    problems=[]
    for rel, e in sorted(entry_map.items()):
        p=ROOT/rel
        if not p.exists():
            problems.append({'path':rel,'problem':'missing'}); continue
        got=sha(p)
        if got != e['sha256']:
            problems.append({'path':rel,'problem':'sha256_mismatch','expected':e['sha256'],'observed':got})
    for rel in sorted(expected-listed):
        problems.append({'path': rel, 'problem': 'not_listed_in_manifest'})
    for rel in sorted(listed-expected):
        problems.append({'path': rel, 'problem': 'listed_but_excluded_or_unexpected'})
    print(json.dumps({'ok': not problems, 'entries': len(entries), 'expected_static_files': len(expected), 'problems': problems[:50]}, indent=2, sort_keys=True))
    return 0 if not problems else 2
if __name__ == '__main__':
    sys.exit(main())
