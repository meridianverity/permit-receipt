#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
EXCLUDE_DIRS = {'.git','.github','__pycache__','.pytest_cache','.mypy_cache','tmp','dist','build','results','checks'}
EXCLUDE_SUFFIXES = {'.pyc'}
EXCLUDE_FILES = {'MANIFEST.json', 'MANIFEST.sha256.json', '.gitignore'}
EXCLUDE_GENERATED_DIR_SUFFIXES = ('.egg-info',)

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def main() -> int:
    entries=[]
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file(): continue
        rel = p.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS or part.endswith(EXCLUDE_GENERATED_DIR_SUFFIXES) for part in rel.parts): continue
        if p.suffix in EXCLUDE_SUFFIXES: continue
        if rel.as_posix() in EXCLUDE_FILES: continue
        entries.append({'path': rel.as_posix(), 'bytes': p.stat().st_size, 'sha256': sha256(p)})
    manifest = {
        'artifact': 'PermitReceipt Public Evaluation Slice for AI-Agent External Effects v2.2.5',
        'manifest_format': 'static-sha256-list-v2',
        'scope': 'static source/provenance files only; generated checks/results directories are intentionally excluded',
        'excludes': sorted(EXCLUDE_FILES) + sorted(EXCLUDE_DIRS) + ['*.egg-info/'],
        'entries': entries,
    }
    (ROOT/'MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf-8')
    (ROOT/'MANIFEST.sha256.json').write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps({'ok': True, 'entries': len(entries)}, indent=2))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
