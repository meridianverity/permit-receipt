#!/usr/bin/env python3
from __future__ import annotations
import contextlib, json, os, runpy, sys, time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault('PYTHONDONTWRITEBYTECODE', '1')
sys.dont_write_bytecode = True
CHECKS = ROOT / 'checks'
CHECKS.mkdir(exist_ok=True)


def run_module(module: str, argv: list[str] | None = None) -> int:
    old = sys.argv[:]
    try:
        sys.argv = [module] + (argv or [])
        runpy.run_module(module, run_name='__main__')
        return 0
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) else 1
    finally:
        sys.argv = old


def run_path(path: str, argv: list[str] | None = None) -> int:
    old = sys.argv[:]
    try:
        sys.argv = [path] + (argv or [])
        runpy.run_path(str(ROOT / path), run_name='__main__')
        return 0
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) else 1
    finally:
        sys.argv = old


def run_pytest() -> int:
    import pytest  # type: ignore
    return int(pytest.main(['-q', '-p', 'no:cacheprovider']))


def main() -> int:
    os.environ.setdefault('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')
    steps: list[tuple[str, Callable[[], int]]] = [
        ('hybrid_demo', lambda: run_module('paygate_hybrid.hybrid_demo', ['--out', 'checks', '--json'])),
        ('paygate_demo', lambda: run_module('paygate_poc.demo', ['--out', 'checks', '--json'])),
        ('paygate_ref', lambda: run_path('scripts/run_paygate_ref.py', ['--out', 'checks/paygate_ref_demo_results.json', '--summary-md', 'checks/paygate_ref_demo_summary.md'])),
        ('orprg_vectors', lambda: run_path('run_vectors.py')),
        ('pytest', run_pytest),
        ('release_gate', lambda: run_path('tools/release_gate.py')),
    ]
    rows = []
    start = time.perf_counter()
    for i, (label, fn) in enumerate(steps, 1):
        t = time.perf_counter()
        CHECKS.mkdir(exist_ok=True)
        out = CHECKS / f'public_eval_{i:02d}_{label}_stdout.txt'
        err = CHECKS / f'public_eval_{i:02d}_{label}_stderr.txt'
        rc = 0
        with out.open('w', encoding='utf-8') as fo, err.open('w', encoding='utf-8') as fe:
            with contextlib.redirect_stdout(fo), contextlib.redirect_stderr(fe):
                try:
                    rc = fn()
                except Exception as exc:
                    rc = 1
                    import traceback
                    fe.write(f'EXCEPTION: {exc!r}\n')
                    traceback.print_exc(file=fe)
        row = {'step': i, 'label': label, 'exit': rc, 'elapsed_seconds': round(time.perf_counter()-t, 6), 'stdout': out.name, 'stderr': err.name}
        rows.append(row)
        print(f"[{i}/{len(steps)}] {label} exit={rc}")
        if rc != 0:
            break
    summary = {'ok': all(r['exit'] == 0 for r in rows) and len(rows) == len(steps), 'rows': rows, 'total_elapsed_seconds': round(time.perf_counter()-start, 6)}
    (CHECKS/'public_eval_run_summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
