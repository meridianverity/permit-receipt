#!/usr/bin/env python3
"""Create optional GitHub dotfiles from visible templates.

This helper is for users who received the manual-upload-friendly public
evaluation packet. The public evaluation does not require these files for
manifest verification, but adding them enables GitHub Actions, issue templates,
and local ignore hygiene.
"""
from __future__ import annotations
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
MAP = {
    ROOT / 'github-ui-files' / 'workflows' / 'qa.yml': ROOT / '.github' / 'workflows' / 'qa.yml',
    ROOT / 'github-ui-files' / 'workflows' / 'ietf126-review-packet.yml': ROOT / '.github' / 'workflows' / 'ietf126-review-packet.yml',
    ROOT / 'github-ui-files' / 'issue-templates' / 'ietf126-cross-reference.md': ROOT / '.github' / 'ISSUE_TEMPLATE' / 'ietf126-cross-reference.md',
    ROOT / 'github-ui-files' / 'issue-templates' / 'ietf126-field-model.md': ROOT / '.github' / 'ISSUE_TEMPLATE' / 'ietf126-field-model.md',
    ROOT / 'github-ui-files' / 'issue-templates' / 'ietf126-negative-vector.md': ROOT / '.github' / 'ISSUE_TEMPLATE' / 'ietf126-negative-vector.md',
    ROOT / 'github-ui-files' / 'gitignore.txt': ROOT / '.gitignore',
}

def main() -> int:
    copied = []
    missing = []
    for src, dst in MAP.items():
        if not src.exists():
            missing.append(src.relative_to(ROOT).as_posix())
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(dst.relative_to(ROOT).as_posix())
    print({'copied': copied, 'missing_templates': missing})
    return 0 if not missing else 2

if __name__ == '__main__':
    raise SystemExit(main())
