#!/usr/bin/env python3
"""Small dependency-free static security and supply-chain hygiene gate."""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

try:
    from release_config import PUBLIC_VERSION
    from source_inventory import iter_source_files
except ImportError:  # pragma: no cover
    from tools.release_config import PUBLIC_VERSION
    from tools.source_inventory import iter_source_files

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_bearer": re.compile(r"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
}
ALLOWED_SECRET_FIXTURES = {"tests", "evaluation_vectors", "test_vectors_paygate_domain"}
SECURITY_MODULES = {
    "orprg_eval/canonicalization.py",
    "orprg_eval/crypto.py",
    "orprg_eval/httpio.py",
    "orprg_eval/jsonio.py",
    "orprg_eval/merkle.py",
    "orprg_eval/persistent_replay.py",
    "orprg_eval/replay.py",
    "orprg_eval/schema.py",
    "orprg_eval/timeutil.py",
    "orprg_eval/verifier.py",
}
SHA_PIN_RE = re.compile(r"^\s*uses:\s*[^@\s]+@([0-9a-f]{40})\s*(?:#.*)?$", re.MULTILINE)
USES_RE = re.compile(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)


class Visitor(ast.NodeVisitor):
    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.findings: list[dict[str, object]] = []

    def add(self, node: ast.AST, kind: str, detail: str) -> None:
        self.findings.append({"path": self.rel, "line": getattr(node, "lineno", None), "kind": kind, "detail": detail})

    def visit_Call(self, node: ast.Call) -> None:
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                name = f"{node.func.value.id}.{node.func.attr}"
            else:
                name = node.func.attr
        if name in {"eval", "exec"}:
            self.add(node, "dynamic_code_execution", name)
        if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads"}:
            self.add(node, "unsafe_deserialization", name)
        if name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
            self.add(node, "weak_hash", name)
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                self.add(node, "subprocess_shell_true", name or "call")
            if keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                self.add(node, "tls_verification_disabled", name or "call")
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in {"pickle", "marshal"}:
                self.add(node, "unsafe_deserialization_import", alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in {"pickle", "marshal"}:
            self.add(node, "unsafe_deserialization_import", node.module or "")
        self.generic_visit(node)


def scan_python(rel: str, path: Path) -> list[dict[str, object]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    except SyntaxError as exc:
        return [{"path": rel, "line": exc.lineno, "kind": "python_syntax_error", "detail": exc.msg}]
    visitor = Visitor(rel)
    visitor.visit(tree)
    return visitor.findings


def scan_workflows(findings: list[dict[str, object]]) -> None:
    workflow_dir = ROOT / ".github" / "workflows"
    if not workflow_dir.is_dir():
        findings.append({"path": ".github/workflows", "kind": "missing_ci_workflow", "detail": "at least one pinned CI workflow is required"})
        return
    for path in sorted(workflow_dir.glob("*.y*ml")):
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        uses = list(USES_RE.finditer(text))
        if not uses:
            findings.append({"path": rel, "kind": "workflow_has_no_actions", "detail": "expected pinned checkout/setup action"})
        for match in uses:
            ref = match.group(2)
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                findings.append({"path": rel, "kind": "workflow_action_not_sha_pinned", "detail": match.group(0).strip()})
        if not re.search(r"(?m)^permissions:\s*\n\s+contents:\s+read\s*$", text):
            findings.append({"path": rel, "kind": "workflow_permissions_not_least_privilege", "detail": "top-level contents: read required"})
        if "persist-credentials: false" not in text:
            findings.append({"path": rel, "kind": "checkout_credentials_persisted", "detail": "set persist-credentials: false"})
        if "pip install" in text and "-e ." in text and "--no-build-isolation" not in text:
            findings.append({
                "path": rel,
                "kind": "editable_build_isolation_not_disabled",
                "detail": "install exact build tools first, then use --no-build-isolation",
            })


def scan_lock(findings: list[dict[str, object]]) -> None:
    lock = ROOT / "requirements-lock-py313-linux-x86_64.txt"
    if not lock.exists():
        findings.append({"path": lock.name, "kind": "missing_hash_lock", "detail": "file not found"})
        return
    logical = "".join(line for line in lock.read_text(encoding="utf-8").splitlines(keepends=True) if not line.lstrip().startswith("#"))
    records = re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^\\\s]+)\s+\\\n\s+--hash=sha256:([0-9a-f]{64})", logical)
    if len(records) < 10:
        findings.append({"path": lock.name, "kind": "lock_record_count_too_low", "detail": str(len(records))})
    versions = {name.lower().replace("_", "-"): version for name, version, _ in records}
    expected_versions = {
        "cryptography": "49.0.0",
        "pytest": "9.1.1",
        "jsonschema": "4.26.0",
        "coverage": "7.15.0",
        "setuptools": "83.0.0",
        "wheel": "0.47.0",
    }
    for required, expected in expected_versions.items():
        observed = versions.get(required)
        if observed is None:
            findings.append({"path": lock.name, "kind": "required_lock_package_missing", "detail": required})
        elif observed != expected:
            findings.append({
                "path": lock.name,
                "kind": "certified_lock_version_mismatch",
                "detail": f"{required}: expected {expected}, observed {observed}",
            })

    pyproject = ROOT / "pyproject.toml"
    try:
        import tomllib

        project_data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        build_requires = set((project_data.get("build-system") or {}).get("requires") or [])
    except Exception as exc:
        findings.append({"path": pyproject.name, "kind": "build_system_parse_failure", "detail": str(exc)})
    else:
        required_build = {"setuptools==83.0.0", "wheel==0.47.0"}
        if build_requires != required_build:
            findings.append({
                "path": pyproject.name,
                "kind": "build_backend_not_exactly_pinned",
                "detail": repr(sorted(build_requires)),
            })


def main() -> int:
    findings: list[dict[str, object]] = []
    python_files = 0
    scanned_files = 0
    for rel_path, path in iter_source_files(ROOT):
        rel = rel_path.as_posix()
        scanned_files += 1
        if path.suffix == ".py":
            python_files += 1
            findings.extend(scan_python(rel, path))
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        fixture_scope = any(part in ALLOWED_SECRET_FIXTURES for part in rel_path.parts)
        if not fixture_scope:
            for kind, regex in SECRET_PATTERNS.items():
                match = regex.search(text)
                if match:
                    findings.append({"path": rel, "kind": f"possible_secret_{kind}", "detail": match.group(0)[:80]})
    scan_workflows(findings)
    scan_lock(findings)
    report = {
        "ok": not findings,
        "version": PUBLIC_VERSION,
        "scanned_files": scanned_files,
        "python_files": python_files,
        "security_modules": sorted(SECURITY_MODULES),
        "finding_count": len(findings),
        "findings": findings,
    }
    CHECKS.mkdir(exist_ok=True)
    (CHECKS / "static_security_scan.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
