"""
Static feature extractor for the PQC detector dataset.

Parses a Python source file with the `ast` module and extracts:
  - imports (module + alias + imported names)
  - function calls (dotted name + line number)
  - randomness usage flags (uses_random, uses_os_urandom, uses_secrets)
  - call counts and a flat list of called names for downstream ML features

The result is written next to the input file as <name>.features.json,
or to a path provided via --output.

Usage:
    python parser.py path/to/file.py
    python parser.py path/to/file.py --output features.json
    python parser.py dataset/vulnerable --recursive
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter
from pathlib import Path


WEAK_RANDOM_FUNCS = {
    "random", "randint", "randrange", "choice", "choices",
    "sample", "uniform", "getrandbits", "shuffle", "seed",
}
SECURE_RANDOM_FUNCS = {
    "urandom", "token_bytes", "token_hex", "token_urlsafe",
    "randbits", "choice", "SystemRandom",
}


def _dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted attribute chain (e.g. os.path.join) from an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


class FeatureVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[dict] = []
        self.imported_modules: set[str] = set()
        self.imported_aliases: dict[str, str] = {}  # alias -> real module
        self.calls: list[dict] = []
        self.functions_defined: list[str] = []
        self.classes_defined: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append({
                "type": "import",
                "module": alias.name,
                "alias": alias.asname,
                "line": node.lineno,
            })
            self.imported_modules.add(alias.name.split(".")[0])
            self.imported_aliases[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self.imports.append({
                "type": "from_import",
                "module": module,
                "name": alias.name,
                "alias": alias.asname,
                "line": node.lineno,
            })
            if module:
                self.imported_modules.add(module.split(".")[0])
            self.imported_aliases[alias.asname or alias.name] = full
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        if name:
            self.calls.append({"name": name, "line": node.lineno})
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions_defined.append(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions_defined.append(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes_defined.append(node.name)
        self.generic_visit(node)


def _detect_randomness(visitor: FeatureVisitor) -> dict:
    """Decide whether the file uses random / os.urandom / secrets.

    Resolution rules:
      - `random` module imports (or `from random import ...`) flag random usage.
      - `os.urandom` calls flag secure usage; importing `os` alone is not enough.
      - `secrets` module imports flag secure usage.
      - Aliased imports (e.g. `import random as rnd`) are resolved via the
        alias table built during visit.
    """
    uses_random = "random" in visitor.imported_modules
    uses_os_urandom = False
    uses_secrets = "secrets" in visitor.imported_modules

    weak_calls: list[str] = []
    secure_calls: list[str] = []

    for call in visitor.calls:
        name = call["name"]
        head, _, tail = name.partition(".")

        resolved_head = visitor.imported_aliases.get(head, head)
        resolved_root = resolved_head.split(".")[0]

        if resolved_root == "random":
            uses_random = True
            weak_calls.append(name)
        elif resolved_root == "os" and tail == "urandom":
            uses_os_urandom = True
            secure_calls.append(name)
        elif resolved_root == "secrets":
            uses_secrets = True
            secure_calls.append(name)
        elif head in WEAK_RANDOM_FUNCS and visitor.imported_aliases.get(head, "").startswith("random"):
            uses_random = True
            weak_calls.append(name)
        elif head == "urandom" and visitor.imported_aliases.get(head, "") == "os.urandom":
            uses_os_urandom = True
            secure_calls.append(name)

    return {
        "uses_random": uses_random,
        "uses_os_urandom": uses_os_urandom,
        "uses_secrets": uses_secrets,
        "weak_random_calls": weak_calls,
        "secure_random_calls": secure_calls,
    }


def extract_features(file_path: Path) -> dict:
    """Read a .py file from disk and extract its features."""
    source = file_path.read_text(encoding="utf-8")
    return extract_features_from_source(source, str(file_path))


def extract_features_from_source(source: str, filename: str = "<input>") -> dict:
    """Extract features from raw source code (no disk I/O)."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return {
            "file": filename,
            "error": f"SyntaxError: {exc.msg} at line {exc.lineno}",
        }

    visitor = FeatureVisitor()
    visitor.visit(tree)

    call_names = [c["name"] for c in visitor.calls]
    call_counts = Counter(call_names)
    randomness = _detect_randomness(visitor)

    return {
        "file": filename,
        "loc": len(source.splitlines()),
        "imports": visitor.imports,
        "imported_modules": sorted(visitor.imported_modules),
        "functions_defined": visitor.functions_defined,
        "classes_defined": visitor.classes_defined,
        "calls": visitor.calls,
        "call_names": call_names,
        "call_counts": dict(call_counts.most_common()),
        "randomness": randomness,
    }


def _iter_targets(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    pattern = "**/*.py" if recursive else "*.py"
    return sorted(p for p in path.glob(pattern) if p.is_file())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract AST features from Python files.")
    ap.add_argument("path", type=Path, help="Python file or directory to analyze")
    ap.add_argument("--output", type=Path, help="Output JSON path (single-file mode)")
    ap.add_argument("--recursive", action="store_true", help="Recurse when path is a directory")
    args = ap.parse_args(argv)

    if not args.path.exists():
        print(f"error: {args.path} does not exist", file=sys.stderr)
        return 2

    targets = _iter_targets(args.path, args.recursive)
    if not targets:
        print(f"error: no .py files found under {args.path}", file=sys.stderr)
        return 2

    if len(targets) == 1:
        features = extract_features(targets[0])
        out = args.output or targets[0].with_suffix(".features.json")
        out.write_text(json.dumps(features, indent=2), encoding="utf-8")
        print(f"wrote {out}")
        return 0

    if args.output:
        print("error: --output is only valid when analyzing a single file", file=sys.stderr)
        return 2

    for target in targets:
        features = extract_features(target)
        out = target.with_suffix(".features.json")
        out.write_text(json.dumps(features, indent=2), encoding="utf-8")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
