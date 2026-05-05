"""
PQC Detector CLI.

Pipeline for a single Python file:
  1. Run parser.extract_features() to get AST-level features.
  2. Run rule-based detectors mapping AST patterns -> known weakness types
     defined in the dataset (weak_randomness, key_and_nonce_reuse,
     insufficient_security_parameters, unchecked_signature_verification).
  3. If a fine-tuned CodeBERT model is available (default: runs/codebert/final),
     also run the model and include its prediction in the report.
  4. Emit a human-readable or JSON report listing weakness type, severity,
     line number, evidence, and a concrete suggested fix.

Usage:
    python cli.py path/to/file.py
    python cli.py path/to/file.py --json
    python cli.py path/to/file.py --save report.json
    python cli.py path/to/file.py --model-dir runs/codebert/final
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from parser import _dotted_name, extract_features, extract_features_from_source  # noqa: E402


WEAKNESS_CATALOG: dict[str, dict] = {
    "weak_randomness": {
        "severity": "critical",
        "title": "Weak randomness in key generation",
        "suggestion": (
            "Replace `random.*` with `os.urandom(n)` or `secrets.token_bytes(n)`. "
            "Cryptographic key material requires a CSPRNG; the standard `random` "
            "module uses Mersenne Twister and is predictable from a small amount "
            "of observed output."
        ),
    },
    "key_and_nonce_reuse": {
        "severity": "critical",
        "title": "Key or nonce reuse in symmetric encryption",
        "suggestion": (
            "Generate a fresh nonce with `os.urandom(12)` for every AES-GCM "
            "encryption, and derive a fresh shared secret per session via a new "
            "KEM encapsulation. Nonce reuse under the same GCM key leaks the "
            "authentication subkey H and lets an attacker forge ciphertexts and "
            "recover plaintexts via XOR."
        ),
    },
    "insufficient_security_parameters": {
        "severity": "high",
        "title": "Post-quantum parameter set below required security level",
        "suggestion": (
            "Use `security_level=768` (ML-KEM-768 / Dilithium3, NIST category 3) "
            "or higher. Level 512 only targets NIST category 1 and is below the "
            "policy threshold for this project."
        ),
    },
    "unchecked_signature_verification": {
        "severity": "critical",
        "title": "Signature verification result ignored",
        "suggestion": (
            "Bind the boolean returned by `verify()` and gate downstream "
            "processing on it, e.g. `if not Dilithium3.verify(pk, msg, sig): "
            "raise InvalidSignature(...)`. Discarding the result makes the "
            "signature scheme equivalent to no signature at all."
        ),
    },
}

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    weakness_type: str
    severity: str
    title: str
    line: int | None
    evidence: str
    suggestion: str


def _finding(weakness_type: str, line: int | None, evidence: str) -> Finding:
    cat = WEAKNESS_CATALOG[weakness_type]
    return Finding(
        weakness_type=weakness_type,
        severity=cat["severity"],
        title=cat["title"],
        line=line,
        evidence=evidence,
        suggestion=cat["suggestion"],
    )


# ---------- Rule-based detectors ----------

def detect_weak_randomness(features: dict) -> list[Finding]:
    """Flag any call resolving to the standard `random` module, including
    aliased imports (`import random as rng`) and from-imports
    (`from random import getrandbits`)."""
    rnd = features["randomness"]
    if not rnd["uses_random"]:
        return []

    aliases: dict[str, str] = {}
    for imp in features["imports"]:
        if imp["type"] == "import":
            key = imp.get("alias") or imp["module"]
            aliases[key] = imp["module"]
        else:  # from_import
            module = imp.get("module") or ""
            full = f"{module}.{imp['name']}" if module else imp["name"]
            key = imp.get("alias") or imp["name"]
            aliases[key] = full

    findings: list[Finding] = []
    for call in features["calls"]:
        name = call["name"]
        head = name.split(".")[0]
        resolved_root = aliases.get(head, head).split(".")[0]
        if resolved_root == "random":
            findings.append(_finding("weak_randomness", call["line"], name))
    return findings


def detect_unchecked_verify(tree: ast.AST) -> list[Finding]:
    """Flag `*.verify(...)` whose return value is discarded.

    AST shape for a discarded-return call is ast.Expr(value=ast.Call(...)).
    Calls inside `if`, assignments, comparisons, etc. are not wrapped in Expr,
    so they are not flagged.
    """
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)):
            continue
        name = _dotted_name(node.value.func)
        if name.endswith(".verify") or name == "verify":
            findings.append(_finding(
                "unchecked_signature_verification",
                node.lineno,
                f"{name}(...) result discarded",
            ))
    return findings


def detect_wrong_params(tree: ast.AST) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords or []:
                if kw.arg == "security_level" and isinstance(kw.value, ast.Constant):
                    if kw.value.value == 512:
                        callee = _dotted_name(node.func) or "<callable>"
                        findings.append(_finding(
                            "insufficient_security_parameters",
                            node.lineno,
                            f"{callee}(security_level=512)",
                        ))
        # Direct references to PQC variants below NIST level 3.
        if isinstance(node, ast.Name) and node.id in LOW_LEVEL_PQC_NAMES:
            findings.append(_finding(
                "insufficient_security_parameters",
                node.lineno,
                node.id,
            ))
        if isinstance(node, ast.Attribute) and node.attr in LOW_LEVEL_PQC_NAMES:
            findings.append(_finding(
                "insufficient_security_parameters",
                node.lineno,
                _dotted_name(node),
            ))
    return findings


LOW_LEVEL_PQC_NAMES = {
    "Kyber512", "MLKEM512", "ML_KEM_512",
    "Dilithium2", "MLDSA44", "ML_DSA_44",
    "Falcon512",
}


def detect_key_reuse(tree: ast.AST) -> list[Finding]:
    """Three heuristics:
       (a) encrypt() called with a constant-bytes literal directly as nonce.
       (b) encrypt() called with a name-bound nonce whose binding is a
           constant-bytes literal anywhere in the file (module or local scope).
       (c) encrypt() called inside a for/while loop using a name-bound nonce
           that is not (re)assigned inside the loop body.
    """
    findings: list[Finding] = []

    def encrypt_calls(scope: ast.AST):
        for n in ast.walk(scope):
            if not isinstance(n, ast.Call):
                continue
            name = _dotted_name(n.func)
            if name.endswith(".encrypt") or name == "encrypt":
                yield n, name

    def get_nonce(call: ast.Call):
        if call.args:
            return call.args[0]
        for kw in call.keywords:
            if kw.arg == "nonce":
                return kw.value
        return None

    # Names bound to constant-bytes anywhere in the file.
    constant_bound_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_constant_bytes(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    constant_bound_names.add(tgt.id)

    # (a) + (b)
    for node, name in encrypt_calls(tree):
        nonce = get_nonce(node)
        if nonce is None:
            continue
        if _is_constant_bytes(nonce):
            findings.append(_finding(
                "key_and_nonce_reuse",
                node.lineno,
                f"{name}(nonce=<constant bytes literal>)",
            ))
        elif isinstance(nonce, ast.Name) and nonce.id in constant_bound_names:
            findings.append(_finding(
                "key_and_nonce_reuse",
                node.lineno,
                f"{name}(nonce={nonce.id} bound to constant)",
            ))

    # (c)
    for loop in ast.walk(tree):
        if not isinstance(loop, (ast.For, ast.While)):
            continue
        for call, name in encrypt_calls(loop):
            nonce = get_nonce(call)
            if isinstance(nonce, ast.Name) and not _name_assigned_in(loop, nonce.id):
                findings.append(_finding(
                    "key_and_nonce_reuse",
                    call.lineno,
                    f"{name}(nonce={nonce.id}) reused across loop iterations",
                ))
    return findings


def _is_constant_bytes(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return _is_constant_bytes(node.left) or _is_constant_bytes(node.right)
    return False


def _name_assigned_in(scope: ast.AST, name: str) -> bool:
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return True
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return True
    return False


# ---------- Optional CodeBERT inference ----------

def model_predict(file_path: Path, model_dir: Path) -> dict | None:
    if not model_dir.exists():
        return None
    return _run_model(file_path.read_text(encoding="utf-8"), model_dir)


def model_predict_source(source: str, model_dir: Path) -> dict | None:
    if not model_dir.exists():
        return None
    return _run_model(source, model_dir)


def _run_model(source: str, model_dir: Path) -> dict:
    try:
        import numpy as np
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError:
        return {"error": "transformers/torch not installed; skipping model inference"}

    tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
    model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
    model.eval()
    inputs = tokenizer(source, truncation=True, max_length=512, return_tensors="pt")
    with torch.no_grad():
        logits = model(**inputs).logits
    probs = torch.softmax(logits, dim=-1).squeeze(0).tolist()
    pred_id = int(np.argmax(probs))
    id2label = model.config.id2label
    return {
        "label": id2label[pred_id],
        "scores": {id2label[i]: float(p) for i, p in enumerate(probs)},
    }


# ---------- Reporting ----------

def _max_severity(findings: list[Finding]) -> str:
    if not findings:
        return "none"
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity


def _build_report(file_path, features: dict, model_pred, findings: list[Finding]) -> dict:
    return {
        "file": str(file_path),
        "model": model_pred,
        "findings": [asdict(f) for f in findings],
        "summary": {
            "total_findings": len(findings),
            "max_severity": _max_severity(findings),
            "verdict": "vulnerable" if findings else "clean",
        },
    }


def analyze_source(
    source: str,
    filename: str = "<input>",
    model_dir: Path | None = None,
    use_model: bool = True,
) -> dict:
    """Run the full pipeline (features + rules + optional model) on a string.

    Returns a dict with two top-level keys:
      - "report"   : the JSON-serializable report (same shape as the CLI output)
      - "features" : the AST-level feature dict, useful for the API/UI to show
                     extra context (LOC, imports, randomness flags, ...).

    On parse error, returns {"error": "...", "file": filename}.
    """
    features = extract_features_from_source(source, filename)
    if "error" in features:
        return {"error": features["error"], "file": filename}

    tree = ast.parse(source, filename=filename)

    raw: list[Finding] = []
    raw.extend(detect_weak_randomness(features))
    raw.extend(detect_unchecked_verify(tree))
    raw.extend(detect_wrong_params(tree))
    raw.extend(detect_key_reuse(tree))

    seen, findings = set(), []
    for f in raw:
        key = (f.weakness_type, f.line, f.evidence)
        if key not in seen:
            seen.add(key)
            findings.append(f)

    model_pred = None
    if use_model and model_dir is not None:
        model_pred = model_predict_source(source, model_dir)

    return {
        "report": _build_report(filename, features, model_pred, findings),
        "features": features,
    }


def render_text(report: dict, features: dict) -> str:
    sep = "-" * 70
    lines = [sep, f"PQC Detector report - {report['file']}", sep]

    mp = report["model"]
    if mp is None:
        lines.append("Model prediction : skipped (no fine-tuned model found)")
    elif "error" in mp:
        lines.append(f"Model prediction : skipped ({mp['error']})")
    else:
        scores = ", ".join(f"{k}={v:.3f}" for k, v in mp["scores"].items())
        lines.append(f"Model prediction : {mp['label']}  ({scores})")

    rnd = features["randomness"]
    lines.append(
        f"AST              : {features['loc']} LOC, "
        f"{len(features['imports'])} imports, {len(features['calls'])} calls"
    )
    lines.append(
        f"Randomness flags : uses_random={rnd['uses_random']}, "
        f"uses_os_urandom={rnd['uses_os_urandom']}, "
        f"uses_secrets={rnd['uses_secrets']}"
    )
    lines.append("")

    findings = report["findings"]
    if not findings:
        lines.append("No vulnerabilities detected by static rules.")
    else:
        lines.append(f"Findings: {len(findings)}")
        lines.append("")
        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] {f['severity'].upper()} - {f['title']}")
            lines.append(f"    weakness_type : {f['weakness_type']}")
            if f["line"]:
                lines.append(f"    location      : line {f['line']}")
            lines.append(f"    evidence      : {f['evidence']}")
            lines.append(f"    suggestion    : {f['suggestion']}")
            lines.append("")

    lines.append(sep)
    summary = report["summary"]
    lines.append(
        f"Verdict: {summary['verdict'].upper()} "
        f"(highest severity: {summary['max_severity']})"
    )
    lines.append(sep)
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="PQC Detector CLI.")
    ap.add_argument("file", type=Path, help="Python file to analyze")
    ap.add_argument("--model-dir", type=Path, default=Path("runs/codebert/final"),
                    help="directory with the fine-tuned CodeBERT model")
    ap.add_argument("--json", action="store_true", help="emit JSON report on stdout")
    ap.add_argument("--save", type=Path, help="save the JSON report to this path")
    args = ap.parse_args()

    if not args.file.exists():
        print(f"error: {args.file} not found", file=sys.stderr)
        return 2
    if args.file.suffix != ".py":
        print(f"error: {args.file} is not a .py file", file=sys.stderr)
        return 2

    source = args.file.read_text(encoding="utf-8")
    result = analyze_source(source, filename=str(args.file), model_dir=args.model_dir)
    if "error" in result:
        print(f"error parsing {args.file}: {result['error']}", file=sys.stderr)
        return 2

    report = result["report"]
    features = result["features"]

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report, features))

    if args.save:
        args.save.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nreport saved to {args.save}")

    return 0 if not report["findings"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
