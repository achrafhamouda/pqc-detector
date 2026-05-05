"""
End-to-end test for the PQC detector.

Runs the full detection pipeline (parser + rule-based detectors) on every
file under dataset/, compares the result against the sibling JSON annotation,
and prints a summary report.

Two metrics are reported:
  - Verdict accuracy: did the tool classify the file as vulnerable vs clean
    correctly? (binary)
  - Weakness-type detection rate: for files annotated as vulnerable, did the
    tool detect the *specific* weakness_type listed in the annotation?

Exit code: 0 if every file is correctly classified AND every vulnerable file
has its weakness_type detected, otherwise 1. Useful as a regression gate.

Usage:
    python test.py
    python test.py --dataset dataset
    python test.py --json
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from cli import (  # noqa: E402
    detect_key_reuse,
    detect_unchecked_verify,
    detect_weak_randomness,
    detect_wrong_params,
    Finding,
)
from parser import extract_features  # noqa: E402


@dataclass
class CaseResult:
    file: str
    expected_label: str
    expected_weakness: str
    predicted_label: str
    detected_weaknesses: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    verdict_correct: bool = False
    weakness_correct: bool | None = None  # None for clean files


def run_pipeline(py_path: Path) -> list[Finding]:
    features = extract_features(py_path)
    if "error" in features:
        return []
    tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
    found: list[Finding] = []
    found.extend(detect_weak_randomness(features))
    found.extend(detect_unchecked_verify(tree))
    found.extend(detect_wrong_params(tree))
    found.extend(detect_key_reuse(tree))
    seen, dedup = set(), []
    for f in found:
        key = (f.weakness_type, f.line, f.evidence)
        if key not in seen:
            seen.add(key)
            dedup.append(f)
    return dedup


def evaluate_case(py_path: Path, ann: dict) -> CaseResult:
    expected_label = ann.get("label", "").lower()
    expected_weakness = ann.get("weakness_type", "none")

    findings = run_pipeline(py_path)
    detected_weaknesses = sorted({f.weakness_type for f in findings})
    predicted_label = "vulnerable" if findings else "clean"

    verdict_correct = predicted_label == expected_label
    if expected_label == "vulnerable":
        weakness_correct = expected_weakness in detected_weaknesses
    else:
        weakness_correct = None

    return CaseResult(
        file=str(py_path),
        expected_label=expected_label,
        expected_weakness=expected_weakness,
        predicted_label=predicted_label,
        detected_weaknesses=detected_weaknesses,
        findings=findings,
        verdict_correct=verdict_correct,
        weakness_correct=weakness_correct,
    )


def collect_cases(dataset_dir: Path) -> list[tuple[Path, dict]]:
    cases = []
    for py_path in sorted(dataset_dir.rglob("*.py")):
        ann_path = py_path.with_suffix(".json")
        if not ann_path.exists():
            continue
        ann = json.loads(ann_path.read_text(encoding="utf-8"))
        cases.append((py_path, ann))
    return cases


def _confusion(results: list[CaseResult]) -> dict:
    tp = sum(1 for r in results if r.expected_label == "vulnerable" and r.predicted_label == "vulnerable")
    tn = sum(1 for r in results if r.expected_label == "clean" and r.predicted_label == "clean")
    fp = sum(1 for r in results if r.expected_label == "clean" and r.predicted_label == "vulnerable")
    fn = sum(1 for r in results if r.expected_label == "vulnerable" and r.predicted_label == "clean")
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def _metrics(cm: dict) -> dict:
    tp, tn, fp, fn = cm["tp"], cm["tn"], cm["fp"], cm["fn"]
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}


def render_text(results: list[CaseResult]) -> str:
    sep = "-" * 78
    lines = [sep, f"PQC Detector - end-to-end test on {len(results)} files", sep]

    header = f"{'STATUS':<7}{'FILE':<42}{'EXPECTED':<48}{'DETECTED'}"
    lines.append(header)
    lines.append("-" * 110)
    for r in results:
        verdict_ok = "OK" if r.verdict_correct else "FAIL"
        if r.expected_label == "vulnerable":
            wflag = "+" if r.weakness_correct else "-"
            verdict_ok = f"{verdict_ok}{wflag}"
        expected = f"{r.expected_label}/{r.expected_weakness}"
        detected = (
            f"{r.predicted_label}/{','.join(r.detected_weaknesses) or 'none'}"
        )
        short = Path(r.file).as_posix()
        if len(short) > 41:
            short = "..." + short[-38:]
        lines.append(f"{verdict_ok:<7}{short:<42}{expected:<48}{detected}")
    lines.append("")

    cm = _confusion(results)
    m = _metrics(cm)
    verdict_correct = sum(1 for r in results if r.verdict_correct)
    vuln_cases = [r for r in results if r.expected_label == "vulnerable"]
    weakness_correct = sum(1 for r in vuln_cases if r.weakness_correct)

    lines.append("Confusion matrix (positive = vulnerable):")
    lines.append(f"  TP={cm['tp']}  FP={cm['fp']}")
    lines.append(f"  FN={cm['fn']}  TN={cm['tn']}")
    lines.append("")
    lines.append("Metrics:")
    lines.append(f"  verdict accuracy  : {verdict_correct}/{len(results)} "
                 f"({m['accuracy']*100:.1f}%)")
    lines.append(f"  precision         : {m['precision']*100:.1f}%")
    lines.append(f"  recall            : {m['recall']*100:.1f}%")
    lines.append(f"  f1                : {m['f1']*100:.1f}%")
    if vuln_cases:
        rate = weakness_correct / len(vuln_cases)
        lines.append(f"  weakness-type detection rate : "
                     f"{weakness_correct}/{len(vuln_cases)} ({rate*100:.1f}%)")

    lines.append(sep)
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="End-to-end test for the PQC detector.")
    ap.add_argument("--dataset", type=Path, default=Path("dataset"))
    ap.add_argument("--json", action="store_true", help="emit JSON report on stdout")
    args = ap.parse_args()

    if not args.dataset.exists():
        print(f"error: {args.dataset} not found", file=sys.stderr)
        return 2

    cases = collect_cases(args.dataset)
    if not cases:
        print(f"error: no annotated files under {args.dataset}", file=sys.stderr)
        return 2

    results = [evaluate_case(p, a) for p, a in cases]

    if args.json:
        cm = _confusion(results)
        m = _metrics(cm)
        verdict_correct = sum(1 for r in results if r.verdict_correct)
        vuln_cases = [r for r in results if r.expected_label == "vulnerable"]
        weakness_correct = sum(1 for r in vuln_cases if r.weakness_correct)
        report = {
            "cases": [
                {
                    "file": r.file,
                    "expected_label": r.expected_label,
                    "expected_weakness": r.expected_weakness,
                    "predicted_label": r.predicted_label,
                    "detected_weaknesses": r.detected_weaknesses,
                    "verdict_correct": r.verdict_correct,
                    "weakness_correct": r.weakness_correct,
                }
                for r in results
            ],
            "summary": {
                "total": len(results),
                "verdict_correct": verdict_correct,
                "verdict_accuracy": verdict_correct / len(results),
                "weakness_type_detection_rate": (
                    weakness_correct / len(vuln_cases) if vuln_cases else None
                ),
                "confusion_matrix": cm,
                **m,
            },
        }
        print(json.dumps(report, indent=2))
    else:
        print(render_text(results))

    all_verdicts_ok = all(r.verdict_correct for r in results)
    all_weaknesses_ok = all(
        r.weakness_correct for r in results if r.expected_label == "vulnerable"
    )
    return 0 if all_verdicts_ok and all_weaknesses_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
