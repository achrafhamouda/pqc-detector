"""
Fine-tune CodeBERT to classify Python source files as vulnerable or clean
based on the pqc_detector dataset.

Pipeline:
  1. Walk dataset/{vulnerable,clean}/*.py and read each file's annotation JSON.
  2. Build a HuggingFace Dataset with `code` and `label` columns
     (label: 0 = clean, 1 = vulnerable).
  3. Tokenize with the CodeBERT tokenizer.
  4. Stratified train/eval split.
  5. Fine-tune microsoft/codebert-base via the Trainer API.
  6. Report accuracy / precision / recall / F1 on the eval split.

Usage:
    python model.py                       # train + evaluate
    python model.py --epochs 5 --batch-size 4
    python model.py --predict path/to/file.py   # use the trained model

Note on data size:
    The shipped dataset has only 6 files, which is far below what is needed
    to actually fine-tune a 125M-parameter model. The script runs end-to-end
    so the pipeline is wired correctly, but expect the metrics to be noisy
    until the dataset is grown to hundreds of examples per class.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import torch
from datasets import Dataset
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

MODEL_NAME = "microsoft/codebert-base"
LABEL2ID = {"clean": 0, "vulnerable": 1}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}


@dataclass
class Example:
    file: str
    code: str
    label: int
    algorithm: str
    weakness_type: str
    severity: str


def load_dataset(dataset_dir: Path) -> list[Example]:
    """Read every .py file under dataset_dir and pair it with its sibling .json."""
    examples: list[Example] = []
    for py_path in sorted(dataset_dir.rglob("*.py")):
        ann_path = py_path.with_suffix(".json")
        if not ann_path.exists():
            print(f"[skip] no annotation for {py_path}")
            continue
        ann = json.loads(ann_path.read_text(encoding="utf-8"))
        label_str = ann.get("label", "").lower()
        if label_str not in LABEL2ID:
            print(f"[skip] unknown label '{label_str}' in {ann_path}")
            continue
        examples.append(
            Example(
                file=str(py_path),
                code=py_path.read_text(encoding="utf-8"),
                label=LABEL2ID[label_str],
                algorithm=ann.get("algorithm", ""),
                weakness_type=ann.get("weakness_type", "none"),
                severity=ann.get("severity", "none"),
            )
        )
    return examples


def stratified_split(examples: list[Example], eval_ratio: float, seed: int = 42):
    """Stratified split that keeps at least one example per class in each side
    when the dataset is tiny."""
    rng = np.random.default_rng(seed)
    by_label: dict[int, list[Example]] = {}
    for ex in examples:
        by_label.setdefault(ex.label, []).append(ex)

    train, eval_ = [], []
    for label, group in by_label.items():
        idx = np.arange(len(group))
        rng.shuffle(idx)
        n_eval = max(1, int(round(len(group) * eval_ratio))) if len(group) > 1 else 0
        eval_ids = set(idx[:n_eval].tolist())
        for i, ex in enumerate(group):
            (eval_ if i in eval_ids else train).append(ex)
    rng.shuffle(train)
    rng.shuffle(eval_)
    return train, eval_


def to_hf_dataset(examples: list[Example]) -> Dataset:
    return Dataset.from_dict({
        "code": [ex.code for ex in examples],
        "label": [ex.label for ex in examples],
        "file": [ex.file for ex in examples],
    })


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", pos_label=LABEL2ID["vulnerable"], zero_division=0,
    )
    return {
        "accuracy": accuracy_score(labels, preds),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def train(args: argparse.Namespace) -> None:
    dataset_dir = Path(args.dataset)
    examples = load_dataset(dataset_dir)
    if not examples:
        raise SystemExit(f"no labeled examples found under {dataset_dir}")

    counts = {ID2LABEL[i]: sum(1 for e in examples if e.label == i) for i in (0, 1)}
    print(f"loaded {len(examples)} examples: {counts}")

    train_ex, eval_ex = stratified_split(examples, args.eval_ratio, seed=args.seed)
    print(f"split → train={len(train_ex)} eval={len(eval_ex)}")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def tokenize(batch):
        return tokenizer(
            batch["code"],
            truncation=True,
            max_length=args.max_length,
            padding=False,
        )

    train_ds = to_hf_dataset(train_ex).map(tokenize, batched=True, remove_columns=["code", "file"])
    eval_ds = to_hf_dataset(eval_ex).map(tokenize, batched=True, remove_columns=["code", "file"])

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=len(LABEL2ID),
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    output_dir = Path(args.output_dir)
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        weight_decay=0.01,
        warmup_ratio=0.1,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=1,
        report_to="none",
        seed=args.seed,
    )

    collator = DataCollatorWithPadding(tokenizer=tokenizer)
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        tokenizer=tokenizer,
        data_collator=collator,
        compute_metrics=compute_metrics,
    )

    trainer.train()
    metrics = trainer.evaluate()
    print("\n=== Final evaluation ===")
    for k in ("eval_accuracy", "eval_precision", "eval_recall", "eval_f1", "eval_loss"):
        if k in metrics:
            print(f"{k:>16}: {metrics[k]:.4f}")

    save_dir = output_dir / "final"
    trainer.save_model(str(save_dir))
    tokenizer.save_pretrained(str(save_dir))
    (save_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"\nmodel + tokenizer saved to {save_dir}")


def predict(args: argparse.Namespace) -> None:
    model_dir = Path(args.model_dir)
    target = Path(args.predict)
    if not model_dir.exists():
        raise SystemExit(f"model dir {model_dir} not found — train first")
    if not target.exists():
        raise SystemExit(f"file {target} not found")

    tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
    model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
    model.eval()

    code = target.read_text(encoding="utf-8")
    inputs = tokenizer(code, truncation=True, max_length=args.max_length, return_tensors="pt")
    with torch.no_grad():
        logits = model(**inputs).logits
    probs = torch.softmax(logits, dim=-1).squeeze(0).tolist()
    pred_id = int(np.argmax(probs))
    print(json.dumps({
        "file": str(target),
        "prediction": ID2LABEL[pred_id],
        "scores": {ID2LABEL[i]: float(p) for i, p in enumerate(probs)},
    }, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description="Fine-tune CodeBERT on the pqc_detector dataset.")
    ap.add_argument("--dataset", default="dataset", help="path to dataset directory")
    ap.add_argument("--output-dir", default="runs/codebert", help="where checkpoints go")
    ap.add_argument("--model-dir", default="runs/codebert/final", help="trained model for --predict")
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch-size", type=int, default=2)
    ap.add_argument("--learning-rate", type=float, default=2e-5)
    ap.add_argument("--max-length", type=int, default=512)
    ap.add_argument("--eval-ratio", type=float, default=0.34)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--predict", help="run inference on a single .py file using --model-dir")
    args = ap.parse_args()

    if args.predict:
        predict(args)
    else:
        train(args)


if __name__ == "__main__":
    main()
