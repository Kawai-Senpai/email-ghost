"""Fine-tune an actual binary content classifier from authorized email corpora."""
import hashlib
import json
from datetime import datetime
from pathlib import Path


def load_split(filename):
    records = []
    for line_number, line in enumerate(Path(filename).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("label") not in ("ham", "spam") or not item.get("campaign_id") or not item.get("text"):
            raise ValueError(f"{filename}:{line_number}: require text, label (ham/spam), campaign_id, and timestamp")
        timestamp = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("Training timestamps must include a timezone")
        content = str(item.get("subject", "")) + "\n" + item["text"]
        records.append({"content": content, "label": 1 if item["label"] == "spam" else 0,
                        "campaign_id": item["campaign_id"], "timestamp": timestamp,
                        "digest": hashlib.sha256(" ".join(content.lower().split()).encode()).hexdigest()})
    if not records or {r["label"] for r in records} != {0, 1}:
        raise ValueError("Each split needs both ham and spam examples")
    if len({r["digest"] for r in records}) != len(records):
        raise ValueError("Duplicate normalized messages within split; deduplicate before training")
    return records


def validate_splits(train, validation, allow_small=False):
    if {r["campaign_id"] for r in train} & {r["campaign_id"] for r in validation}:
        raise ValueError("Campaign leakage between training and validation splits")
    if {r["digest"] for r in train} & {r["digest"] for r in validation}:
        raise ValueError("Duplicate content leakage between splits")
    if max(r["timestamp"] for r in train) >= min(r["timestamp"] for r in validation):
        raise ValueError("Validation must occur strictly after training in time")
    if not allow_small and (len(train) < 100 or len(validation) < 100):
        raise ValueError("At least 100 records per split required; --allow-small-dataset is for pipeline debugging only")


def train_model(args):
    train, validation = load_split(args.train_file), load_split(args.validation_file)
    validate_splits(train, validation, args.allow_small_dataset)
    # Keep heavy optional dependencies out of the core API and dataset validation.
    import numpy as np
    import torch
    from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, precision_score, recall_score, roc_auc_score
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, num_labels=2,
                    id2label={0: "ham", 1: "spam"}, label2id={"ham": 0, "spam": 1}, trust_remote_code=False)

    class Messages(torch.utils.data.Dataset):
        def __init__(self, items):
            self.items = items

        def __len__(self):
            return len(self.items)

        def __getitem__(self, index):
            item = self.items[index]
            encoded = tokenizer(item["content"], truncation=True, max_length=args.max_length, padding="max_length")
            encoded["labels"] = item["label"]
            return encoded

    def metrics(prediction):
        probabilities = np.asarray(prediction.predictions)
        labels = np.asarray(prediction.label_ids)
        predicted = probabilities >= .5
        tn, fp, fn, tp = confusion_matrix(labels, predicted, labels=[0, 1]).ravel()
        return {"precision": float(precision_score(labels, predicted, zero_division=0)),
                "recall": float(recall_score(labels, predicted, zero_division=0)),
                "false_positive_rate": float(fp / (fp + tn)), "false_negative_rate": float(fn / (fn + tp)),
                "pr_auc": float(average_precision_score(labels, probabilities)),
                "roc_auc": float(roc_auc_score(labels, probabilities)),
                "brier_score": float(brier_score_loss(labels, probabilities))}

    def logits_for_metrics(logits, labels):
        if isinstance(logits, tuple):
            logits = logits[0]
        return torch.softmax(logits.float(), dim=-1)[:, 1]

    training_args = TrainingArguments(output_dir=args.output, num_train_epochs=args.epochs,
        per_device_train_batch_size=1, per_device_eval_batch_size=1, gradient_accumulation_steps=8,
        learning_rate=2e-5, eval_strategy="epoch", save_strategy="epoch", save_total_limit=1,
        use_cpu=args.cpu, seed=42, data_seed=42, report_to=[], logging_steps=10)
    trainer = Trainer(model=model, args=training_args, train_dataset=Messages(train), eval_dataset=Messages(validation),
                      compute_metrics=metrics, preprocess_logits_for_metrics=logits_for_metrics)
    trainer.train()
    measured = trainer.evaluate()
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)
    report = {"base_model": args.base_model, "train_count": len(train), "validation_count": len(validation),
              "train_file_sha256": hashlib.sha256(Path(args.train_file).read_bytes()).hexdigest(),
              "validation_file_sha256": hashlib.sha256(Path(args.validation_file).read_bytes()).hexdigest(),
              "max_length": args.max_length, "metrics": measured, "calibrated": False,
              "gmail_prediction_available": False, "pipeline_debug_only": args.allow_small_dataset,
              "limitations": ["Validation is not an independent final test", "No Gmail placement calibration", "Sender and campaign generalization require independent testing"]}
    Path(args.output, "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
