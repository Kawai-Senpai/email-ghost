"""Optional measured probability estimates, loaded from transparent JSON artifacts."""
import hashlib
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .engines import scanner_has_result


def sigmoid(value):
    return 1 / (1 + math.exp(-max(-700, min(700, value))))


def feature_values(report):
    values, fingerprints = {}, {}
    scanner = report.get("rspamd", {})
    if scanner_has_result(scanner):
        values["rspamd_score"] = float(scanner["score"])
        fingerprints["rspamd_score"] = scanner.get("revision", "unknown")
    for model in report.get("content_models", []):
        if model.get("available"):
            name = "content:" + model["id"]
            probability = max(1e-6, min(1 - 1e-6, float(model["probability"])))
            values[name] = math.log(probability / (1 - probability))
            fingerprints[name] = model.get("model_fingerprint", "unknown")
    return values, fingerprints


class Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    schema_version: Literal[1] = 1
    artifact_id: str
    task: Literal["local_spam", "gmail_placement"]
    created_at: str
    feature_names: list[str] = Field(min_length=1, max_length=9)
    fingerprints: dict[str, str]
    coefficients: list[float]
    intercept: float
    calibration_coefficient: float
    calibration_intercept: float
    sender_domains: list[str]
    evaluation: dict[str, float]
    training_counts: dict[str, int]
    validated: bool
    source_hashes: dict[str, str]

    @model_validator(mode="after")
    def validate_contract(self):
        if len(self.feature_names) != len(self.coefficients) or len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("Feature names and coefficients must match uniquely")
        if set(self.feature_names) != set(self.fingerprints) or "unknown" in self.fingerprints.values():
            raise ValueError("Every calibration feature needs a known version fingerprint")
        if self.task == "gmail_placement" and not self.sender_domains:
            raise ValueError("Gmail prediction needs an explicit sending-domain scope")
        return self


def estimate(report, task, path, sender_domain):
    if not path:
        return {"available": False, "probability": None, "reason": "calibration_not_configured"}
    try:
        artifact = Artifact.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"available": False, "probability": None, "reason": "invalid_calibration_artifact", "error": str(exc)}
    if artifact.task != task or not artifact.validated or any(artifact.training_counts.get(split, 0) < 100 for split in ("train", "calibration", "test")):
        return {"available": False, "probability": None, "reason": "calibration_not_validated"}
    try:
        age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(artifact.created_at.replace("Z", "+00:00"))).total_seconds() / 86400
        if age_days < 0 or age_days > float(os.getenv("GHOST_CALIBRATION_MAX_AGE_DAYS", "90")):
            return {"available": False, "probability": None, "reason": "calibration_expired"}
    except (ValueError, TypeError):
        return {"available": False, "probability": None, "reason": "invalid_calibration_timestamp"}
    if artifact.sender_domains and sender_domain.lower() not in artifact.sender_domains:
        return {"available": False, "probability": None, "reason": "sender_outside_calibration_scope"}
    values, fingerprints = feature_values(report)
    missing = [name for name in artifact.feature_names if name not in values]
    if missing:
        return {"available": False, "probability": None, "reason": "missing_calibration_features", "missing_features": missing}
    if any(fingerprints[name] != artifact.fingerprints[name] for name in artifact.feature_names):
        return {"available": False, "probability": None, "reason": "model_or_scanner_version_changed"}
    linear = artifact.intercept + sum(coefficient * values[name] for name, coefficient in zip(artifact.feature_names, artifact.coefficients))
    probability = sigmoid(artifact.calibration_coefficient * linear + artifact.calibration_intercept)
    return {"available": True, "probability": probability, "artifact_id": artifact.artifact_id,
            "task": task, "calibrated": True, "sender_domains": artifact.sender_domains,
            "evaluation": artifact.evaluation, "training_counts": artifact.training_counts,
            "method": "logistic_meta_classifier_with_heldout_platt_calibration",
            "limitations": ["Estimate is valid only within its measured dataset and sender scope", "Drift and recipient-specific behavior can change outcomes"]}


def describe_calibration(path, task):
    if not path:
        return {"configured": False, "validated": False}
    try:
        artifact = Artifact.model_validate_json(Path(path).read_text(encoding="utf-8"))
        return {"configured": True, "validated": artifact.validated and artifact.task == task,
                "artifact_id": artifact.artifact_id, "sender_domains": artifact.sender_domains,
                "per_message_checks_required": True}
    except (OSError, ValueError):
        return {"configured": True, "validated": False, "reason": "invalid_calibration_artifact"}


def read_examples(filename, task):
    import re
    examples = []
    for line in Path(filename).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("label") not in ("spam", "ham", "inbox") or not item.get("source"):
            raise ValueError("Calibration records need label and observed-label source")
        if task == "gmail_placement" and item.get("provider") != "gmail":
            raise ValueError("Gmail calibration requires actual Gmail-labeled records")
        if not re.fullmatch(r"[0-9a-f]{64}", item.get("message_digest", "")):
            raise ValueError("Each record needs the captured message SHA-256 as message_digest")
        timestamp = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or not item.get("campaign_id"):
            raise ValueError("Calibration requires timezone-aware timestamps and campaign IDs")
        values, fingerprints = feature_values(item["report"])
        examples.append({"label": int(item["label"] == "spam"), "values": values, "fingerprints": fingerprints,
                         "digest": item["message_digest"], "timestamp": timestamp, "campaign_id": item["campaign_id"],
                         "sender_domain": item.get("sender_domain", "").lower()})
    if not examples or {e["label"] for e in examples} != {0, 1}:
        raise ValueError("Each split needs spam and legitimate observations")
    if len({e["digest"] for e in examples}) != len(examples):
        raise ValueError("Deduplicate messages within each calibration split")
    return examples


def fit(args):
    from .training import validate_splits
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import brier_score_loss, confusion_matrix, precision_score, recall_score, roc_auc_score
    import numpy as np
    splits = {name: read_examples(getattr(args, name + "_file"), args.task) for name in ("train", "calibration", "test")}
    validate_splits(splits["train"], splits["calibration"], args.allow_small_dataset)
    validate_splits(splits["calibration"], splits["test"], args.allow_small_dataset)
    # Adjacent checks are insufficient for a reused campaign in first and last splits.
    if {e["digest"] for e in splits["train"]} & {e["digest"] for e in splits["test"]} or {e["campaign_id"] for e in splits["train"]} & {e["campaign_id"] for e in splits["test"]}:
        raise ValueError("Training/test campaign or duplicate leakage")
    names = args.features.split(",")
    domains = sorted(set(d.strip().lower() for d in args.sender_domains.split(",") if d.strip()))
    if args.task == "gmail_placement" and not domains:
        raise ValueError("Use --sender-domains to bound Gmail prediction scope")
    fingerprints = {name: splits["train"][0]["fingerprints"].get(name, "unknown") for name in names}
    arrays = {}
    for split, records in splits.items():
        for record in records:
            if domains and record["sender_domain"] not in domains:
                raise ValueError("Dataset contains sending domains outside the requested scope")
            if any(name not in record["values"] or record["fingerprints"].get(name) != fingerprints[name] or fingerprints[name] == "unknown" for name in names):
                raise ValueError("All rows must have every selected feature from the same model/scanner versions")
        arrays[split] = (np.asarray([[row["values"][name] for name in names] for row in records]), np.asarray([row["label"] for row in records]))
    meta = LogisticRegression(max_iter=2000).fit(*arrays["train"])
    calibration_x, calibration_y = arrays["calibration"]
    platt = LogisticRegression(max_iter=2000).fit(meta.decision_function(calibration_x).reshape(-1, 1), calibration_y)
    test_x, test_y = arrays["test"]
    probabilities = platt.predict_proba(meta.decision_function(test_x).reshape(-1, 1))[:, 1]
    predicted = probabilities >= .5
    tn, fp, fn, tp = confusion_matrix(test_y, predicted, labels=[0, 1]).ravel()
    prevalence = float(np.mean(arrays["train"][1]))
    evaluation = {"brier_score": float(brier_score_loss(test_y, probabilities)),
                  "baseline_brier_score": float(brier_score_loss(test_y, np.full(len(test_y), prevalence))),
                  "roc_auc": float(roc_auc_score(test_y, probabilities)),
                  "false_positive_rate": float(fp / (fp + tn)), "false_negative_rate": float(fn / (fn + tp)),
                  "precision": float(precision_score(test_y, predicted, zero_division=0)),
                  "recall": float(recall_score(test_y, predicted, zero_division=0)), "test_count": float(len(test_y))}
    accepted = (not args.allow_small_dataset and evaluation["brier_score"] < evaluation["baseline_brier_score"]
                and evaluation["roc_auc"] > .5 and evaluation["false_positive_rate"] <= args.max_false_positive_rate)
    hashes = {name: hashlib.sha256(Path(getattr(args, name + "_file")).read_bytes()).hexdigest() for name in splits}
    identity = {"source_hashes": hashes, "task": args.task, "features": names, "fingerprints": fingerprints,
                "sender_domains": domains, "coefficients": meta.coef_[0].tolist(), "intercept": float(meta.intercept_[0]),
                "calibration_coefficient": float(platt.coef_[0][0]), "calibration_intercept": float(platt.intercept_[0]),
                "max_false_positive_rate": args.max_false_positive_rate, "validated": accepted}
    artifact = Artifact(artifact_id=hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24], task=args.task,
        created_at=datetime.now(timezone.utc).isoformat(), feature_names=names, fingerprints=fingerprints,
        coefficients=meta.coef_[0].tolist(), intercept=float(meta.intercept_[0]),
        calibration_coefficient=float(platt.coef_[0][0]), calibration_intercept=float(platt.intercept_[0]),
        sender_domains=domains, evaluation=evaluation, training_counts={key: len(value) for key, value in splits.items()},
        validated=accepted, source_hashes=hashes)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    print(json.dumps({"artifact": str(output), "validated": accepted, "evaluation": evaluation}, indent=2))
    return accepted
