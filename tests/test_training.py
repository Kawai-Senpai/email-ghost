import json

import pytest

from email_ghost.training import load_split, validate_splits


def write_split(path, prefix, date):
    path.write_text("\n".join(json.dumps({"label": label, "subject": prefix + label, "text": prefix + " message " + label,
        "campaign_id": prefix + label, "timestamp": date}) for label in ("ham", "spam")), encoding="utf-8")
    return load_split(path)


def test_corpus_splits_guard_against_leakage(tmp_path):
    train = write_split(tmp_path / "train.jsonl", "train-", "2026-01-01T00:00:00Z")
    validation = write_split(tmp_path / "validation.jsonl", "validation-", "2026-02-01T00:00:00Z")
    validate_splits(train, validation, allow_small=True)
    with pytest.raises(ValueError, match="100 records"):
        validate_splits(train, validation)
    validation[0]["campaign_id"] = train[0]["campaign_id"]
    with pytest.raises(ValueError, match="Campaign leakage"):
        validate_splits(train, validation, allow_small=True)


def test_chronology_is_required(tmp_path):
    train = write_split(tmp_path / "train.jsonl", "train-", "2026-03-01T00:00:00Z")
    validation = write_split(tmp_path / "validation.jsonl", "validation-", "2026-02-01T00:00:00Z")
    with pytest.raises(ValueError, match="strictly after"):
        validate_splits(train, validation, allow_small=True)
