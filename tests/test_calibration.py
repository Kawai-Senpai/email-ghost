import json
from datetime import datetime, timezone

from email_ghost.calibration import Artifact, estimate


def artifact(task="local_spam"):
    return Artifact(artifact_id="measured-test-artifact", task=task, created_at=datetime.now(timezone.utc).isoformat(),
        feature_names=["rspamd_score"], fingerprints={"rspamd_score": "test-v1"}, coefficients=[1.0], intercept=0,
        calibration_coefficient=1, calibration_intercept=0, sender_domains=["example.test"] if task == "gmail_placement" else [],
        evaluation={"brier_score": .1, "false_positive_rate": .02}, training_counts={"train": 100, "calibration": 100, "test": 100},
        validated=True, source_hashes={})


def test_optional_probability_requires_scope_features_and_versions(tmp_path):
    path = tmp_path / "gmail.json"
    path.write_text(artifact("gmail_placement").model_dump_json())
    report = {"rspamd": {"available": True, "score": 2, "revision": "test-v1"}}
    result = estimate(report, "gmail_placement", path, "example.test")
    assert result["available"] and .88 < result["probability"] < .89
    assert estimate(report, "gmail_placement", path, "other.test")["reason"] == "sender_outside_calibration_scope"
    report["rspamd"]["revision"] = "changed"
    assert estimate(report, "gmail_placement", path, "example.test")["reason"] == "model_or_scanner_version_changed"
    assert not estimate({}, "gmail_placement", path, "example.test")["available"]


def test_debug_or_unvalidated_artifacts_cannot_enable_percentages(tmp_path):
    data = artifact()
    data.validated = False
    path = tmp_path / "debug.json"
    path.write_text(data.model_dump_json())
    assert estimate({}, "local_spam", path, "example.test")["reason"] == "calibration_not_validated"


def test_audit_api_can_return_optional_calibrated_percentages(client, tmp_path, monkeypatch):
    import email_ghost.app as application
    async def scan(raw, envelope):
        return {"available": True, "score": 2, "revision": "test-v1", "symbols": {}}
    monkeypatch.setattr(application, "scan_rspamd", scan)
    for task, variable in (("local_spam", "GHOST_LOCAL_CALIBRATION_FILE"), ("gmail_placement", "GHOST_GMAIL_CALIBRATION_FILE")):
        data = artifact(task)
        data.fingerprints["rspamd_score"] = "test-v1:bayes-" + application.store.learning_revision()
        path = tmp_path / (task + ".json")
        path.write_text(data.model_dump_json())
        monkeypatch.setenv(variable, str(path))
    ident = client.post("/v1/compose", json={"sender": "sender@example.test", "text": "Test"}).json()["id"]
    report = client.post(f"/v1/messages/{ident}/audit", json={}).json()
    assert report["gmail_prediction_available"]
    assert .88 < report["gmail_spam_probability"] < .89
    assert .88 < report["spam_risk_probability"] < .89
    assert report["local_calibration"]["artifact_id"]
    assert not client.post(f"/v1/messages/{ident}/assert", json={"max_gmail_probability": .5}).json()["passed"]


def test_export_uses_saved_audit_before_observed_feedback(client):
    from email_ghost.app import store
    ident = client.post("/v1/compose", json={"run_id": "campaign-a", "text": "Message"}).json()["id"]
    client.post(f"/v1/messages/{ident}/audit", json={})
    client.post(f"/v1/messages/{ident}/feedback", json={"provider": "gmail", "label": "inbox", "source": "owned Gmail seed account"})
    records = client.get("/v1/calibration/examples?provider=gmail").json()["records"]
    record = next(r for r in records if r["campaign_id"] == "campaign-a")
    assert record["message_digest"] == store.get(ident)["digest"]
    assert record["provider"] == "gmail" and record["label"] == "inbox"
    assert record["report"]["message_id"] == ident


def test_real_calibration_fit_mechanics_on_synthetic_data(tmp_path):
    import hashlib
    from types import SimpleNamespace
    import pytest
    pytest.importorskip("sklearn")
    from email_ghost.calibration import fit
    files = {}
    for month, split in enumerate(("train", "calibration", "test"), 1):
        records = []
        for index in range(100):
            spam = index % 2 == 1
            records.append({"label": "spam" if spam else "inbox", "provider": "gmail", "source": "SYNTHETIC TEST ONLY",
                "message_digest": hashlib.sha256(f"{split}-{index}".encode()).hexdigest(),
                "timestamp": f"2026-{month:02d}-01T00:00:00Z", "campaign_id": f"{split}-{index}",
                "sender_domain": "example.test", "report": {"rspamd": {"available": True,
                    "score": (8 if spam else -2) + index / 1000, "revision": "test-v1"}}})
        path = tmp_path / (split + ".jsonl")
        path.write_text("\n".join(json.dumps(record) for record in records))
        files[split + "_file"] = str(path)
    output = tmp_path / "calibration.json"
    assert fit(SimpleNamespace(**files, task="gmail_placement", features="rspamd_score", sender_domains="example.test",
              output=str(output), max_false_positive_rate=.1, allow_small_dataset=False))
    result = estimate({"rspamd": {"available": True, "score": 8, "revision": "test-v1"}}, "gmail_placement", output, "example.test")
    assert result["available"] and result["probability"] > .9
