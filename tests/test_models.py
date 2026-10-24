import asyncio
import json

from email_ghost.models import ModelRegistry, ModelSpec, consensus


def test_independent_reports_preserve_disagreement_and_failures(tmp_path, monkeypatch):
    from email_ghost import models
    path = tmp_path / "models.json"
    path.write_text(json.dumps({"models": [{"id": name, "path": str(tmp_path / name)} for name in ("a", "b", "broken")]}))

    async def predict(self, text, explain=False):
        if self.spec.id == "broken":
            return {"available": False, "probability": None, "reason": "missing_weights"}
        return {"available": True, "probability": .9 if self.spec.id == "a" else .1}

    monkeypatch.setattr(models.ContentModel, "predict", predict)
    registry = ModelRegistry(path)
    result = asyncio.run(registry.predict("some message"))
    assert len(result["reports"]) == 3
    assert result["consensus"]["disagreement"]
    assert result["consensus"]["unavailable_models"] == 1
    assert result["primary"]["id"] == "a"
    assert result["consensus"]["gmail_probability"] is None


def test_registry_errors_are_explicit(tmp_path):
    path = tmp_path / "models.json"
    path.write_text('{"models":[{"id":"same","path":"one"},{"id":"same","path":"two"}]}')
    registry = ModelRegistry(path)
    assert "unique" in registry.error
    result = asyncio.run(registry.predict("text"))
    assert not result["primary"]["available"]
    assert result["primary"]["reason"] == "model_configuration_error"


def test_required_models_and_calibration_fail_closed(client):
    ident = client.post("/v1/compose", json={"text": "A message"}).json()["id"]
    for expected in ({"required_models": ["not-installed"]}, {"max_spam_probability": .1}, {"max_gmail_probability": .1}):
        result = client.post(f"/v1/messages/{ident}/assert", json=expected).json()
        assert not result["passed"]


def test_model_defaults_bound_memory_and_allow_gpu():
    spec = ModelSpec(id="model", path="weights", device="cuda:0", dtype="float16")
    assert not spec.keep_loaded
    assert spec.device == "cuda:0"
