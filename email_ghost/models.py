import asyncio
import importlib.util
import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .engines import ContentModel


class ModelSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    path: str = Field(min_length=1)
    spam_label: str = "spam"
    device: str = Field("cpu", pattern=r"^(cpu|auto|mps|cuda(?::[0-9]+)?)$")
    dtype: Literal["auto", "float32", "float16", "bfloat16"] = "float32"
    max_length: int = Field(4096, ge=128, le=8192)
    threshold: float = Field(.5, ge=0, le=1)
    keep_loaded: bool = False


class RegistryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    models: list[ModelSpec] = Field(max_length=8)


def consensus(reports):
    available = [r for r in reports if r.get("available")]
    spam = sum(r["verdict"] == "spam" for r in available)
    ham = len(available) - spam
    return {"available_models": len(available), "unavailable_models": len(reports) - len(available),
            "spam_votes": spam, "ham_votes": ham, "disagreement": spam > 0 and ham > 0,
            "verdict": "unavailable" if not available else "disagreement" if spam and ham else "spam" if spam else "ham",
            "calibrated": False, "method": "independent_model_votes", "gmail_probability": None}


class ModelRegistry:
    def __init__(self, config_path=None):
        self.error = None
        self.specs = []
        self.lock = asyncio.Lock()
        filename = config_path if config_path is not None else os.getenv("GHOST_MODELS_FILE", "")
        try:
            if filename:
                self.specs = RegistryConfig.model_validate(json.loads(Path(filename).read_text(encoding="utf-8"))).models
            elif os.getenv("GHOST_MODEL_PATH"):
                self.specs = [ModelSpec(id="content-default", path=os.environ["GHOST_MODEL_PATH"],
                    spam_label=os.getenv("GHOST_SPAM_LABEL", "spam"), device=os.getenv("GHOST_MODEL_DEVICE", "cpu"))]
            ids = [spec.id for spec in self.specs]
            if len(set(ids)) != len(ids):
                raise ValueError("Model IDs must be unique")
        except (OSError, ValueError) as exc:
            self.error = str(exc)
            self.specs = []
        self.models = {spec.id: ContentModel(spec) for spec in self.specs}

    @property
    def configured(self):
        return bool(self.specs)

    def describe(self):
        return {"configured": self.configured, "configuration_error": self.error,
                "scheduling": "sequential_across_models_and_requests", "models": [
                    spec.model_dump(exclude={"path"}) for spec in self.specs]}

    async def predict(self, text, explain=False, model_ids=None):
        wanted = list(dict.fromkeys(self.models if model_ids is None else model_ids))
        if any(ident not in self.models for ident in wanted):
            raise ValueError("Unknown model ID; discover /v1/models first")
        reports = []
        # Avoid overlapping large models on a small GPU, including across requests.
        async with self.lock:
            for ident in wanted:
                engine = self.models[ident]
                report = await engine.predict(text, explain)
                report.update(id=ident, threshold=engine.spec.threshold,
                              configured_device=engine.spec.device, dtype=engine.spec.dtype)
                if report["available"]:
                    report["verdict"] = "spam" if report["probability"] >= engine.spec.threshold else "ham"
                else:
                    report["verdict"] = "unavailable"
                reports.append(report)
        primary = next((r for r in reports if r["available"]), None)
        return {"reports": reports, "consensus": consensus(reports), "configuration_error": self.error,
                "primary": primary or {"available": False, "probability": None,
                    "reason": "model_configuration_error" if self.error else "no_content_models_available"}}


def hardware():
    result = {"cpu_count": os.cpu_count(), "torch_installed": importlib.util.find_spec("torch") is not None,
              "cuda_available": False, "cuda_devices": []}
    if result["torch_installed"]:
        try:
            import torch
            result["cuda_available"] = torch.cuda.is_available()
            for index in range(torch.cuda.device_count()):
                info = torch.cuda.get_device_properties(index)
                result["cuda_devices"].append({"id": index, "name": info.name, "total_memory_bytes": info.total_memory})
        except Exception as exc:
            result["error"] = str(exc)
    return result
