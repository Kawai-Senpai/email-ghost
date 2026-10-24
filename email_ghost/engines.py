import asyncio
import hashlib
import os
import re
from pathlib import Path

import httpx


async def scan_rspamd(raw, envelope):
    url = os.getenv("GHOST_RSPAMD_URL", "")
    if not url:
        return {"available": False, "reason": "rspamd_not_configured"}
    headers = {"Content-Type": "message/rfc822", "Flags": "pass_all"}
    for source, dest in (("sender_ip", "IP"), ("mail_from", "From"), ("helo", "Helo")):
        if envelope.get(source):
            headers[dest] = envelope[source]
    try:
        async with httpx.AsyncClient(timeout=25, trust_env=False) as client:
            response = await client.post(url.rstrip("/") + "/checkv2", content=raw, headers=headers)
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict) or not isinstance(result.get("score"), (int, float)):
                raise ValueError("invalid scanner response")
        return {"available": True, "score": result["score"], "required_score": result.get("required_score"),
                "action": result.get("action"), "symbols": result.get("symbols", {}),
                "is_skipped": result.get("is_skipped", False), "passthrough_module": result.get("passthrough_module"),
                "thresholds": result.get("thresholds", {}), "messages": result.get("messages", {}),
                "revision": os.getenv("GHOST_SCANNER_REVISION", "rspamd-default-v1")}
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return {"available": False, "reason": "scanner_failed", "error": str(exc)}


async def learn_rspamd(raw, label):
    url = os.getenv("GHOST_RSPAMD_CONTROLLER_URL", "")
    if not url:
        return {"learned": False, "reason": "rspamd_controller_not_configured"}
    try:
        async with httpx.AsyncClient(timeout=25, trust_env=False) as client:
            response = await client.post(url.rstrip("/") + ("/learnspam" if label == "spam" else "/learnham"),
                                         content=raw, headers={"Content-Type": "message/rfc822", "Password": os.getenv("GHOST_RSPAMD_PASSWORD", "")})
            response.raise_for_status()
            data = response.json()
            return {"learned": data.get("success") is True, "engine": "rspamd", "label": label, "result": data}
    except (httpx.HTTPError, ValueError) as exc:
        return {"learned": False, "reason": "learning_failed", "error": str(exc)}


def scanner_has_result(scan):
    # GTUBE deliberately bypasses other modules while returning a definitive reject.
    return bool(scan.get("available") and (not scan.get("is_skipped") or
        (scan.get("passthrough_module") == "GTUBE" and scan.get("action") == "reject" and "GTUBE" in scan.get("symbols", {}))))


def authentication_from_symbols(scan, sender_ip):
    mappings = {
        "spf": {"R_SPF_ALLOW": "pass", "R_SPF_FAIL": "fail", "R_SPF_SOFTFAIL": "softfail", "R_SPF_NA": "none", "R_SPF_DNSFAIL": "temperror"},
        "dkim": {"R_DKIM_ALLOW": "pass", "R_DKIM_REJECT": "fail", "R_DKIM_NA": "none", "R_DKIM_TEMPFAIL": "temperror", "R_DKIM_PERMFAIL": "permerror"},
        "dmarc": {"DMARC_POLICY_ALLOW": "pass", "DMARC_POLICY_REJECT": "fail", "DMARC_POLICY_QUARANTINE": "fail", "DMARC_POLICY_SOFTFAIL": "fail", "DMARC_NA": "none", "DMARC_DNSFAIL": "temperror"},
    }
    results = {}
    symbols = scan.get("symbols", {}) if scan.get("available") and not scan.get("is_skipped") else {}
    for mechanism, mapping in mappings.items():
        found = [{"symbol": symbol, "status": status, "details": symbols[symbol]} for symbol, status in mapping.items() if symbol in symbols]
        if found and (mechanism != "spf" or sender_ip):
            statuses = {item["status"] for item in found}
            results[mechanism] = {"status": found[0]["status"] if len(statuses) == 1 else "mixed", "source": "rspamd", "evidence": found}
    return results


class ContentModel:
    """Optional locally fine-tuned binary classifier; no downloads at runtime."""
    def __init__(self, spec=None):
        self.spec = spec
        self.path = spec.path if spec else os.getenv("GHOST_MODEL_PATH", "")
        self.pipeline = None
        self.fingerprint = None
        self.lock = asyncio.Lock()

    async def predict(self, text, explain=False):
        if not self.path:
            return {"available": False, "reason": "fine_tuned_model_not_configured", "probability": None}
        async with self.lock:
            try:
                return await asyncio.to_thread(self._run, text, explain)
            except Exception as exc:
                return {"available": False, "reason": "model_failed", "error": str(exc), "probability": None}

    def _run(self, text, explain):
        try:
            return self._predict(text, explain)
        finally:
            if self.spec and not self.spec.keep_loaded:
                self.pipeline = None
                import gc
                gc.collect()
                try:
                    import torch
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                except ImportError:
                    pass

    def _predict(self, text, explain):
        if self.pipeline is None:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
            device = self.spec.device if self.spec else os.getenv("GHOST_MODEL_DEVICE", "cpu")
            if device == "auto":
                device = "cuda:0" if torch.cuda.is_available() else "cpu"
            dtype_name = self.spec.dtype if self.spec else "float32"
            dtype = "auto" if dtype_name == "auto" else getattr(torch, dtype_name)
            model = AutoModelForSequenceClassification.from_pretrained(self.path, local_files_only=True,
                                                                       torch_dtype=dtype, trust_remote_code=False)
            if model.config.num_labels != 2:
                raise ValueError("Use a fine-tuned binary spam/ham classifier")
            tokenizer = AutoTokenizer.from_pretrained(self.path, local_files_only=True)
            self.pipeline = pipeline("text-classification", model=model, tokenizer=tokenizer,
                                     device=device)
        spam_label = self.spec.spam_label if self.spec else os.getenv("GHOST_SPAM_LABEL", "spam")
        max_length = self.spec.max_length if self.spec else 4096

        def score(value):
            scores = self.pipeline(value, truncation=True, max_length=max_length, top_k=None)
            match = next((s for s in scores if s["label"].lower() == spam_label.lower()), None)
            if match is None:
                raise ValueError("Model lacks configured spam label: " + spam_label)
            return float(match["score"])

        full = score(text)
        if self.fingerprint is None:
            digest = hashlib.sha256(f"{spam_label}:{max_length}:{self.spec.dtype if self.spec else 'float32'}".encode())
            for path in sorted(Path(self.path).iterdir()):
                if path.is_file() and path.suffix in (".json", ".safetensors", ".bin", ".txt", ".model"):
                    digest.update(path.name.encode())
                    with path.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
            self.fingerprint = digest.hexdigest()
        sentences = re.split(r"(?<=[.!?])\s+", text)
        contributions = []
        if explain:
            for i, sentence in enumerate(sentences[:20]):
                reduced = " ".join(sentences[:i] + sentences[i + 1:])
                contributions.append({"sentence": sentence, "score_delta": full - score(reduced or " ")})
        return {"available": True, "probability": full, "ham_score": 1 - full, "calibrated": False,
                "device_used": str(self.pipeline.device), "max_length": max_length,
                "model_fingerprint": self.fingerprint,
                "label": spam_label, "explanation_method": "sentence_deletion_probability_delta",
                "explanations": sorted(contributions, key=lambda s: -s["score_delta"]),
                "limitations": ["Model output is uncalibrated", f"Input truncated to {max_length} tokens", "At most 20 sentences explained"]}
