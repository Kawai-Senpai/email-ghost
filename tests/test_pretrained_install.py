"""Pinned downloads must not silently accept damaged or executable artifacts."""
import hashlib
import importlib.util
import json
from pathlib import Path

import httpx
import pytest

spec = importlib.util.spec_from_file_location("pretrained_install", Path(__file__).parents[1] / "scripts/install_pretrained_models.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def setup_download(tmp_path, monkeypatch, *, corrupt=False, partial=False):
    model = {"id": "test", "repository": "publisher/test", "revision": "a" * 40,
             "directory": "test-spam", "spam_label": "spam", "max_length": 512,
             "limitations": "Test fixture, not real model weights"}
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pretrained-models.json").write_text(json.dumps({"models": [model]}))
    data = b"safe checkpoint fixture"
    files = {"model.safetensors": data, "config.json": b'{"model_type":"bert"}',
             "tokenizer.json": b"{}"}
    if partial:
        dest = tmp_path / "models/test-spam"
        dest.mkdir(parents=True)
        (dest / "model.safetensors.partial").write_bytes(data[:8])
    requested = []
    def handle(request):
        requested.append(request)
        if request.url.path.startswith("/api/models/"):
            return httpx.Response(200, json={"sha": model["revision"], "siblings": [
                {"rfilename": name, "lfs": {"sha256": hashlib.sha256(content).hexdigest()}}
                for name, content in files.items()] + [{"rfilename": "custom_code.py"}, {"rfilename": "pytorch_model.bin"}]})
        filename = request.url.path.rsplit("/", 1)[-1]
        content = files[filename]
        if filename == "model.safetensors" and corrupt:
            return httpx.Response(200, content=b"damaged")
        if "range" in request.headers:
            assert filename == "model.safetensors"
            assert request.headers["range"] == "bytes=8-"
            return httpx.Response(206, headers={"Content-Range": f"bytes 8-{len(content)-1}/{len(content)}"}, content=content[8:])
        return httpx.Response(200, content=content)
    real_client = httpx.Client
    monkeypatch.setattr(installer, "ROOT", tmp_path)
    monkeypatch.setattr(installer.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw))
    return files, requested


def test_verified_artifacts_are_reused_and_executable_files_excluded(tmp_path, monkeypatch):
    files, requested = setup_download(tmp_path, monkeypatch)
    installer.main()
    assert set(p.name for p in (tmp_path / "models/test-spam").iterdir()) == set(files) | {"provenance.json"}
    assert json.loads((tmp_path / "config/models.json").read_text())["models"][0]["spam_label"] == "spam"
    requested.clear()
    installer.main()
    assert all(r.url.path.startswith("/api/models/") for r in requested)


def test_hash_mismatch_never_publishes_registry(tmp_path, monkeypatch):
    setup_download(tmp_path, monkeypatch, corrupt=True)
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        installer.main()
    assert not (tmp_path / "config/models.json").exists()
    assert not (tmp_path / "models/test-spam/model.safetensors").exists()


def test_pinned_partial_download_resumes_then_verifies_full_hash(tmp_path, monkeypatch):
    files, requested = setup_download(tmp_path, monkeypatch, partial=True)
    installer.main()
    assert (tmp_path / "models/test-spam/model.safetensors").read_bytes() == files["model.safetensors"]
    assert any("range" in r.headers for r in requested)
