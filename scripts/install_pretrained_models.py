"""Fetch pinned, non-executable classifier artifacts and prepare the local registry.

Does not train, send, label messages or enable calibrated probabilities.
Existing artifacts are checked against recorded SHA256 before reuse.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
           "special_tokens_map.json", "vocab.json", "vocab.txt", "merges.txt",
           "spm.model", "sentencepiece.bpe.model", "README.md", "LICENSE", "LICENSE.txt"}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    manifest = json.loads((ROOT / "config/pretrained-models.json").read_text())
    registry = []
    with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(45, connect=15)) as client:
        for model in manifest["models"]:
            repo, revision = model["repository"], model["revision"]
            dest = ROOT / "models" / model["directory"]
            dest.mkdir(parents=True, exist_ok=True)
            provenance_path = dest / "provenance.json"
            old = json.loads(provenance_path.read_text()) if provenance_path.exists() else {}
            response = client.get(f"https://huggingface.co/api/models/{repo}/revision/{revision}", params={"blobs": "true"})
            response.raise_for_status()
            metadata = response.json()
            if metadata["sha"] != revision:
                raise ValueError(f"Revision mismatch for {repo}")
            files = sorted({entry["rfilename"] for entry in metadata["siblings"]} & ALLOWED)
            if not {"config.json", "model.safetensors"}.issubset(files):
                raise ValueError(f"Missing full safe classifier checkpoint: {repo}")
            hashes = {}
            entries = {entry["rfilename"]: entry for entry in metadata["siblings"]}
            for filename in files:
                path = dest / filename
                expected = old.get("sha256", {}).get(filename)
                upstream_hash = entries[filename].get("lfs", {}).get("sha256")
                if path.exists() and expected and sha256(path) == expected and old.get("revision") == revision and (not upstream_hash or expected == upstream_hash):
                    hashes[filename] = expected
                    continue
                print(f"Downloading {model['id']}/{filename}", flush=True)
                partial = path.with_suffix(path.suffix + ".partial")
                for attempt in range(3):
                    try:
                        offset = partial.stat().st_size if partial.exists() else 0
                        headers = {"Range": f"bytes={offset}-"} if offset else {}
                        with client.stream("GET", f"https://huggingface.co/{repo}/resolve/{revision}/{filename}", headers=headers) as download:
                            download.raise_for_status()
                            append = offset and download.status_code == 206
                            if append and not download.headers.get("content-range", "").startswith(f"bytes {offset}-"):
                                raise ValueError("Unexpected resume offset")
                            with partial.open("ab" if append else "wb") as output:
                                for block in download.iter_bytes(1024 * 1024):
                                    output.write(block)
                        if upstream_hash and sha256(partial) != upstream_hash:
                            raise ValueError(f"Upstream SHA256 mismatch: {repo}/{filename}")
                        break
                    except (httpx.HTTPError, ConnectionError, OSError):
                        if attempt == 2:
                            raise
                        print(f"Retrying read-only download {filename}, attempt {attempt + 2}/3", flush=True)
                        time.sleep(attempt + 1)
                partial.replace(path)
                hashes[filename] = sha256(path)
            # DistilBERT publisher supplies only the original cased vocabulary.
            # Explicit cased settings prevent AutoTokenizer's uncased default.
            if model["id"] == "distilbert" and "tokenizer_config.json" not in files:
                settings = {"tokenizer_class": "DistilBertTokenizer", "do_lower_case": False,
                            "model_max_length": 512}
                path = dest / "tokenizer_config.json"
                path.write_text(json.dumps(settings, indent=2) + "\n")
                hashes[path.name] = sha256(path)
            transformations = old.get("transformations", [])
            if model["id"] == "deberta":
                path = dest / "tokenizer_config.json"
                settings = json.loads(path.read_text(encoding="utf-8"))
                extras = settings.get("extra_special_tokens")
                if isinstance(extras, list):
                    named = {value for key, value in settings.items() if key.endswith("_token") and isinstance(value, str)}
                    if not set(extras).issubset(named):
                        raise ValueError("Cannot safely normalize unfamiliar extra special tokens")
                    original = dest / "tokenizer_config.upstream.json"
                    original.write_bytes(path.read_bytes())
                    settings.pop("extra_special_tokens")
                    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
                    transformations = [{"file": path.name, "upstream_sha256": sha256(original),
                        "reason": "Transformers5 list-valued extra_special_tokens is incompatible with4.57; removed only redundant named PAD/CLS/SEP entries. Named tokens and token IDs retained."}]
                    hashes[path.name] = sha256(path)
            provenance = {**model, "source_url": f"https://huggingface.co/{repo}/tree/{revision}",
                          "sha256": hashes, "locally_validated": False,
                          "transformations": transformations,
                          "limitations": model["limitations"]}
            provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
            registry.append({"id": model["id"], "path": "/models/" + model["directory"],
                             "spam_label": model["spam_label"], "device": "cpu", "dtype": "float32",
                             "max_length": model["max_length"], "threshold": .5, "keep_loaded": False})
            print(f"Prepared {model['id']} at {revision}", flush=True)
    path = ROOT / "config/models.json"
    path.write_text(json.dumps({"models": registry}, indent=2) + "\n")
    print(f"Registry: {path}; verify every model with a real audit before claiming available.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
