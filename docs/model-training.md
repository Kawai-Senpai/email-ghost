# Train the optional semantic spam detector

Rspamd is the working default detector; its Bayes learning and rule engine do not require a GPU or transformer model. This optional path adds a separately inspectable content classifier, using ModernBERT by default. No labeled mailbox data is included and no accuracy is claimed without your own evaluation.

Install the optional dependencies in a Python environment suitable for PyTorch:

```sh
python -m pip install -e '.[ml]'
email-ghost train-model --train-file corpora/train.jsonl --validation-file corpora/validation.jsonl --output models/spam
```

Each JSONL record must include `text`, `label` (`spam` or `ham`), `campaign_id`, and an ISO 8601 `timestamp` with a timezone. `subject` is optional. For example:

```json
{"subject":"Order #123 confirmed","text":"Your order is confirmed.","label":"ham","campaign_id":"order-confirmation-v2","timestamp":"2026-01-01T12:00:00Z"}
```

Use authorized, representative recent mail. Normalize MIME into subject and visible body text before preparing records; do not treat sender reputation as body text. Every split needs both classes. The command rejects duplicate normalized content, shared campaigns across splits, and validation timestamps that do not strictly follow all training timestamps. It requires at least 100 records in each split; that minimum is a guard against accidentally using toy data, not a guarantee of sufficient data. `--allow-small-dataset` is for pipeline debugging and marks the evaluation as such. Manually review near duplicates and sender leakage, which exact hashes and campaign IDs cannot detect.

The default base model is `answerdotai/ModernBERT-base`; `--base-model` can point to another compatible binary-classification encoder or a local model directory. Training may download base model/tokenizer files. Runtime inference uses only local files. Base model weights are not a ready-made spam detector; training creates the `ham`/`spam` classification head.

Batch size is one with gradient accumulation to reduce memory pressure. Use `--cpu` for CPU training and `--max-length 512` for a smaller debugging run. Full fine-tuning memory requirements are substantially greater than inference; the application does not promise a 4 GB training budget. Default sequence length is 4096, with truncation. Choose 512–8192 through the CLI, within the architecture's actual supported context. Runtime caps are independently configured per model (legacy default 4096).

Output includes model/tokenizer files and `evaluation.json`: precision, recall, false-positive/negative rates, PR-AUC, ROC-AUC, Brier score, source-file hashes, split counts, and limitations. Metrics are from the validation split, not an untouched final test. Keep an independent later corpus for final evaluation. These numbers are about your local content classifier, never Gmail placement.

Run the model in Docker:

```sh
docker compose -f compose.yaml -f compose.ml.yaml up -d --build
```

This builds an opt-in image with the ML dependencies and mounts `./models/spam` as `/models/spam`. Inference defaults to CPU. Verify `content_model.available` in an audit, not only `content_model_configured` in discovery. To use a GPU you must install a suitable PyTorch/CUDA runtime and configure Docker GPU access for your machine; the default Compose configuration is CPU-only.

Set `GHOST_MODEL_PATH` for one model or use `GHOST_MODELS_FILE` for multiple independent classifiers. The [spam-only guide](spam-testing.md) covers the registry, GPU override, per-model mixed precision, memory management and independent reports. Set the actual spam label used by each checkpoint. Missing files, incompatible labels, and dependency failures return explicit unavailable results. `explain: true` runs up to 20 sentence-deletion comparisons per selected model; score deltas explain each classifier's output, not Gmail's reasoning.

The model's softmax output is uncalibrated. Optional learned/calibrated local and Gmail estimates require a separate [calibration workflow](calibration.md); recording feedback does not train them automatically.
