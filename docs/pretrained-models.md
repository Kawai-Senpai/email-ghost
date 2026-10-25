# Installed independent text classifiers

This opt-in local deployment runs four separately reported spam classifiers with
Rspamd. They classify subject/body text, not images. Rendering checks are separate.
No calibrated local or Gmail probabilities have been fitted.

| ID | Publisher checkpoint | Limitations |
|---|---|---|
| modernbert | [sharecreative/modernbert-spam-classifier-feb25](https://huggingface.co/sharecreative/modernbert-spam-classifier-feb25) | Fine-tuned spam head;1024-token cap. Publisher license undeclared: review before redistribution. Small-corpus metrics are not local validation. |
| roberta | [mshenoda/roberta-spam](https://huggingface.co/mshenoda/roberta-spam) | MIT; mixed SMS/Telegram/Enron training. Publisher documents class1 as spam; runtime LABEL_1. |
| deberta | [Avijit070/spam-email-deberta-v3](https://huggingface.co/Avijit070/spam-email-deberta-v3) | Apache-2.0; sparse card, local accuracy unestablished. Tokenizer metadata needs compatibility normalization. |
| distilbert | [dima806/email-spam-detection-distilbert](https://huggingface.co/dima806/email-spam-detection-distilbert) | Apache-2.0; cased email classifier. Publisher metrics do not establish cold-outreach performance. |

[The manifest](../config/pretrained-models.json) pins revisions, labels and token
caps. [The installer](../scripts/install_pretrained_models.py) downloads only
whitelisted safetensors/tokenizer assets/cards, verifies upstream LFS SHA256 and
records hashes/source revisions in ignored `models/<name>/provenance.json`.
It writes ignored `config/models.json`; weights are not committed. No remote code
or pickle checkpoint is loaded. Verified artifacts are reused. Interrupted GETs
have at most3 attempts and resume the pinned file; unexpected ranges/hashes fail.

DistilBERT supplies a cased vocabulary without tokenizer settings; the installer
explicitly disables lowercasing. DeBERTa's Transformers5 list-valued
`extra_special_tokens` is incompatible with4.57. The installer removes only
redundant PAD/CLS/SEP entries already present as named tokens, preserving the
original file and transformation provenance. Token IDs and named special tokens
remain intact. Unknown extra tokens fail instead of being silently dropped.

## Reproduce the setup

Run from this checkout in a Python environment with httpx. On a fresh machine,
build the normal `email-ghost:local` base image first.

```powershell
uv run python scripts/install_pretrained_models.py
docker compose -f compose.yaml -f compose.models-cpu.yaml build sandbox
docker compose -f compose.yaml -f compose.models-cpu.yaml up -d --no-deps --no-build --wait sandbox
```

[Dockerfile.ml-cpu](../Dockerfile.ml-cpu) extends that base with pinned CPU PyTorch,
Transformers, Accelerate, SentencePiece and Protobuf. The
[Compose override](../compose.models-cpu.yaml) preserves ports, capture volume,
Rspamd and Redis. Current local API18030/SMTP11025 differ from fresh defaults;
discover actual ports. The unrelated Mailpit instance remains separate.
Models run sequentially on CPU, two OpenMP/MKL threads, `keep_loaded:false`.
The host GTX1650 has4GB VRAM, but this deployment uses CPU. Report the actual
device. GPU remains a separate opt-in setup.

## Verify inference and inspect disagreement

Check `/healthz`, `/v1/models` and capabilities, then audit a captured message and
assert `required_models` includes all4 IDs. Inspect every availability/error,
fingerprint, device, score and verdict. Configured files do not prove inference.

Verified2026-10-25: all4 available on capture
`b744eac0ed144001a7ae4af68cbae991`, audit
`140d66635a6f42d891eafe62fddfb4f2`; all4 required-model assertions passed.
This fictional mechanics fixture is not a validation corpus or training label.
The first audit exposed missing Protobuf and incompatible DeBERTa metadata;
both were fixed before claiming readiness. No Bayes learning occurred.

The first outreach comparison exposed3ham/1spam disagreement. Preserve all model
reports and inspect explanations. Revise only for better factual clarity/writing;
never invent an averaged probability, disable disagreement to force a pass, or
train on a detector's own verdict. No local sender accuracy or Gmail placement
has been measured. See [training](model-training.md), [calibration](calibration.md),
[spam testing](spam-testing.md), [integration contract](integration-contract.md),
[operating skill](../skills/email-ghost/SKILL.md), [spam skill](../skills/email-ghost-spam/SKILL.md),
and [README](../README.md).
