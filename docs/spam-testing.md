# Use Email Ghost only for spam testing

You can use Email Ghost as a standalone spam-testing service. Rendering, previews, screenshots, and the rest of the email studio are optional. The dedicated interface is `/spam`; the same detector is also available through HTTP and the CLI.

## 1. Start the detector

With Docker and Compose installed, run from the repository:

```sh
docker compose -f compose.yaml -f compose.spam.yaml up -d --build --wait
```

This uses the smaller `Dockerfile.spam`, which does not download browser engines. It starts the API, Rspamd, and persistent Redis. It needs no GPU and no external mail account. The first build still downloads Python dependencies. Reuse the same Compose file flags for `logs`, `up`, and `down` so the deployment mode is explicit.

Open **http://localhost:8030/spam**. If the standard ports are occupied, copy `.env.example` to `.env` and select unused host ports; this checkout uses **HTTP 18030** and **SMTP 11025** to coexist with another Mailpit. Use **http://localhost:18030/spam** for that configuration. Other containers on the same Compose network use `http://sandbox:8030` and `sandbox:1025` regardless of published host ports.

Readiness: `GET /healthz` checks the API/database. `GET /v1/capabilities` identifies configured detector capabilities; `GET /v1/models` lists content models and CPU/CUDA availability. A configured engine may still fail a particular scan, so inspect the scan result itself. `docker compose ... --wait` waits for API, Rspamd, and Redis health checks.

## 2. Test through the page

On `/spam`, either import an `.eml` file or enter a subject and plain-text body. HTML is optional. The imported file takes precedence when one is selected. Click Clear imported file to return to copy-only mode. Add the actual production sending IP and envelope sender under **Sending context & explanations** if known. Click **Run spam test**.

The result shows Rspamd evidence, each configured content model's independent report, disagreement, optional calibrated estimates, and a full JSON report. Explanations rerun selected models for sentence deletion and may take considerably longer than an ordinary scan.

A raw `.eml` is preferable: it preserves headers, MIME alternatives, DKIM signatures, attachments and URLs. Copy-only tests cannot establish sender reputation, actual SPF/DMARC alignment, transport behavior or recipient history. Compose-generated sender defaults use `.test` domains and are not a simulation of your production infrastructure.

## 3. Test through HTTP

Import a complete email:

```sh
curl --fail-with-body -X POST 'http://localhost:8030/v1/messages?run_id=campaign-a' -H 'Content-Type: message/rfc822' --data-binary @message.eml
```

The response contains `id`. Replace `MESSAGE_ID` below with that value:

```sh
curl --fail-with-body -X POST 'http://localhost:8030/v1/messages/MESSAGE_ID/spam' -H 'Content-Type: application/json' -d '{}'
```

For known production context and selected models:

```json
{"sender_ip":"203.0.113.10","mail_from":"bounce@yourdomain.com","helo":"mail.yourdomain.com","model_ids":["modernbert","roberta"],"explain":true}
```

The example IP is documentation-only; replace it with your real production IP or omit it. Never pass the sandbox's Docker IP as production context. Omit `model_ids` to run every configured classifier; use `[]` for a scanner-only audit. An unknown model ID is a validation error.

`POST /v1/compose` accepts `subject`, `text`, optional `html`, `sender`, `recipient`, and `run_id` for copy tests. `POST /v1/audit` accepts raw MIME directly, captures it and returns a full audit. `/v1/messages/{id}/audit` returns the superset of `/spam`: local structural findings, URLs and recommended actions as well as detector reports. It also saves an immutable audit snapshot for outcome-based calibration exports.

## 4. Interpret the result

| Field | Meaning |
| --- | --- |
| `verdict` | `high_risk`, `needs_review`, `low_scanner_risk`, or `uncertain` |
| `rspamd.score` / `action` | Actual filter result; the score is not a percentage |
| `rspamd.symbols` | Rule/statistical evidence and scores |
| `authentication` | Recognized scanner evidence; unsupported mechanisms stay not verified |
| `content_models[]` | Separate binary classifier reports, score, verdict, device and explanation |
| `model_consensus` | Agreement or disagreement among available models; not a calibrated average |
| `local_calibration` | Optional held-out calibrated local spam estimate and artifact provenance |
| `gmail_calibration` | Optional Gmail outcome estimate within validated sender/feature scope |
| `missing_signals` | Reasons the test is incomplete |
| `recommended_actions` | Concrete structural/security fixes |

Keep unavailable engines visible. A scanner timeout, missing model, unrecognized label, GPU OOM, or generic skipped scan is not a clean result. Rspamd's standard GTUBE test is a special case: it forces rejection and skips remaining modules. The result includes a GTUBE passthrough module, GTUBE symbol, and reject action; the sandbox recognizes that as a definitive spam rejection.

`content_models[].probability` is an uncalibrated classifier score. The legacy top-level `content_spam_probability` identifies the first available model, named by `content_spam_probability_model_id`; it is not a mean. Voting preserves disagreements rather than hiding them. Multiple similarly trained models may share blind spots. Prefer separately validated models that add complementary evidence.

Local calibrated percentages and Gmail estimates are opt-in. They require measured artifacts and become unavailable if required features are missing, versions change, the artifact expires, or the sender is outside its scope. See [calibration](calibration.md). Do not convert null probabilities to zero or describe local scores as Google's secret score.

## 5. Add independent deep learning models

Rspamd works without this section. To add fine-tuned binary transformer classifiers, place their local Hugging Face model/tokenizer directories under `./models`. Copy `config/models.example.json` to ignored `config/models.json`, then edit it to match only the actual models you have. The example paths are not bundled pretrained spam models.

```json
{"models":[
  {"id":"modernbert","path":"/models/modernbert-spam","spam_label":"spam","device":"auto","dtype":"auto","max_length":4096,"threshold":0.5,"keep_loaded":false},
  {"id":"roberta","path":"/models/roberta-spam","spam_label":"LABEL_1","device":"cpu","dtype":"float32","max_length":512,"threshold":0.5,"keep_loaded":false}
]}
```

Use the actual spam label from each model's config. Base ModernBERT, RoBERTa or DeBERTa weights need a trained classification head; a generic language model is not a spam detector. Up to eight models may be configured. Per-model token caps must fit that model's supported context; raising a 512-token encoder's limit does not extend its architecture.

```sh
docker compose -f compose.yaml -f compose.spam.yaml -f compose.ml.yaml -f compose.models.yaml up -d --build --wait
```

The ML override installs optional PyTorch/Transformers dependencies; the registry override mounts the model configuration. Each classifier gets its own report and failure state. One model failure does not remove healthy model results. Models run sequentially across requests to avoid overlapping large allocations. `keep_loaded:false` releases models between runs; this reduces peak VRAM but increases loading latency. `keep_loaded:true` intentionally retains weights and may exceed a small GPU's memory when multiple models are configured.

To fine-tune your own semantic detector, follow [model training](model-training.md). Training is optional and requires authorized labeled data. You can train different compatible architectures using `--base-model` and evaluate them separately before adding them to the registry.

## 6. Optional GPU acceleration

Install NVIDIA drivers and NVIDIA Container Toolkit on the Docker host. Add the GPU override:

```sh
docker compose -f compose.yaml -f compose.spam.yaml -f compose.ml.yaml -f compose.models.yaml -f compose.gpu.yaml up -d --build --wait
```

Set a model's `device` to `cuda:0` to require that GPU, or `auto` to choose CUDA when available and CPU otherwise. Explicit CUDA requests do not silently become CPU inference when CUDA is missing. `float16` or `bfloat16` can reduce memory on compatible hardware; use `float32` for the broadest CPU compatibility. `auto` precision uses the model's stored precision. `/v1/models` reports discovered CUDA hardware; each successful prediction reports `device_used`.

On a 3–4 GB GPU, start with one encoder, short inputs, and `keep_loaded:false`, then measure. Do not assume a model will fit merely because its weights fit: attention activations, sequence length, explanations, dtype and runtime also consume memory. Larger classification models are optional; the runtime supports compatible local sequence-classification checkpoints, not arbitrary generative prompting. Full fine-tuning may need considerably more memory than inference.

## 7. Bayes learning and observed outcomes

Rspamd includes a Bayesian classifier, but it needs labeled data. Explicitly teach a known example:

```sh
curl --fail-with-body -X POST 'http://localhost:8030/v1/messages/MESSAGE_ID/learn' -H 'Content-Type: application/json' -d '{"label":"ham"}'
```

Use `spam` for a genuinely labeled spam example. Check `learned` and the engine response; duplicate or insufficient text may be rejected. Never bootstrap ground truth by blindly training on the scanner's own verdict. Learning is shared detector state and persists in Redis. Successful learning changes the scanner calibration revision; earlier calibrated artifacts then stop applying until retrained.

Record actual Gmail placement separately with `/feedback` (`provider:gmail`, `label:spam` or `inbox`, and a provenance `source`), or explicitly import from an owned Gmail mailbox using the [Google adapter](google-integrations.md). Save an audit before feedback so a contemporaneous feature snapshot can be exported. `/feedback` does not automatically train Bayes or fit a probability model.

## 8. CI assertions and reports

Create an assertion file, for example:

```json
{"require_rspamd":true,"max_rspamd_score":6,"max_errors":0,"required_models":["modernbert","roberta"],"max_model_scores":{"modernbert":0.3,"roberta":0.3},"allow_model_disagreement":false}
```

Only require models you installed. Add `max_spam_probability` or `max_gmail_probability` only when the corresponding optional calibration is enabled for your test scope; otherwise the assertion fails as unavailable.

```sh
email-ghost --url http://localhost:8030 audit MESSAGE_ID
email-ghost --url http://localhost:8030 assert MESSAGE_ID --spec assertions.json
email-ghost --url http://localhost:8030 test examples/suite.json --output reports/spam-suite
email-ghost --url http://localhost:8030 report campaign-a
```

Run locally after installing the package, or inside the API container with `docker compose ... exec sandbox email-ghost ...` (internal URL defaults to 8030). The CLI uses exit 0 for success, 1 for assertion/validation failure, 2 for API or input errors. The suite emits `results.json` and `junit.xml`. An HTTP 200 assertion response still requires checking `passed`.

`python scripts/smoke.py --require-scanner` verifies SMTP capture, MIME/attachment inspection, actual Rspamd scanning and the standard GTUBE rejection without using screenshots. Adjust `--url` and `--smtp-port` for host port overrides. Do not add `--screenshots` in the browser-free deployment.

## 9. Privacy, troubleshooting and cleanup

The preview renderer never fetches mail URLs; the detector inspects them and Rspamd may perform DNS/reputation queries. Attachments are not executed; dangerous-extension findings are not antivirus scanning. Imported authentication headers are untrusted. Google access is read-only and occurs only through explicit adapter calls. Keep capture/API ports local unless you deliberately add authentication and network controls.

Use `docker compose ... logs --tail=100 sandbox rspamd redis` for failures. If Rspamd is unavailable, inspect service health before editing copy. If a model is unavailable, check its local files, binary classification head, configured spam label, optional dependencies and actual device memory. If calibration is unavailable, inspect its explicit reason and scope/version requirements rather than substituting a number.

`docker compose ... down` stops the stack and preserves data. `down -v` destroys the persistent inbox and learned detector state; it is not routine cleanup. Deleting a test message preserves audit snapshots, feedback events, and screenshot artifacts. There is no automatic disk quota or retention policy.

For agent operation, install the focused [email-ghost-spam skill](../skills/email-ghost-spam/SKILL.md), also served at `/spam-skill.md`. The full sandbox skill is available separately at `/skill.md`.
