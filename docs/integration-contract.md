# Email Ghost integration handoff

Updated during the sandbox implementation on 2026-10-24. Intended for the parallel Ultra-Emailer integration session.

Local HTTP URL is `http://127.0.0.1:18030`; SMTP is `127.0.0.1:11025`. These are selected in the ignored `.env` because the standard 8030/1025 ports belong to existing services. Do not stop or replace the existing Mailpit. Docker container-to-container defaults remain HTTP 8030 and SMTP 1025. A short local server restart may occur while packaging is verified; use bounded readiness retries.

The existing integration operations are preserved: `/healthz`, `/v1/capabilities`, raw MIME upload to `/v1/messages?run_id=...`, `/v1/messages/{id}/audit`, and `/v1/messages/{id}/assert`. Upload bytes unchanged with `message/rfc822`; isolate every draft/test with a unique run ID. The original MIME is downloadable at `/raw`. No external SMTP relay is implemented.

New operations and additive report fields:

- `POST /v1/messages/{id}/spam` returns focused spam results. `audit` remains the superset.
- `content_models` contains independent optional transformer reports with `id`, `available`, spam score, verdict, device, precision, fingerprint and explanations. `model_consensus` exposes spam/ham votes and disagreement; it is not a calibrated probability.
- Legacy `content_model` and `content_spam_probability` identify the first available content model, not an averaged ensemble.
- `GET /v1/models` exposes model registry and CPU/CUDA discovery. A model configuration does not guarantee usable weights.
- Optional `local_calibration` and `gmail_calibration` results include `available`, `probability`, artifact ID, domain scope and measured evaluation. Percentages appear only with validated artifacts and matching model/scanner versions and required features. Gmail placement requires actual Gmail outcomes and trained sending-domain scope. Without these, probabilities remain null while ordinary scanner/model reports continue working.
- Capabilities now distinguish `gmail_prediction_supported:true` from currently installed `gmail_calibration` artifact status and per-message `gmail_prediction_available`. An unconfigured artifact is an optional setup condition, not a permanently unsupported feature. The spam UI keeps unconfigured estimates in a collapsed setup section.
- `POST /v1/messages/{id}/learn` explicitly trains Rspamd Bayes on a known `spam`/`ham` label. This changes detector state and invalidates earlier scanner calibration revisions. Do not use a heuristic output as a ground-truth training label.
- `/spam` is a dedicated spam testing UI. `compose.spam.yaml` builds a browser-free detector service; the HTTP API stays compatible.
- Model files, ML dependencies and GPU access are optional overrides (`compose.ml.yaml`, `compose.models.yaml`, `compose.gpu.yaml`). They are not required for the default Rspamd detector.
- `GET /v1/calibration/examples` exports observed-label records paired with prior saved audit snapshots; `train-calibration` consumes chronological campaign-separated train/calibration/test JSONL and writes optional local/Gmail artifacts. Runtime JSON coefficients need no ML dependency. `compose.calibration.yaml` enables mounted artifacts; the default detector works without them.
- `/spam-skill.md` and `/guides/spam-testing.md` provide focused spam-only operation, multiple model comparisons, GPU setup and calibrated-estimate instructions.

Always inspect `rspamd.available` and whether its scan is definitive. A generic `is_skipped=true` is inconclusive. The standard GTUBE test intentionally returns `is_skipped=true`, `passthrough_module=GTUBE`, action `reject`, and a GTUBE symbol; this is a definitive spam rejection. Do not treat it as a clean message. Normal scan scores are not probabilities. HTTP 200 from an assertion route still requires checking `passed`.

The classification values currently used by integrations remain `uncertain`, `low_scanner_risk`, `needs_review`, and `high_risk`. A low scanner score is not a guarantee of inbox placement. Preserve warnings and missing signals in the consumer's output. Never silently convert unavailable optional percentages to zero.

Use the portable [agent skill](../skills/email-ghost/SKILL.md), [spam-only guide](spam-testing.md), and generated `/openapi.json` for detailed operation. `scripts/smoke.py` verifies real SMTP capture, MIME/attachments, live Rspamd and GTUBE detection, assertions, and optional screenshots. The fixture suite CLI exports JSON and JUnit.
