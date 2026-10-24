# Optional calibrated spam and Gmail estimates

This feature is optional. Rspamd, independent transformer reports, structural checks and assertions work without it. Calibration is for users with authorized labeled observations and enough data to measure generalization. It never turns a rule score or an uncalibrated softmax into a percentage by arbitrary rescaling.

Two independent artifacts are supported:

- `local_spam`: estimates local spam risk from labeled spam/ham examples.
- `gmail_placement`: estimates observed Gmail Spam placement for explicitly scoped sending domains, from real Gmail labels.

The runtime loads transparent JSON coefficients and applies a logistic meta-classifier followed by a separately trained Platt calibration layer. Artifacts record feature names, model fingerprints/scanner revision, source hashes, split counts, domain scope and independent test metrics. Runtime prediction needs no scikit-learn or pickle deserialization.

## Collect data with provenance

For each message, use a meaningful campaign/template run ID, save an audit with `/v1/messages/{id}/audit`, then record a known outcome with `/feedback`. For Gmail, use actual observations from authorized mailboxes; `POST /v1/integrations/gmail/import` with `audit:true` performs a read-only import, saves a report and records an observed SPAM/INBOX label. Ordinary archived/Sent messages do not become inbox examples. See [Google integrations](google-integrations.md).

Export `/v1/calibration/examples?provider=gmail` (omit the filter for local datasets). Its `records` array contains the contemporaneous saved report, digest, campaign ID, provider, label source, sender domain and timestamp. Feedback without a preceding audit is counted as omitted; it is not reconstructed from a later rescan that could contain future reputation information. Deleted messages are not exported. The endpoint is capped at 10,000 records; larger datasets should be assembled from independently stored audit evidence.

Split the records into **three JSONL files**: train, calibration, and an untouched final test, in chronological order. Do not randomly split copies of one campaign. Each JSONL line has this structure:

```json
{"label":"spam","provider":"gmail","source":"owned seed Gmail API observation","message_digest":"64_lowercase_hex_characters_of_raw_mime_sha256","timestamp":"2026-01-01T12:00:00Z","campaign_id":"campaign-a","sender_domain":"yourdomain.com","report":{"rspamd":{"available":true,"score":8,"revision":"your_actual_saved_revision"},"content_models":[]}}
```

Use actual exported values; the example is a schema illustration, not training data. Allowed labels are `spam`, `ham`, and `inbox`. Gmail tasks require `provider:gmail`. Sources must identify how labels were obtained. Every split must contain both classes, at least 100 distinct messages, no repeated normalized message digest, no shared campaigns, and dates strictly after the previous split. The first and final split are also checked for shared campaigns/digests. Exact hashes cannot detect all near duplicates or sender leakage; review the dataset deliberately.

One hundred examples per split is a minimum guard, not evidence that the dataset represents your senders or future campaigns. Calibration does not solve insufficient or biased observations. Independently validate each sending domain and email class you intend to support.

## Train and evaluate

Install only the calibration dependencies if you do not need transformers:

```sh
python -m pip install -e '.[calibration]'
email-ghost train-calibration --task local_spam --train-file corpora/train.jsonl --calibration-file corpora/calibration.jsonl --test-file corpora/test.jsonl --features rspamd_score --output calibration/local.json
```

For multiple independent content models, include their feature IDs:

```sh
email-ghost train-calibration --task local_spam --train-file corpora/train.jsonl --calibration-file corpora/calibration.jsonl --test-file corpora/test.jsonl --features rspamd_score,content:modernbert,content:roberta --output calibration/local.json
```

All selected features must be present in every record and come from identical model/scanner versions. Model probabilities enter as clipped log-odds. Missing scores are not imputed as zero. To build a Gmail artifact:

```sh
email-ghost train-calibration --task gmail_placement --sender-domains yourdomain.com --train-file corpora/gmail-train.jsonl --calibration-file corpora/gmail-calibration.jsonl --test-file corpora/gmail-test.jsonl --features rspamd_score,content:modernbert --output calibration/gmail.json
```

`--sender-domains` accepts a comma-separated exact list and is required for Gmail. Every dataset record must be inside that scope. This version does not generalize a calibrated artifact automatically to other domains or recipient histories.

The command fits the meta-classifier on train, fits the calibration layer on calibration, and measures Brier score, ROC-AUC, false positive/negative rates, precision and recall on the untouched test split. Validation requires a better Brier score than a constant training-prevalence baseline, ROC-AUC above chance, and a false-positive rate no greater than `--max-false-positive-rate` (default 0.01). Choose a stricter threshold appropriate to your use case; this default is not a deliverability guarantee. Exit 0 means validation passed, 1 means the artifact failed its gates, 2 means invalid input or a dependency error.

`--allow-small-dataset` can debug the mechanics with small corpora, but its artifact always has `validated:false` and cannot enable percentages. Tests use synthetic observations solely to verify fitting and runtime mechanics; their metrics are not product accuracy claims. No real calibrated model or Gmail-labeled corpus is bundled with this repository.

## Enable an artifact

For local development set `GHOST_LOCAL_CALIBRATION_FILE` and/or `GHOST_GMAIL_CALIBRATION_FILE` to the JSON files. For Docker:

```sh
docker compose -f compose.yaml -f compose.spam.yaml -f compose.calibration.yaml up -d --build --wait
```

The override mounts `./calibration/local.json` and `./calibration/gmail.json`. If you have only one artifact, the other estimate explicitly remains unavailable. ML features additionally require the corresponding models/ML overrides. Restart after changing model configuration or weights; calibration JSON itself is re-read on each audit.

Successful reports include `local_calibration.available:true` / `gmail_calibration.available:true`, the calibrated `probability`, artifact ID, scope and held-out evaluation. Legacy `spam_risk_probability` and `gmail_spam_probability` become non-null accordingly. `gmail_prediction_available` becomes true only for a message passing all runtime checks. The base detector still reports its own evidence separately.

Runtime rejects invalid/unvalidated artifacts, fewer than 100 records in any split, missing feature inputs, changed model fingerprints or scanner learning revision, out-of-scope senders, and expired artifacts. Default maximum age is 90 days; configure `GHOST_CALIBRATION_MAX_AGE_DAYS` deliberately for your monitoring policy. Model weight/config/precision/token-limit fingerprints are computed from actual files. Successful Bayes learning through this API increments the scanner revision and invalidates earlier scanner-based calibration. When changing Rspamd rules/configuration or teaching it outside this API, bump `GHOST_SCANNER_REVISION` and refit.

Use `max_spam_probability` or `max_gmail_probability` in assertions to require and gate a calibrated result. Missing calibration fails the check. A measured probability still carries uncertainty: future campaigns, sender infrastructure changes, recipient personalization and Google filtering drift can invalidate past relationships. Monitor outcomes and refit with genuinely later independent test data.
