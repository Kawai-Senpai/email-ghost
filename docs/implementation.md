# Implementation scope and sources

The original todo and spamdetector documents are research notes, including descriptions of archives that are not present in this repository. This implementation starts from those notes, not an existing starter application.

Implemented: local SMTP capture with exact MIME download, run-scoped inbox, MIME/attachment inspection, local message/security/accessibility/compatibility audits, Rspamd HTTP scanning with Redis persistence, optional locally installed transformer inference and sentence deletion, sanitized responsive previews, three browser screenshot engines, 16/112 variation matrices, persisted galleries, pixel diffs, assertions, feedback provenance, audit events, CLI, OpenAPI discovery, dashboard, Docker image/Compose and an agent skill.

The optional `train-model` workflow fine-tunes a binary transformer classifier and records validation metrics, source digests, and leakage checks. This workflow is implemented, but no authorized training corpus or trained spam weights are bundled, and no full transformer training run was performed during core verification.

Implemented optional extensions: independent binary transformer model registry with CPU/CUDA selection, mixed precision and sequential unloading; separately fitted local/Gmail logistic meta-models with held-out calibration and chronological/campaign-separated test validation; model/scanner version and sender-scope guards; contemporaneous audit/feedback export; read-only Gmail observation imports and Postmaster v2 compliance/statistics queries using operator access tokens. These extensions have unit/mechanics tests, not a real labeled Gmail performance benchmark. They are inactive without suitable artifacts/credentials.

Not implemented: interactive OAuth consent/refresh, RETVec, Integrated Gradients, comprehensive Can I Email database, element-level difference inspector, IMAP, or actual proprietary client screenshot adapters. These require external clients or further implementation. Null values and unavailable flags are part of the public contract; do not replace them with invented estimates.

Agent usability is based on stable structured operations, isolated run IDs, bounded waits, explicit capability flags, provenance, and downloadable artifacts. A skill provides operating decisions; generated OpenAPI provides exact field definitions. HTTP and CLI make the sandbox usable across agent frameworks without an additional protocol gateway.

Primary references checked during implementation:

- [Rspamd protocol](https://docs.rspamd.com/developers/protocol/): `/checkv2`, envelope metadata headers, JSON symbols, action and score semantics.
- [Playwright network isolation](https://playwright.dev/python/docs/network): context routing and blocking service workers.
- [Playwright BrowserContext](https://playwright.dev/python/docs/api/class-browsercontext): isolated contexts, JavaScript setting, viewport and color scheme.
- [Agent Skills specification](https://agentskills.io/specification): portable SKILL.md metadata and bundled instructions.
- [Gmail CSS support](https://developers.google.com/workspace/gmail/design/css): documented CSS support is not a complete local rendering engine.
- [ModernBERT model card](https://huggingface.co/answerdotai/ModernBERT-base): base weights require downstream fine-tuning for classification.
- [Transformers Trainer](https://huggingface.co/docs/transformers/v4.57.1/en/main_classes/trainer): supervised fine-tuning and evaluation interface.
- [Rspamd GTUBE behavior](https://docs.rspamd.com/other/gtube_patterns/): GTUBE deliberately skips other modules while forcing a reject action.

The research notes contain time-sensitive claims and pasted citation placeholders. They are not a verified compatibility database and are not used to fabricate rendering support or filtering probabilities.
