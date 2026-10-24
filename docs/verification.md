# Verification evidence

Verified locally on 2026-10-24:

- 30 pytest checks pass, including MIME preservation, run isolation, attachment safety, URL findings, authentication provenance, optional model failure/disagreement, calibration scope/version guards, positive percentage output through the API, and calibration fitting mechanics.
- Both agent skills pass the skill creator validator; Python/JavaScript checks and Compose configuration checks pass.
- Full and browser-free Docker images build and run with healthy API/Rspamd/Redis services. The spam-only deployment passes live SMTP capture, MIME inspection, assertions and GTUBE rejection; screenshot requests are explicitly disabled there.
- Full Docker SMTP/audit/assertion/screenshot smoke checks pass for Chromium, Firefox and WebKit (16 variants each). The full Chromium matrix produces 112 screenshots and an offline gallery.
- Original local captures remain accessible after migration into the persistent Docker volume. Packaged skills and guides resolve even without the source repository path.
- The dedicated spam page successfully submits a GTUBE test and reports Rspamd rejection. Browser layout checks found no horizontal overflow at 390, 768 and 1440 pixels.
- NVIDIA GeForce GTX 1650 (4 GB) is visible on the host and through Docker GPU access.

Evidence files are generated under ignored `reports/`: `docker-chromium.json`, `docker-firefox.json`, `docker-webkit.json`, `docker-full-matrix.json`, `docker-spam-only.json`, `release-suite/results.json`, `release-suite/junit.xml`, and `full-matrix/index.html`.

Bounds: calibration fitting tests use synthetic fixtures to verify mechanics, not to establish real spam/Gmail accuracy. No production calibrated artifact, authorized mailbox corpus, or fine-tuned transformer weights were supplied or installed. Full transformer training/inference and performance on the GPU were not benchmarked. Google adapters are covered with mock responses and official endpoint documentation; no live Google credentials were used. A GitHub Actions workflow is included but was not executed on GitHub during this session.
