# Changelog

All notable changes to **capstone2 — Hybrid SSH brute-force detector** are
documented here. Dates in ISO-8601 format.

## [1.0.1] — 2026-07-07
**Self-contained release zip.** A user can now download the source
archive, run a single command, and have a working demo without
any extra steps beyond having Python installed.

### Added
- Tracked `data/processed/sample_auth.log` and `groundtruth_ips.txt`
  so the dashboard has data to load immediately.
- Tracked `src/models/artifacts/latest.joblib` and `latest.meta.json`
  so ML scoring works out-of-the-box (no need to train first).
- `scripts/install_and_run.cmd` (Windows) and `scripts/install_and_run.sh`
  (macOS/Linux): one-shot setup + dashboard launch.
- Dashboard auto-generates a sample log on the fly if the file is
  somehow missing.

### Changed
- `.gitignore` updated: timestamped model artefacts still ignored,
  the canned `latest.*` artefacts explicitly allowlisted.
- Removed the duplicate timestamped `random_forest_*.joblib` copy in
  `src/models/artifacts/`.

### Notes
- 9/9 unit tests still passing.
- Zip size went from ~43 KB to ~205 KB (still tiny).

## [1.0.0] — 2026-07-07
First **stable 1.0** release.

## [0.1.0] — 2026-07-07
Initial release. Implements the four-layer hybrid architecture:
rule engine, log parser/normaliser, ML training pipeline, and
weighted rule + ML fusion. Includes Streamlit dashboard and
LaTeX report skeleton.
