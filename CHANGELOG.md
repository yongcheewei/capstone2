# Changelog

All notable changes to **capstone2 — Hybrid SSH brute-force detector** are
documented here. Dates in ISO-8601 format.

## [1.0.0-beta.1] — 2026-07-07
First public **1.0 beta** snapshot. The detection pipeline is feature
complete end-to-end; no behavioural changes since `v0.1.0`, only a
version bump and housekeeping.

### Added
- `CHANGELOG.md` (this file).
- `src/__version__ = "1.0.0-beta.1"` and matching `pyproject.toml`
  version field so downstream tools can detect the build.

### Notes
- 9/9 unit tests passing.
- `scripts/run_pipeline.py` runs cleanly: 150 events → 18 rule
  detections → RF/XGBoost/IsolationForest trained → baseline
  comparison table written to `report/figures/baseline_comparison.csv`.

## [0.1.0] — 2026-07-07
Initial release. Implements the four-layer hybrid architecture:
rule engine, log parser/normaliser, ML training pipeline, and
weighted rule + ML fusion. Includes Streamlit dashboard and
LaTeX report skeleton.
