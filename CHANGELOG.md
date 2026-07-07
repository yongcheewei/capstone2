# Changelog

All notable changes to **capstone2 — Hybrid SSH brute-force detector** are
documented here. Dates in ISO-8601 format.

## [1.0.0] — 2026-07-07
First **stable 1.0** release. Promoted from `v1.0.0-beta.1` after
end-to-end pipeline + unit-test verification. From now on this tag
is the recommended download for both human users and downstream
automation.

### Changed
- `src/__version__ = "1.0.0"` and matching `pyproject.toml` version
  field.
- GitHub release `v1.0.0` published as a stable (non-prerelease)
  release and marked **Latest**.
- No code changes vs the beta tag — the pipeline, the ML models, and
  the Streamlit dashboard are all frozen at the same commit lineage.

### Notes
- 9/9 unit tests passing.
- `scripts/run_pipeline.py` reproduces baseline metrics via the
  bundled toy dataset; swap in Loghub Linux_auth for the final
  report evaluation.

## [1.0.0-beta.1] — 2026-07-07
First public **1.0 beta** snapshot. The detection pipeline is feature
complete end-to-end; no behavioural changes since `v0.1.0`, only a
version bump and housekeeping.

## [0.1.0] — 2026-07-07
Initial release. Implements the four-layer hybrid architecture:
rule engine, log parser/normaliser, ML training pipeline, and
weighted rule + ML fusion. Includes Streamlit dashboard and
LaTeX report skeleton.
