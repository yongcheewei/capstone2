#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[run_pipeline.sh] generating sample log if missing"
python scripts/generate_sample_log.py --out data/processed/sample_auth.log || true

echo "[run_pipeline.sh] running end-to-end pipeline"
python scripts/run_pipeline.py

echo "[run_pipeline.sh] running tests"
python -m pytest -q
