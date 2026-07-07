#!/usr/bin/env bash
# One-shot, no-extras setup + launch for the Streamlit dashboard.
#
# Tested on Ubuntu 22.04 / macOS 13 with Python 3.10+. For Windows,
# use ``scripts/install_and_run.cmd`` from a PowerShell prompt.
#
# Usage
# -----
#   bash scripts/install_and_run.sh
#
# What it does
# ------------
# 1. Creates a project-local virtual environment in ``.venv``
#    (skipped if it already exists).
# 2. Installs Python dependencies from ``requirements.txt``.
# 3. Launches the Streamlit demo dashboard on port 8501.
#
# The release zip ships with a sample ``data/processed/sample_auth.log``
# and a pre-trained model at ``src/models/artifacts/latest.joblib``,
# so the dashboard works immediately on first run.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
    echo "[install_and_run.sh] python3 was not found on PATH. Install Python 3.10+ first." >&2
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "[install_and_run.sh] creating virtual environment .venv"
    python3 -m venv .venv
fi

echo "[install_and_run.sh] activating .venv"
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[install_and_run.sh] installing requirements"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo
echo "[install_and_run.sh] launching Streamlit dashboard"
echo "[install_and_run.sh] (Ctrl-C to stop)"
echo
exec streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0
