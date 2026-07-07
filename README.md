# capstone2 — Hybrid SSH Brute-Force Detector

A rule-based + machine-learning hybrid system for detecting SSH brute-force attacks on Linux authentication logs. Capstone 2 project extending the Capstone 1 rule-only detector with an ML layer and a hybrid decision fusion engine.

## What it does
- Parses Linux `auth.log` / `secure` files into structured events.
- Applies static and adaptive threshold rules (re-implemented from Capstone 1).
- Extracts per-IP and per-time-window features for ML.
- Trains classifiers (Random Forest, XGBoost, Isolation Forest).
- Fuses rule + ML outputs via a configurable hybrid decision layer.
- Ships a Streamlit dashboard for live demo.

## Repository layout
```
capstone2/
├── src/
│   ├── parser/        # log ingest + normaliser
│   ├── rules/         # static, adaptive, hybrid rule sets
│   ├── features/      # feature engineering for ML
│   ├── models/        # train.py, predict.py
│   ├── hybrid/        # rule + ML fusion
│   └── evaluation/    # metrics, plots, baseline comparisons
├── dashboard/         # Streamlit demo app
├── tests/             # pytest suite
├── data/              # datasets + README (raw/ git-ignored)
├── notebooks/         # EDA + ablations
├── scripts/           # pipeline + download helpers
└── report/            # LaTeX report source
```

## Quick start

### One-shot demo (recommended for first-time users)

The release zip ships with a sample `auth.log` and a pre-trained model
artefact, so a single command gets the demo running:

```bash
# Windows
scripts\install_and_run.cmd

# macOS / Linux
bash scripts/install_and_run.sh
```

The script creates `.venv`, installs dependencies, then launches the
Streamlit dashboard at <http://localhost:8501>.

### Manual setup

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
pytest -q                       # unit tests
scripts\run_pipeline.cmd        # end-to-end smoke run (Windows)
bash scripts/run_pipeline.sh    # end-to-end smoke run (macOS/Linux)
streamlit run dashboard/app.py  # demo dashboard
```

## Datasets
See `data/README.md` for sources (Loghub Linux_auth, public Kaggle SSH-attack logs, locally simulated attacks via `hydra`/`medusa`).

## Status
- [x] Repo scaffold
- [x] Rule engine (static + adaptive + hybrid)
- [x] Log parser + normaliser
- [x] Feature engineering
- [x] ML training pipeline (RF / XGBoost / IsolationForest)
- [x] Hybrid fusion layer
- [x] Evaluation suite (precision / recall / F1 / FPR / latency)
- [x] Streamlit dashboard
- [x] Unit tests
- [ ] Final report and slides (writing stage)
