from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd

from .train import ARTIFACT_DIR, FEATURE_COLUMNS


@dataclass
class ModelBundle:
    name: str
    model: object
    scaler: object
    feature_columns: list
    metrics: dict
    created_at: str
    notes: str = ""


def load_artifact(path: str | Path) -> ModelBundle:
    blob = joblib.load(path)
    return ModelBundle(
        name=blob["name"],
        model=blob["model"],
        scaler=blob["scaler"],
        feature_columns=blob["feature_columns"],
        metrics=blob["metrics"],
        created_at=blob["created_at"],
        notes=blob.get("notes", ""),
    )


def load_latest_artifact() -> ModelBundle:
    latest_meta = ARTIFACT_DIR / "latest.meta.json"
    latest_joblib = ARTIFACT_DIR / "latest.joblib"
    if not latest_joblib.exists():
        # fall back to most recent .joblib
        files = sorted(ARTIFACT_DIR.glob("*.joblib"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            raise FileNotFoundError(f"no model artefacts in {ARTIFACT_DIR}")
        return load_artifact(files[0])
    return load_artifact(latest_joblib)


def predict_proba(bundle: ModelBundle,
                  features: pd.DataFrame) -> pd.Series:
    """Return a per-IP attack probability (0..1)."""
    df = features.copy()
    if "ip" in df.columns:
        df = df.set_index("ip")
    for col in bundle.feature_columns:
        if col not in df.columns:
            df[col] = 0
    X = df[bundle.feature_columns].fillna(0).to_numpy(dtype=float)
    Xs = bundle.scaler.transform(X)
    m = bundle.model
    if hasattr(m, "predict_proba"):
        score = m.predict_proba(Xs)[:, 1]
    elif hasattr(m, "decision_function"):
        raw = -m.score_samples(Xs) if "IsolationForest" in m.__class__.__name__ \
            else m.decision_function(Xs)
        raw_min, raw_max = raw.min(), raw.max()
        score = (raw - raw_min) / (raw_max - raw_min + 1e-9)
    else:
        score = m.predict(Xs).astype(float)
    return pd.Series(score, index=df.index, name="ml_score")
