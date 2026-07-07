from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

try:
    from xgboost import XGBClassifier  # noqa: F401
    HAS_XGB = True
except Exception:
    HAS_XGB = False

ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_COLUMNS: List[str] = [
    "failed_total", "accepted_total", "failure_to_success_ratio",
    "failures_per_minute", "unique_users_targeted",
    "invalid_user_attempts", "invalid_user_ratio", "unique_ports",
    "active_minutes", "attempts_per_minute", "username_entropy",
    "is_internal_ip", "first_attempt_hour", "rapid_attempts_burst",
]


@dataclass
class ModelBundle:
    name: str
    model: object
    scaler: StandardScaler
    feature_columns: List[str]
    metrics: dict
    created_at: str
    notes: str = ""


def _stack(features: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, pd.Series]:
    """Return X, y, ip for a labelled feature table."""
    df = features.copy()
    if "label" not in df.columns:
        raise ValueError("features DataFrame must contain a 'label' column")
    y = df["label"].astype(int).to_numpy()
    ips = df["ip"].astype(str)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"missing feature columns: {missing}")
    X = df[FEATURE_COLUMNS].fillna(0).to_numpy(dtype=float)
    return X, y, ips


def _maybe_apply_smote(X: np.ndarray, y: np.ndarray,
                       random_state: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    if (y == 1).sum() < 5 or (y == 0).sum() < 5:
        return X, y
    pos = max(int((y == 0).sum() * 0.3), int((y == 1).sum()))
    target = max(int((y == 0).sum() * 0.5), int((y == 1).sum()))
    target = max(target, pos)
    try:
        from imblearn.over_sampling import SMOTE
        sm = SMOTE(sampling_strategy={1: target},
                   random_state=random_state, k_neighbors=2)
        X, y = sm.fit_resample(X, y)
    except Exception:
        pass
    return X, y


def _metrics(y_true: np.ndarray, y_pred: np.ndarray,
             y_score: np.ndarray | None = None) -> dict:
    out = {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "n": int(len(y_true)),
        "n_positive": int(y_true.sum()),
    }
    if y_score is not None and len(set(y_true.tolist())) > 1:
        try:
            out["roc_auc"] = float(roc_auc_score(y_true, y_score))
        except Exception:
            pass
    return out


def _fit_one(name: str,
             build,
             X_tr: np.ndarray, y_tr: np.ndarray,
             X_te: np.ndarray, y_te: np.ndarray,
             scaler: StandardScaler,
             notes: str = "") -> ModelBundle:
    model = build()
    model.fit(X_tr, y_tr)
    if hasattr(model, "predict_proba"):
        score = model.predict_proba(X_te)[:, 1]
    elif hasattr(model, "decision_function"):
        score = model.decision_function(X_te)
        score = (score - score.min()) / (score.max() - score.min() + 1e-9)
    else:
        score = model.predict(X_te).astype(float)
    pred = (score >= 0.5).astype(int)
    metrics = _metrics(y_te, pred, score)
    return ModelBundle(
        name=name,
        model=model,
        scaler=scaler,
        feature_columns=list(FEATURE_COLUMNS),
        metrics=metrics,
        created_at=datetime.now().isoformat(),
        notes=notes,
    )


def _isolation_forest(X_tr: np.ndarray, y_tr: np.ndarray,
                      X_te: np.ndarray, y_te: np.ndarray,
                      scaler: StandardScaler) -> ModelBundle:
    if_contamination = max(0.01, min(0.5, float(y_tr.mean() or 0.1)))
    iso = IsolationForest(
        n_estimators=200, contamination=if_contamination,
        random_state=42, n_jobs=1,
    )
    iso.fit(X_tr)
    raw = -iso.score_samples(X_te)
    raw = (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
    pred = (raw >= 0.5).astype(int)
    metrics = _metrics(y_te, pred, raw)
    return ModelBundle(
        name="isolation_forest",
        model=iso,
        scaler=scaler,
        feature_columns=list(FEATURE_COLUMNS),
        metrics=metrics,
        created_at=datetime.now().isoformat(),
        notes=f"unsupervised; contamination={if_contamination:.3f}",
    )


def train_models(features: pd.DataFrame,
                 test_size: float = 0.25,
                 random_state: int = 42,
                 save: bool = True) -> List[ModelBundle]:
    """Train RF, XGBoost (if installed) and IsolationForest.

    Returns a list of ``ModelBundle`` objects; the best by F1 is also
    persisted to ``models/artifacts/``.
    """
    X, y, ips = _stack(features)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state,
        stratify=y if y.sum() and len(set(y)) > 1 else None,
    )

    scaler = StandardScaler().fit(X_train)
    X_tr = scaler.transform(X_train)
    X_te = scaler.transform(X_test)

    X_tr_bal, y_tr_bal = _maybe_apply_smote(X_tr, y_train)

    bundles: List[ModelBundle] = []
    bundles.append(_fit_one(
        "random_forest",
        lambda: RandomForestClassifier(
            n_estimators=300, max_depth=12,
            random_state=random_state, n_jobs=1, class_weight="balanced"),
        X_tr_bal, y_tr_bal, X_te, y_test, scaler,
        notes="class_weight=balanced",
    ))

    if HAS_XGB:
        bundles.append(_fit_one(
            "xgboost",
            lambda: XGBClassifier(
                n_estimators=300, max_depth=6, learning_rate=0.08,
                subsample=0.9, colsample_bytree=0.9,
                eval_metric="logloss", random_state=random_state,
                n_jobs=1, scale_pos_weight=max(1.0, (y_tr_bal == 0).sum() /
                                               max(1, (y_tr_bal == 1).sum())),
            ),
            X_tr_bal, y_tr_bal, X_te, y_test, scaler,
            notes="xgb with scale_pos_weight",
        ))

    bundles.append(_isolation_forest(X_tr_bal, y_tr_bal, X_te, y_test, scaler))

    if save:
        best = max(bundles, key=lambda b: b.metrics.get("f1", 0))
        stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        model_path = ARTIFACT_DIR / f"{best.name}_{stamp}.joblib"
        meta_path = ARTIFACT_DIR / f"{best.name}_{stamp}.meta.json"
        joblib.dump(
            {
                "name": best.name,
                "model": best.model,
                "scaler": best.scaler,
                "feature_columns": best.feature_columns,
                "metrics": best.metrics,
                "created_at": best.created_at,
                "notes": best.notes,
            },
            model_path,
        )
        meta_path.write_text(json.dumps({
            "name": best.name, "metrics": best.metrics,
            "feature_columns": best.feature_columns,
            "created_at": best.created_at, "notes": best.notes,
            "artifact_path": str(model_path),
        }, indent=2))
        # also write a stable "latest"
        latest_model = ARTIFACT_DIR / "latest.joblib"
        latest_meta = ARTIFACT_DIR / "latest.meta.json"
        if latest_model.exists():
            latest_model.unlink()
        if latest_meta.exists():
            latest_meta.unlink()
        latest_model.write_bytes(model_path.read_bytes())
        latest_meta.write_text(meta_path.read_text())

    return bundles
