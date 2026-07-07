from __future__ import annotations

import time
from typing import Callable, Iterable

import numpy as np
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)


def compute_metrics(y_true: Iterable[int],
                    y_pred: Iterable[int],
                    y_score: Iterable[float] | None = None
                    ) -> dict:
    """Return a dict with precision/recall/F1/accuracy/ROC-AUC + CM."""
    y_true = np.asarray(list(y_true), dtype=int)
    y_pred = np.asarray(list(y_pred), dtype=int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    out = {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
        "fn": int(cm[1, 0]), "tp": int(cm[1, 1]),
        "n": int(len(y_true)),
        "n_positive": int(y_true.sum()),
    }
    if y_score is not None:
        y_score = np.asarray(list(y_score), dtype=float)
        if len(set(y_true.tolist())) > 1:
            try:
                out["roc_auc"] = float(roc_auc_score(y_true, y_score))
            except Exception:
                pass
    return out


def latency_per_event(fn: Callable, events: Iterable, warmup: int = 5) -> float:
    """Return mean milliseconds per event for ``fn(events)``."""
    items = list(events)
    for _ in range(warmup):
        fn(items)
    start = time.perf_counter()
    fn(items)
    elapsed = (time.perf_counter() - start) * 1000.0
    return elapsed / max(1, len(items))
