from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

import numpy as np
import pandas as pd

FIGURE_DIR = Path(__file__).resolve().parents[3] / "report" / "figures"
FIGURE_DIR.mkdir(parents=True, exist_ok=True)


def _save(fig, fname: str) -> str:
    out = FIGURE_DIR / fname
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    import matplotlib.pyplot as plt
    plt.close(fig)
    return str(out)


def plot_confusion(y_true: Sequence[int], y_pred: Sequence[int],
                   title: str = "Confusion matrix",
                   fname: str = "confusion.png"):
    import matplotlib.pyplot as plt
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(4, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["benign", "attack"]); ax.set_yticklabels(["benign", "attack"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, int(v), ha="center", va="center",
                color="white" if v > cm.max() / 2 else "black")
    ax.set_title(title)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    return _save(fig, fname)


def plot_roc(y_true: Sequence[int], y_score: Sequence[float],
             title: str = "ROC curve",
             fname: str = "roc.png"):
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, auc
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.plot(fpr, tpr, label=f"AUC={roc_auc:.3f}")
    ax.plot([0, 1], [0, 1], "--", color="grey")
    ax.set_xlabel("False positive rate"); ax.set_ylabel("True positive rate")
    ax.set_title(title); ax.legend(loc="lower right")
    return _save(fig, fname)


def plot_score_dist(scores_by_group: dict, title: str = "Score distribution",
                    fname: str = "score_dist.png"):
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(5, 3))
    for label, scores in scores_by_group.items():
        ax.hist(np.asarray(scores), bins=30, alpha=0.5, label=label)
    ax.set_xlabel("score"); ax.set_ylabel("count")
    ax.set_title(title); ax.legend()
    return _save(fig, fname)
