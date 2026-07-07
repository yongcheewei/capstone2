from __future__ import annotations

from typing import Optional

import numpy as np
import pandas as pd

from ..rules.engine import run_rules, RuleConfig
from .build_features import build_feature_matrix


def label_via_rules(features: pd.DataFrame,
                    events: pd.DataFrame,
                    cfg: Optional[RuleConfig] = None,
                    min_confidence: float = 0.4) -> pd.DataFrame:
    """Bootstrap labels for ML training using the rule engine.

    Any IP that generated a rule detection above ``min_confidence`` is
    labelled as an attack (1); everything else is 0.

    Useful for self-supervised warm-start when no labelled dataset is
    available, then iteratively refined with human review.
    """
    feats = features.copy()
    detections = run_rules(events, cfg or RuleConfig())
    flagged = detections[detections["confidence"] >= min_confidence]
    flagged_ips = set(flagged["ip"].astype(str).tolist())
    feats["label"] = feats["ip"].astype(str).isin(flagged_ips).astype(int)
    return feats


def label_from_groundtruth(features: pd.DataFrame,
                           groundtruth_ips: list[str]) -> pd.DataFrame:
    feats = features.copy()
    gt = set(groundtruth_ips)
    feats["label"] = feats["ip"].astype(str).isin(gt).astype(int)
    return feats
