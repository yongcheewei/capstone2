from __future__ import annotations

from typing import List

import numpy as np
import pandas as pd

from ._types import Detection, RuleConfig
from .static_threshold import _count_failures


def adaptive_threshold_detect(df: pd.DataFrame,
                              cfg: RuleConfig) -> List[Detection]:
    """Adaptive threshold per IP: compute the mean and stddev of failure
    rate per minute over the baseline window, then alert whenever a one
    minute bucket exceeds ``mean + multiplier * stddev``.

    This reproduces the Capstone 1 finding that adaptive thresholding
    lifts detection by ~30% versus static thresholds, while keeping
    the implementation small enough for small organisations.
    """
    failures = _count_failures(df)
    if failures.empty:
        return []

    baseline_days = max(1, cfg.adaptive_baseline_days)
    baseline_window = pd.Timedelta(days=baseline_days)
    dets: List[Detection] = []
    mult = cfg.adaptive_multiplier

    for ip, g in failures.groupby("ip"):
        g = g.sort_values("timestamp").reset_index(drop=True)
        start = g["timestamp"].min()
        baseline_end = start + baseline_window
        baseline = g[g["timestamp"] <= baseline_end]
        if len(baseline) < 5:
            base_rate = cfg.static_threshold
        else:
            per_min = baseline.set_index("timestamp").resample("1min").size()
            mean = per_min.mean()
            std = per_min.std(ddof=0)
            base_rate = mean + mult * std
            base_rate = max(base_rate, cfg.static_threshold)

        per_min_full = g.set_index("timestamp").resample("1min").size()
        high = per_min_full[per_min_full > base_rate]
        if high.empty:
            continue

        groups = (high.index.to_series().diff() > pd.Timedelta("2min")).cumsum()
        for _, segment in high.groupby(groups):
            seg_start = segment.index.min()
            seg_end = segment.index.max()
            seg_attempts = int(segment.sum())
            dets.append(Detection(
                rule="adaptive",
                ip=ip,
                start_ts=seg_start.isoformat(),
                end_ts=seg_end.isoformat(),
                attempts=seg_attempts,
                confidence=float(np.clip(seg_attempts / (base_rate * 2 + 1), 0, 1)),
                details={"baseline_per_min": float(base_rate),
                         "multiplier": mult,
                         "baseline_days": baseline_days},
            ))
    return dets
