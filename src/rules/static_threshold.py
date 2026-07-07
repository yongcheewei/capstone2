from __future__ import annotations

from typing import List

import pandas as pd

from ._types import Detection, RuleConfig

FAILURE_TYPES = {"failed_password", "invalid_user", "pam_auth_failure"}


def _count_failures(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["event_type"].isin(FAILURE_TYPES)].copy()


def static_threshold_detect(df: pd.DataFrame,
                            cfg: RuleConfig) -> List[Detection]:
    """Pure static rule: > ``static_threshold`` failures from a single IP
    inside any rolling ``static_window_seconds`` window.

    This is intentionally simple - it matches the static baseline
    described in the Capstone 1 abstract as the lower bound for the
    performance comparison.
    """
    failures = _count_failures(df)
    if failures.empty:
        return []

    dets: List[Detection] = []
    window = pd.Timedelta(seconds=cfg.static_window_seconds)
    thresh = cfg.static_threshold

    for ip, g in failures.groupby("ip"):
        g = g.sort_values("timestamp").reset_index(drop=True)
        n = len(g)
        i = 0
        while i < n:
            j = i
            while j < n and g.iloc[j]["timestamp"] - g.iloc[i]["timestamp"] <= window:
                j += 1
            count = j - i
            if count >= thresh:
                dets.append(Detection(
                    rule="static",
                    ip=ip,
                    start_ts=g.iloc[i]["timestamp"].isoformat(),
                    end_ts=g.iloc[j - 1]["timestamp"].isoformat(),
                    attempts=int(count),
                    confidence=min(1.0, count / (thresh * 2)),
                    details={"window_seconds": cfg.static_window_seconds,
                             "threshold": thresh},
                ))
                i = j
            else:
                i += 1
    return dets
