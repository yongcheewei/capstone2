from __future__ import annotations

from typing import List, Optional

import pandas as pd

from ._types import (
    Detection,
    RuleConfig,
    detections_to_df,
    ensure_events_df,
)
from .static_threshold import static_threshold_detect
from .adaptive_threshold import adaptive_threshold_detect
from .hybrid_rules import hybrid_rule_detect


def run_rules(events,
              config: Optional[RuleConfig] = None,
              include: Optional[List[str]] = None) -> pd.DataFrame:
    """Run the requested rule set and return a DataFrame of detections.

    Parameters
    ----------
    events : DataFrame or iterable of dicts
    config : RuleConfig, optional
        Defaults to :class:`RuleConfig`.
    include : list of str, optional
        Subset of ``{"static", "adaptive", "hybrid"}``. Defaults to all.
    """
    cfg = config or RuleConfig()
    df = ensure_events_df(events)
    if df.empty:
        return detections_to_df([])

    include = include or ["static", "adaptive", "hybrid"]
    all_dets: List[Detection] = []
    if "static" in include:
        all_dets.extend(static_threshold_detect(df, cfg))
    if "adaptive" in include:
        all_dets.extend(adaptive_threshold_detect(df, cfg))
    if "hybrid" in include:
        all_dets.extend(hybrid_rule_detect(df, cfg, detections_so_far=all_dets))
    return detections_to_df(all_dets)
