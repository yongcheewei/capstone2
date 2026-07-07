from __future__ import annotations

from typing import List

import pandas as pd

from ._types import Detection, RuleConfig
from .static_threshold import _count_failures, FAILURE_TYPES


def _contextual_alerts(failures: pd.DataFrame, cfg: RuleConfig) -> List[Detection]:
    """Contextual rules: invalid-user floods, user-spray patterns, and
    low port consistency (suggests scripted attacks)."""
    dets: List[Detection] = []
    for ip, g in failures.groupby("ip"):
        g = g.sort_values("timestamp").reset_index(drop=True)

        invalid = g[g["invalid_user"] == True]  # noqa: E712
        if len(invalid) >= 3:
            dets.append(Detection(
                rule="contextual_invalid_user_flood",
                ip=ip,
                start_ts=invalid["timestamp"].min().isoformat(),
                end_ts=invalid["timestamp"].max().isoformat(),
                attempts=int(len(invalid)),
                confidence=min(1.0, len(invalid) / 10.0),
                details={"invalid_attempts": int(len(invalid))},
            ))

        unique_users = g["user"].dropna().nunique()
        if unique_users >= cfg.hybrid_min_users_targeted:
            avg_attempts_per_user = len(g) / unique_users
            if avg_attempts_per_user <= cfg.hybrid_max_avg_attempts_per_user:
                dets.append(Detection(
                    rule="contextual_user_spray",
                    ip=ip,
                    start_ts=g["timestamp"].min().isoformat(),
                    end_ts=g["timestamp"].max().isoformat(),
                    attempts=int(len(g)),
                    confidence=min(1.0, unique_users / 20.0),
                    details={"unique_users": int(unique_users),
                             "avg_attempts_per_user":
                                 float(avg_attempts_per_user)},
                ))

        if "port" in g.columns and g["port"].notna().sum() > 5:
            ports = g["port"].dropna().astype(int)
            span = ports.max() - ports.min()
            if span < 50:
                dets.append(Detection(
                    rule="contextual_low_port_diversity",
                    ip=ip,
                    start_ts=g["timestamp"].min().isoformat(),
                    end_ts=g["timestamp"].max().isoformat(),
                    attempts=int(len(g)),
                    confidence=0.6,
                    details={"port_min": int(ports.min()),
                             "port_max": int(ports.max()),
                             "span": int(span)},
                ))
    return dets


def hybrid_rule_detect(df: pd.DataFrame,
                       cfg: RuleConfig,
                       detections_so_far: List[Detection] | None = None
                       ) -> List[Detection]:
    """Combine threshold-based detections with contextual rules.

    Passing ``detections_so_far`` de-duplicates: if a static / adaptive
    detection already covers an IP close in time we suppress a weaker
    contextual alert for the same IP and overlapping window.
    """
    failures = _count_failures(df)
    if failures.empty:
        return []

    contextual = _contextual_alerts(failures, cfg)

    if not detections_so_far:
        return contextual

    seen_keys = {(d.ip, d.start_ts[:16]) for d in detections_so_far}
    out: List[Detection] = []
    for c in contextual:
        k = (c.ip, c.start_ts[:16])
        if k in seen_keys and c.confidence < 0.7:
            continue
        out.append(c)
        seen_keys.add(k)
    return out
