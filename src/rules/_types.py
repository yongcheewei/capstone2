from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Union

import pandas as pd


@dataclass
class RuleConfig:
    """Tunable parameters for the rule engine."""

    static_window_seconds: int = 60
    static_threshold: int = 5
    adaptive_baseline_days: int = 7
    adaptive_multiplier: float = 3.0
    hybrid_min_users_targeted: int = 5
    hybrid_max_avg_attempts_per_user: float = 2.0


@dataclass
class Detection:
    """One alert produced by a rule."""

    rule: str
    ip: str
    start_ts: str
    end_ts: str
    attempts: int
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def ensure_events_df(events: Union[pd.DataFrame, list]) -> pd.DataFrame:
    if isinstance(events, pd.DataFrame):
        df = events.copy()
    else:
        df = pd.DataFrame(list(events))
    if "timestamp" not in df.columns:
        raise ValueError("events must include a 'timestamp' column")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "ip"])
    if "invalid_user" not in df.columns:
        df["invalid_user"] = False
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def detections_to_df(detections: List[Detection]) -> pd.DataFrame:
    records = [d.as_dict() for d in detections]
    if not records:
        return pd.DataFrame(
            columns=["rule", "ip", "start_ts", "end_ts", "attempts",
                     "confidence", "details"]
        )
    return pd.DataFrame(records)
