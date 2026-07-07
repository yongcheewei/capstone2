from __future__ import annotations

from collections import Counter
from math import log2
from typing import List

import numpy as np
import pandas as pd

from ..rules.static_threshold import FAILURE_TYPES

FEATURE_COLUMNS: List[str] = [
    "failed_total",
    "accepted_total",
    "failure_to_success_ratio",
    "failures_per_minute",
    "unique_users_targeted",
    "invalid_user_attempts",
    "invalid_user_ratio",
    "unique_ports",
    "active_minutes",
    "attempts_per_minute",
    "username_entropy",
    "is_internal_ip",
    "first_attempt_hour",
    "rapid_attempts_burst",
]


def _is_internal(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except (ValueError, ImportError):
            return False
    try:
        first = int(parts[0])
        second = int(parts[1])
    except ValueError:
        return False
    if first == 10:
        return True
    if first == 192 and second == 168:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 127:
        return True
    return False


def _entropy(series: pd.Series) -> float:
    if series.empty:
        return 0.0
    counts = Counter(series.dropna())
    total = sum(counts.values())
    if total == 0:
        return 0.0
    e = 0.0
    for c in counts.values():
        p = c / total
        e -= p * log2(p)
    return e


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate an events DataFrame into per-IP feature rows.

    The DataFrame must have at least ``timestamp``, ``ip``, ``user``,
    ``event_type`` and ``invalid_user``. Output is one row per IP.
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "ip"])
    df["event_type"] = df["event_type"].fillna("")

    out_rows = []
    for ip, g in df.groupby("ip"):
        g = g.sort_values("timestamp").reset_index(drop=True)
        failed = g[g["event_type"].isin(FAILURE_TYPES)]
        accepted = g[g["event_type"] == "accepted_password"]
        invalid_user = g[g["invalid_user"] == True]  # noqa: E712

        ts = g["timestamp"]
        span_min = max(1.0, (ts.max() - ts.min()).total_seconds() / 60.0)

        usernames = g["user"].dropna()
        user_counts = usernames.value_counts() if not usernames.empty else \
            pd.Series(dtype=int)

        bursts = (ts.diff().dt.total_seconds().fillna(9999) < 1.0).sum()

        ports = pd.to_numeric(g.get("port", pd.Series(dtype=float)),
                              errors="coerce").dropna()

        attempts_per_minute = len(g) / span_min
        failures_per_minute = len(failed) / span_min
        ratio = (len(failed) / len(accepted)) if len(accepted) else float(len(failed))

        out_rows.append({
            "ip": ip,
            "failed_total": int(len(failed)),
            "accepted_total": int(len(accepted)),
            "failure_to_success_ratio": float(ratio),
            "failures_per_minute": float(failures_per_minute),
            "unique_users_targeted": int(usernames.nunique()),
            "invalid_user_attempts": int(len(invalid_user)),
            "invalid_user_ratio":
                float(len(invalid_user) / max(1, len(failed))),
            "unique_ports": int(ports.nunique()) if not ports.empty else 0,
            "active_minutes": float(span_min),
            "attempts_per_minute": float(attempts_per_minute),
            "username_entropy": float(_entropy(usernames)),
            "is_internal_ip": int(_is_internal(ip)),
            "first_attempt_hour": int(ts.min().hour),
            "rapid_attempts_burst": int(bursts),
        })

    return pd.DataFrame(out_rows)


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Convenience wrapper that orders columns consistently."""
    feats = build_features(df)
    if feats.empty:
        return pd.DataFrame(columns=["ip", *FEATURE_COLUMNS])
    feats = feats.set_index("ip")
    for col in FEATURE_COLUMNS:
        if col not in feats.columns:
            feats[col] = 0
    feats = feats[FEATURE_COLUMNS]
    return feats.reset_index()
