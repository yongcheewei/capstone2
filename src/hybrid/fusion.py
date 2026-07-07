from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional

import numpy as np
import pandas as pd


@dataclass
class FusionConfig:
    """Configuration for rule + ML fusion.

    Decision logic
    -------------
    1. If ``rule_score >= rule_block_threshold`` -> block (attack).
    2. Else if ``ml_score >= ml_block_threshold`` -> block.
    3. Else if both signals are below their ``*_allow_threshold`` -> allow.
    4. Otherwise, final score = alpha * rule + (1 - alpha) * ml.
       If final score >= decision_threshold -> block.
    """

    alpha: float = 0.5
    rule_block_threshold: float = 0.85
    rule_allow_threshold: float = 0.1
    ml_block_threshold: float = 0.7
    ml_allow_threshold: float = 0.2
    decision_threshold: float = 0.5
    aggregating: str = "max"


def rule_score_from_detections(detections: pd.DataFrame,
                               aggregating: str = "max") -> pd.DataFrame:
    """Aggregate per-IP detections into a single ``rule_score`` row per IP.

    Returns a DataFrame with columns ``ip`` and ``rule_score`` (0..1)
    plus the number of distinct rules that fired.
    """
    if detections is None or detections.empty:
        return pd.DataFrame(columns=["ip", "rule_score", "rules_fired"])
    df = detections.copy()
    df["ip"] = df["ip"].astype(str)
    if aggregating == "max":
        agg = df.groupby("ip")["confidence"].max()
    elif aggregating == "mean":
        agg = df.groupby("ip")["confidence"].mean()
    else:
        agg = df.groupby("ip")["confidence"].max()
    counts = df.groupby("ip")["rule"].nunique()
    out = pd.DataFrame({"ip": agg.index.astype(str),
                        "rule_score": agg.values,
                        "rules_fired": counts.reindex(agg.index).fillna(0).astype(int).values})
    return out


def hybrid_score(rule_df: pd.DataFrame,
                 ml_df: pd.DataFrame,
                 cfg: Optional[FusionConfig] = None) -> pd.DataFrame:
    """Compute per-IP final decision given rule scores and ML scores.

    Parameters
    ----------
    rule_df : DataFrame
        Must have columns ``ip`` and ``rule_score``.
    ml_df : DataFrame
        Must have columns ``ip`` and ``ml_score``.
    """
    cfg = cfg or FusionConfig()

    if rule_df is None or rule_df.empty:
        rule_df = pd.DataFrame(columns=["ip", "rule_score", "rules_fired"])
    rule_df = rule_df.copy()
    if "rules_fired" not in rule_df.columns:
        rule_df["rules_fired"] = 0

    if ml_df is None or ml_df.empty:
        ml_df = pd.DataFrame(columns=["ip", "ml_score"])

    rule_df["ip"] = rule_df["ip"].astype(str)
    ml_df["ip"] = ml_df["ip"].astype(str)

    merged = pd.merge(rule_df, ml_df, on="ip", how="outer").fillna(0)

    block = np.zeros(len(merged), dtype=int)
    final_score = np.full(len(merged), np.nan)

    rule_block = merged["rule_score"].to_numpy() >= cfg.rule_block_threshold
    rule_allow = merged["rule_score"].to_numpy() <= cfg.rule_allow_threshold
    ml_block = merged["ml_score"].to_numpy() >= cfg.ml_block_threshold
    ml_allow = merged["ml_score"].to_numpy() <= cfg.ml_allow_threshold

    block |= rule_block | ml_block
    block &= ~((rule_allow & ml_allow))

    combined = cfg.alpha * merged["rule_score"].to_numpy() + \
        (1.0 - cfg.alpha) * merged["ml_score"].to_numpy()
    final_score = np.where(np.isnan(final_score), combined, final_score)

    decision = np.where(
        block == 1, 1,
        np.where(final_score >= cfg.decision_threshold, 1, 0),
    )

    merged["final_score"] = final_score
    merged["final_decision"] = decision.astype(int)
    return merged.sort_values("final_score", ascending=False).reset_index(drop=True)


def fuse(detections: pd.DataFrame,
         ml_scores: pd.Series,
         features: pd.DataFrame,
         cfg: Optional[FusionConfig] = None) -> pd.DataFrame:
    """High-level convenience wrapper.

    Parameters
    ----------
    detections : DataFrame
        Per-IP alerts from the rule engine.
    ml_scores : Series
        Index = ip (str), values = probability of attack.
    features : DataFrame
        The feature matrix produced by ``build_feature_matrix``.
    """
    cfg = cfg or FusionConfig()
    rule_df = rule_score_from_detections(detections, cfg.aggregating)
    if isinstance(ml_scores, pd.Series):
        ml_df = ml_scores.reset_index()
        ml_df.columns = ["ip", "ml_score"]
    elif isinstance(ml_scores, pd.DataFrame):
        ml_df = ml_scores.rename(columns={ml_scores.columns[-1]: "ml_score"})
    else:
        ml_df = pd.DataFrame(ml_scores, columns=["ml_score"])
        ml_df["ip"] = features["ip"].astype(str).tolist() \
            if "ip" in features.columns else [str(i) for i in range(len(ml_df))]

    feats = features.copy()
    if "ip" in feats.columns:
        feats = feats.set_index("ip")
    feats = feats.reindex(ml_df["ip"].astype(str))
    return hybrid_score(rule_df, ml_df, cfg)
