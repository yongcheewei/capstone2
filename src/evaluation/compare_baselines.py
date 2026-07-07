from __future__ import annotations

from typing import Dict, List

import numpy as np
import pandas as pd

from ..hybrid.fusion import FusionConfig, fuse, hybrid_score, rule_score_from_detections
from ..rules.engine import RuleConfig, ensure_events_df, run_rules
from ..features.build_features import build_feature_matrix
from .metrics import compute_metrics, latency_per_event


def _per_ip_rule_decision(detections: pd.DataFrame) -> pd.Series:
    if detections is None or detections.empty:
        return pd.Series(dtype=int)
    rule_per_ip = (detections.groupby(["ip", "rule"])["confidence"].max()
                  .reset_index()
                  .groupby("ip")["confidence"].max())
    return (rule_per_ip >= 0.5).astype(int)


def compare_baselines(events: pd.DataFrame,
                      features: pd.DataFrame,
                      ml_scores_by_model: Dict[str, pd.Series],
                      ground_truth_ips: List[str],
                      rule_cfg: RuleConfig | None = None,
                      fusion_cfg: FusionConfig | None = None,
                      latency_samples: int | None = None
                      ) -> pd.DataFrame:
    """Run all baselines and return a comparison DataFrame.

    Baselines produced
    ------------------
    1. Static rule only
    2. Adaptive rule only
    3. Hybrid rule set (static + adaptive + contextual)
    4. ML only (one row per supplied model)
    5. Hybrid (rule + ML) - one row per supplied model
    """
    rule_cfg = rule_cfg or RuleConfig()
    fusion_cfg = fusion_cfg or FusionConfig()

    feats = build_feature_matrix(events)
    if "ip" in feats.columns:
        feats = feats.set_index("ip")

    gt = set(str(x) for x in ground_truth_ips)
    ips = feats.index.astype(str).tolist()
    y_true = np.array([1 if ip in gt else 0 for ip in ips])

    rows = []

    static_dets = run_rules(events, rule_cfg, include=["static"])
    static_dec = _per_ip_rule_decision(static_dets)
    y_pred_static = np.array([int(static_dec.get(ip, 0)) for ip in ips])
    rows.append({
        "system": "static_rule",
        **compute_metrics(y_true, y_pred_static),
        "latency_ms_per_event": latency_per_event(
            lambda ev: run_rules(ev, rule_cfg, include=["static"]),
            [ensure_events_df(events).to_dict("records")],
        ) if latency_samples else 0.0,
    })

    adaptive_dets = run_rules(events, rule_cfg, include=["adaptive"])
    adaptive_dec = _per_ip_rule_decision(adaptive_dets)
    y_pred_adapt = np.array([int(adaptive_dec.get(ip, 0)) for ip in ips])
    rows.append({
        "system": "adaptive_rule",
        **compute_metrics(y_true, y_pred_adapt),
        "latency_ms_per_event": latency_per_event(
            lambda ev: run_rules(ev, rule_cfg, include=["adaptive"]),
            [ensure_events_df(events).to_dict("records")],
        ) if latency_samples else 0.0,
    })

    hybrid_dets = run_rules(events, rule_cfg)
    hybrid_dec = _per_ip_rule_decision(hybrid_dets)
    y_pred_hybrid_rule = np.array([int(hybrid_dec.get(ip, 0)) for ip in ips])
    rows.append({
        "system": "hybrid_rule_only",
        **compute_metrics(y_true, y_pred_hybrid_rule),
        "latency_ms_per_event": latency_per_event(
            lambda ev: run_rules(ev, rule_cfg),
            [ensure_events_df(events).to_dict("records")],
        ) if latency_samples else 0.0,
    })

    for model_name, ml_scores in ml_scores_by_model.items():
        if isinstance(ml_scores, pd.Series):
            ms = ml_scores.reindex(ips).fillna(0.0).to_numpy()
        else:
            ms = np.asarray(ml_scores, dtype=float)
        y_pred_ml = (ms >= 0.5).astype(int)
        rows.append({
            "system": f"ml_only_{model_name}",
            **compute_metrics(y_true, y_pred_ml, ms),
            "latency_ms_per_event": 0.0,
        })

        rule_df = rule_score_from_detections(hybrid_dets)
        rule_df = rule_df.set_index("ip").reindex(ips).fillna(0).reset_index()
        ml_df = pd.DataFrame({"ip": ips, "ml_score": ms})
        fused = hybrid_score(rule_df, ml_df, fusion_cfg)
        fused_index = fused.set_index("ip")["final_decision"].reindex(ips).fillna(0)
        y_pred_hybrid = fused_index.astype(int).to_numpy()
        rows.append({
            "system": f"hybrid_{model_name}",
            **compute_metrics(y_true, y_pred_hybrid,
                              fused.set_index("ip")["final_score"].reindex(ips).fillna(0).to_numpy()),
            "latency_ms_per_event": 0.0,
        })

    return pd.DataFrame(rows)
