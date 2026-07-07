"""End-to-end pipeline: parse -> rule -> features -> train -> evaluate -> fuse.

Usage:
    python scripts/run_pipeline.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from io import StringIO
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.parser import parse_file
from src.rules import RuleConfig, run_rules
from src.features import build_feature_matrix
from src.features.label import label_via_rules
from src.models import train_models, load_latest_artifact, predict_proba, ARTIFACT_DIR
from src.hybrid import FusionConfig, hybrid_score, rule_score_from_detections
from src.evaluation.compare_baselines import compare_baselines


SAMPLE_LOG = ROOT / "data" / "processed" / "sample_auth.log"
GT_FILE = ROOT / "data" / "processed" / "groundtruth_ips.txt"


def ensure_sample_log() -> Path:
    if not SAMPLE_LOG.exists():
        print(f"[run_pipeline] generating sample log at {SAMPLE_LOG}")
        from scripts.generate_sample_log import generate
        generate(SAMPLE_LOG)
    return SAMPLE_LOG


def ensure_groundtruth() -> list[str]:
    if not GT_FILE.exists():
        attacker_ip = "1.2.3.4"
        second = "5.5.5.5"
        GT_FILE.parent.mkdir(parents=True, exist_ok=True)
        GT_FILE.write_text(attacker_ip + "\n" + second + "\n", encoding="utf-8")
    return [ln.strip() for ln in GT_FILE.read_text().splitlines() if ln.strip()]


def parse_to_df(log_path: Path) -> pd.DataFrame:
    events = parse_file(log_path)
    df = pd.DataFrame([e.as_dict() for e in events])
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "ip"])
    return df


def main() -> None:
    log_path = ensure_sample_log()
    gt_ips = ensure_groundtruth()

    print(f"[run_pipeline] parsing {log_path}")
    df = parse_to_df(log_path)
    print(f"[run_pipeline] {len(df):,} events parsed")

    cfg = RuleConfig()
    detections = run_rules(df, cfg)
    det_path = ROOT / "report" / "figures" / "rule_detections.csv"
    det_path.parent.mkdir(parents=True, exist_ok=True)
    detections.to_csv(det_path, index=False)
    print(f"[run_pipeline] {len(detections)} rule detections saved to {det_path}")

    feats = build_feature_matrix(df)
    labelled = label_via_rules(feats, df, cfg, min_confidence=0.4)
    feats_path = ROOT / "report" / "figures" / "features.csv"
    labelled.to_csv(feats_path, index=False)
    print(f"[run_pipeline] features saved to {feats_path} "
          f"({labelled['label'].sum()} attack / {(labelled['label'] == 0).sum()} benign)")

    print("[run_pipeline] training ML models")
    bundles = train_models(labelled)
    for b in bundles:
        print(f"   - {b.name}: {b.metrics}")

    ips = labelled["ip"].astype(str).tolist()
    ml_scores_by_name: dict[str, pd.Series] = {}
    for b in bundles:
        scores = predict_proba(b, labelled.drop(columns=["label"]))
        scores.index = scores.index.astype(str)
        ml_scores_by_name[b.name] = scores.reindex(ips).fillna(0.0)

    print("[run_pipeline] comparing baselines")
    comparison = compare_baselines(
        events=df,
        features=labelled.drop(columns=["label"]),
        ml_scores_by_model=ml_scores_by_name,
        ground_truth_ips=gt_ips,
        rule_cfg=cfg,
    )
    comp_path = ROOT / "report" / "figures" / "baseline_comparison.csv"
    comparison.to_csv(comp_path, index=False)
    print(f"[run_pipeline] baseline comparison saved to {comp_path}")
    print(comparison.to_string(index=False))

    print("[run_pipeline] generating summary figures")
    from src.evaluation.plots import (
        plot_confusion, plot_roc, plot_score_dist,
    )
    rule_dec = (rule_score_from_detections(detections)
                .set_index("ip")["rule_score"].reindex(ips).fillna(0).to_numpy())
    y_true = np.array([1 if ip in set(gt_ips) else 0 for ip in ips])

    plot_confusion(y_true, (rule_dec >= 0.5).astype(int),
                   title="Rule-only confusion", fname="cm_rule.png")
    rf_scores = ml_scores_by_name.get("random_forest", pd.Series(dtype=float))
    if not rf_scores.empty:
        plot_roc(y_true, rf_scores.reindex(ips).fillna(0).to_numpy(),
                 title="ML (RF) ROC", fname="roc_ml.png")
        ml_only = rf_scores.reindex(ips).fillna(0).to_numpy()
        plot_confusion(y_true, (ml_only >= 0.5).astype(int),
                       title="ML (RF) confusion", fname="cm_ml.png")

        fused = hybrid_score(
            rule_score_from_detections(detections),
            rf_scores.reset_index().rename(columns={0: "ml_score"}),
            FusionConfig(),
        )
        fused_scores = fused.set_index("ip")["final_score"].reindex(ips).fillna(0).to_numpy()
        plot_roc(y_true, fused_scores,
                 title="Hybrid (rule+RF) ROC", fname="roc_hybrid.png")
        plot_score_dist(
            {"benign_y_true_0": fused_scores[y_true == 0],
             "attack_y_true_1": fused_scores[y_true == 1]},
            title="Hybrid score distribution",
            fname="score_dist_hybrid.png",
        )

    summary = {
        "events": int(len(df)),
        "distinct_ips": int(df["ip"].nunique()),
        "rule_detections": int(len(detections)),
        "models_trained": [b.name for b in bundles],
        "best_f1_by_system": comparison.set_index("system")["f1"].to_dict(),
        "artifact_dir": str(ARTIFACT_DIR),
        "timestamp": datetime.now().isoformat(),
    }
    out = ROOT / "report" / "figures" / "pipeline_summary.json"
    out.write_text(json.dumps(summary, indent=2))
    print(f"[run_pipeline] summary written to {out}")


if __name__ == "__main__":
    main()
