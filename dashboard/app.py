"""Streamlit demo dashboard for the hybrid SSH brute-force detector.

Run with:
    streamlit run dashboard/app.py
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT))

from src.parser import parse_file
from src.rules import RuleConfig, run_rules
from src.features import build_feature_matrix
from src.hybrid import FusionConfig, rule_score_from_detections, hybrid_score
from src.models import load_latest_artifact, predict_proba

st.set_page_config(page_title="SSH Brute-Force Hybrid Detector",
                   layout="wide")
st.title("SSH Brute-Force Hybrid Detector — Capstone 2 demo")
st.write(
    "Upload a Linux `auth.log` (or use the bundled sample), run the rule "
    "engine and ML model, then inspect the fused decision per source IP."
)

with st.sidebar:
    st.header("Settings")
    static_window = st.slider("Static window (s)", 10, 600, 60, 5)
    static_thresh = st.slider("Static threshold", 2, 50, 5, 1)
    adapt_mult = st.slider("Adaptive multiplier (k)", 1.0, 6.0, 3.0, 0.1)
    rule_alpha = st.slider("Hybrid alpha (rule weight)", 0.0, 1.0, 0.5, 0.05)
    rule_block = st.slider("Rule block threshold", 0.5, 1.0, 0.85, 0.01)
    ml_block = st.slider("ML block threshold", 0.4, 1.0, 0.7, 0.01)
    decision_thresh = st.slider("Final decision threshold", 0.2, 0.9, 0.5, 0.01)

sample_path = ROOT / "data" / "processed" / "sample_auth.log"
uploaded = st.file_uploader("Upload auth.log", type=["log", "txt"])

if not sample_path.exists():
    with st.spinner("Bundled sample log missing — generating one on the fly..."):
        try:
            from scripts.generate_sample_log import generate
            sample_path.parent.mkdir(parents=True, exist_ok=True)
            generate(sample_path)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not auto-generate sample log: {exc}")

log_text: str | None = None
if uploaded is not None:
    log_text = uploaded.read().decode("utf-8", errors="replace")
elif sample_path.exists():
    log_text = sample_path.read_text(encoding="utf-8", errors="replace")
    st.info(f"Loaded sample log ({sample_path.name}, "
            f"{len(log_text.splitlines())} lines)")
else:
    st.warning("No log available. Upload one above.")

if log_text:
    with st.spinner("Parsing log..."):
        from io import StringIO
        events = parse_file(StringIO(log_text))
        df = pd.DataFrame([e.as_dict() for e in events])
    st.success(f"Parsed {len(df):,} events")

    cfg = RuleConfig(static_window_seconds=static_window,
                     static_threshold=static_thresh,
                     adaptive_multiplier=adapt_mult)
    detections = run_rules(df, cfg)
    features = build_feature_matrix(df)
    rule_df = rule_score_from_detections(detections)

    ml_df = pd.DataFrame(columns=["ip", "ml_score"])
    model_summary = None
    try:
        bundle = load_latest_artifact()
        ml_scores = predict_proba(bundle, features)
        ml_df = ml_scores.reset_index()
        ml_df.columns = ["ip", "ml_score"]
        model_summary = bundle.metrics
    except FileNotFoundError:
        st.warning("No trained model artefact found. "
                   "Showing rule-only (run scripts/run_pipeline.py to train).")

    fusion = FusionConfig(alpha=rule_alpha,
                          rule_block_threshold=rule_block,
                          ml_block_threshold=ml_block,
                          decision_threshold=decision_thresh)
    fused = hybrid_score(rule_df, ml_df, fusion)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events", f"{len(df):,}")
    c2.metric("Distinct IPs", f"{df['ip'].nunique():,}")
    c3.metric("Rule alerts", f"{len(detections):,}")
    c4.metric("Final blocks", int(fused["final_decision"].sum()))

    st.subheader("Per-IP fused decisions")
    st.dataframe(fused, use_container_width=True, height=320)

    if model_summary:
        st.subheader("Loaded model")
        st.json(model_summary)

    st.subheader("Rule detections")
    st.dataframe(detections, use_container_width=True, height=240)
else:
    st.stop()
