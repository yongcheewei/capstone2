import pandas as pd
import pytest

from src.parser import parse_line
from src.rules import RuleConfig, run_rules
from src.features import build_feature_matrix, build_features
from src.hybrid import FusionConfig, hybrid_score, rule_score_from_detections
from src.evaluation import compute_metrics


SAMPLE_LOG = """\
Mar 15 10:23:45 srv sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 50000 ssh2
Mar 15 10:23:46 srv sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 50001 ssh2
Mar 15 10:23:47 srv sshd[1234]: Failed password for invalid user test from 1.2.3.4 port 50002 ssh2
Mar 15 10:23:48 srv sshd[1234]: Failed password for invalid user oracle from 1.2.3.4 port 50003 ssh2
Mar 15 10:23:49 srv sshd[1234]: Failed password for invalid user postgres from 1.2.3.4 port 50004 ssh2
Mar 15 10:23:50 srv sshd[1234]: Failed password for invalid user nagios from 1.2.3.4 port 50005 ssh2
Mar 15 10:24:00 srv sshd[1234]: Accepted password for alice from 9.9.9.9 port 51000 ssh2
Mar 15 10:24:05 srv sshd[1234]: Failed password for bob from 5.5.5.5 port 51100 ssh2
"""


def test_parser_extracts_ip_user_event_type():
    ev = parse_line(SAMPLE_LOG.splitlines()[0])
    assert ev is not None
    assert ev.ip == "1.2.3.4"
    assert ev.user == "admin"
    assert ev.event_type == "failed_password"
    assert ev.invalid_user is True


def test_parser_accepts_accepted_password():
    line = "Mar 15 10:24:00 srv sshd[1234]: Accepted password for alice from 9.9.9.9 port 51000 ssh2"
    ev = parse_line(line)
    assert ev is not None
    assert ev.event_type == "accepted_password"
    assert ev.invalid_user is False


def test_parser_ignores_unrelated_lines():
    assert parse_line("totally not a syslog line") is None
    assert parse_line("Mar 15 10:00:00 srv cron[1]: (root) CMD (run-parts /etc/cron.hourly)") is None


def test_static_rule_triggers_on_rapid_failures():
    from io import StringIO
    from src.parser import parse_file
    events = parse_file(StringIO(SAMPLE_LOG))
    df = pd.DataFrame([e.as_dict() for e in events])
    dets = run_rules(df, RuleConfig(static_window_seconds=60,
                                    static_threshold=5),
                     include=["static"])
    assert (dets["ip"] == "1.2.3.4").any()


def test_static_rule_does_not_trigger_for_one_failure():
    from io import StringIO
    from src.parser import parse_file
    events = parse_file(StringIO(SAMPLE_LOG))
    df = pd.DataFrame([e.as_dict() for e in events])
    dets = run_rules(df, RuleConfig(static_window_seconds=60,
                                    static_threshold=5),
                     include=["static"])
    assert not (dets["ip"] == "5.5.5.5").any()


def test_features_build_matrix_has_expected_columns():
    from io import StringIO
    from src.parser import parse_file
    events = parse_file(StringIO(SAMPLE_LOG))
    df = pd.DataFrame([e.as_dict() for e in events])
    feats = build_feature_matrix(df)
    assert "failed_total" in feats.columns
    assert "unique_users_targeted" in feats.columns
    row = feats.set_index("ip").loc["1.2.3.4"]
    assert row["failed_total"] >= 6
    assert row["unique_users_targeted"] >= 6


def test_hybrid_score_blocks_high_rule_or_high_ml():
    rule_df = pd.DataFrame({"ip": ["a", "b", "c"],
                            "rule_score": [0.95, 0.3, 0.1]})
    ml_df = pd.DataFrame({"ip": ["a", "b", "c"],
                         "ml_score": [0.1, 0.8, 0.1]})
    fused = hybrid_score(rule_df, ml_df,
                         FusionConfig(rule_block_threshold=0.85,
                                      ml_block_threshold=0.7))
    by_ip = fused.set_index("ip")["final_decision"].to_dict()
    assert by_ip["a"] == 1
    assert by_ip["b"] == 1
    assert by_ip["c"] == 0


def test_compute_metrics_basic():
    m = compute_metrics([0, 1, 1, 0], [0, 1, 0, 0], [0.2, 0.8, 0.4, 0.1])
    assert m["tp"] == 1 and m["fn"] == 1
    assert m["precision"] == 1.0
    assert abs(m["recall"] - 0.5) < 1e-6


def test_rule_score_from_detections_aggregates_max():
    dets = pd.DataFrame({
        "ip": ["a", "a", "b"],
        "rule": ["static", "contextual_invalid_user_flood", "static"],
        "confidence": [0.7, 0.5, 0.9],
    })
    scores = rule_score_from_detections(dets)
    s = scores.set_index("ip")["rule_score"].to_dict()
    assert s["a"] == 0.7
    assert s["b"] == 0.9
