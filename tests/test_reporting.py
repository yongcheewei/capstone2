# unit tests for the reporting module - covers precision / recall / f1 math
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reporting import compute_metrics, rule_breakdown


class TestComputeMetrics(unittest.TestCase):
    def test_perfect_detection(self):
        # alert on the right ips, no false positives
        alerts = [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}]
        truth = {"1.1.1.1", "2.2.2.2"}
        m = compute_metrics(alerts, truth)
        self.assertEqual(m["true_positives"], 2)
        self.assertEqual(m["false_positives"], 0)
        self.assertEqual(m["false_negatives"], 0)
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 1.0)
        self.assertEqual(m["f1_score"], 1.0)

    def test_missed_attacker(self):
        # we caught one but missed another
        alerts = [{"ip": "1.1.1.1"}]
        truth = {"1.1.1.1", "2.2.2.2"}
        m = compute_metrics(alerts, truth)
        self.assertEqual(m["true_positives"], 1)
        self.assertEqual(m["false_negatives"], 1)
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 0.5)

    def test_false_positive(self):
        # we flagged an innocent ip
        alerts = [{"ip": "1.1.1.1"}, {"ip": "9.9.9.9"}]
        truth = {"1.1.1.1"}
        m = compute_metrics(alerts, truth)
        self.assertEqual(m["true_positives"], 1)
        self.assertEqual(m["false_positives"], 1)
        self.assertEqual(m["precision"], 0.5)
        self.assertEqual(m["recall"], 1.0)

    def test_empty_inputs(self):
        m = compute_metrics([], set())
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["recall"], 0.0)


class TestRuleBreakdown(unittest.TestCase):
    def test_counts_per_rule(self):
        alerts = [
            {"rule": "static_threshold", "ip": "1.1.1.1"},
            {"rule": "static_threshold", "ip": "2.2.2.2"},
            {"rule": "off_hours", "ip": "3.3.3.3"},
        ]
        b = rule_breakdown(alerts)
        self.assertEqual(b["static_threshold"], 2)
        self.assertEqual(b["off_hours"], 1)


if __name__ == "__main__":
    unittest.main()
