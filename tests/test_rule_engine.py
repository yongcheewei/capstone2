# unit tests for the rule engine - covers each of the 4 rules
import unittest
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.rule_engine import (
    static_threshold_rule,
    adaptive_threshold_rule,
    account_diversity_rule,
    time_of_day_rule,
    distributed_attack_rule,
    run_all_rules,
)


def make_event(ts, ip, username, status="failed"):
    return {"timestamp": ts, "ip": ip, "username": username, "status": status}


class TestStaticThresholdRule(unittest.TestCase):
    def test_triggers_on_burst(self):
        # 6 fails in 30 sec from one ip - should trigger
        base = datetime(2026, 1, 12, 10, 0, 0)
        events = [make_event(base + timedelta(seconds=i*3), "1.1.1.1", "root") for i in range(6)]
        alerts = static_threshold_rule(events, threshold=5, window=60)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "1.1.1.1")

    def test_does_not_trigger_below_threshold(self):
        # only 3 fails - should not trigger
        base = datetime(2026, 1, 12, 10, 0, 0)
        events = [make_event(base + timedelta(seconds=i*3), "1.1.1.1", "root") for i in range(3)]
        alerts = static_threshold_rule(events, threshold=5, window=60)
        self.assertEqual(len(alerts), 0)

    def test_ignores_success_events(self):
        # 6 success logins should never trigger
        base = datetime(2026, 1, 12, 10, 0, 0)
        events = [make_event(base + timedelta(seconds=i*3), "1.1.1.1", "root", "success") for i in range(6)]
        alerts = static_threshold_rule(events, threshold=5, window=60)
        self.assertEqual(len(alerts), 0)


class TestAdaptiveThresholdRule(unittest.TestCase):
    def test_triggers_on_burst_above_threshold(self):
        # baseline 5, multiplier 3, threshold = max(6, 7) = 7
        # 8 fails should trigger
        base = datetime(2026, 1, 12, 10, 0, 0)
        events = [make_event(base + timedelta(seconds=i*2), "1.1.1.1", "root") for i in range(8)]
        baseline = {"1.1.1.1": 5}
        alerts = adaptive_threshold_rule(events, baseline)
        self.assertEqual(len(alerts), 1)

    def test_skips_small_typo_burst(self):
        # baseline 5, threshold 7 - 6 fails should NOT trigger adaptive
        base = datetime(2026, 1, 12, 10, 0, 0)
        events = [make_event(base + timedelta(seconds=i*3), "1.1.1.1", "charlie") for i in range(6)]
        baseline = {"1.1.1.1": 5}
        alerts = adaptive_threshold_rule(events, baseline)
        self.assertEqual(len(alerts), 0)


class TestAccountDiversityRule(unittest.TestCase):
    def test_triggers_on_many_usernames(self):
        # 1 ip hitting 4 different users
        base = datetime(2026, 1, 12, 10, 0, 0)
        events = [
            make_event(base + timedelta(seconds=i*5), "1.1.1.1", f"user{i}")
            for i in range(4)
        ]
        alerts = account_diversity_rule(events, min_users=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["unique_usernames"], 4)

    def test_does_not_trigger_on_same_user(self):
        # 5 fails but all on the same user
        base = datetime(2026, 1, 12, 10, 0, 0)
        events = [make_event(base + timedelta(seconds=i*5), "1.1.1.1", "root") for i in range(5)]
        alerts = account_diversity_rule(events, min_users=3)
        self.assertEqual(len(alerts), 0)


class TestTimeOfDayRule(unittest.TestCase):
    def test_triggers_off_hours_fails(self):
        # 3am fails should be flagged
        events = [
            make_event(datetime(2026, 1, 12, 3, i), "1.1.1.1", "root")
            for i in [0, 10, 20]
        ]
        alerts = time_of_day_rule(events, start_hour=8, end_hour=20)
        self.assertEqual(len(alerts), 1)

    def test_does_not_trigger_work_hours(self):
        # 10am fails should NOT be flagged by off-hours rule
        events = [
            make_event(datetime(2026, 1, 12, 10, i), "1.1.1.1", "root")
            for i in [0, 10, 20]
        ]
        alerts = time_of_day_rule(events, start_hour=8, end_hour=20)
        self.assertEqual(len(alerts), 0)


class TestRunAllRules(unittest.TestCase):
    def test_dedupes_per_ip_rule(self):
        # the same ip + same rule should only fire once
        base = datetime(2026, 1, 12, 10, 0, 0)
        events = [make_event(base + timedelta(seconds=i*3), "1.1.1.1", "root") for i in range(6)]
        alerts = run_all_rules(events, baseline={"1.1.1.1": 5})
        # at most one static_threshold alert for 1.1.1.1
        static_count = sum(1 for a in alerts if a["rule"] == "static_threshold" and a["ip"] == "1.1.1.1")
        self.assertLessEqual(static_count, 1)


class TestDistributedAttackRule(unittest.TestCase):
    def test_triggers_on_subnet_botnet(self):
        # 3 ips from 45.32.10.0/24 all hitting root within 5 min
        base = datetime(2026, 1, 12, 3, 0, 0)
        events = []
        for i, ip in enumerate(["45.32.10.4", "45.32.10.5", "45.32.10.6"]):
            events.append(make_event(base + timedelta(seconds=i*20), ip, "root"))
        alerts = distributed_attack_rule(events, min_ips=3, window=600)
        self.assertEqual(len(alerts), 1)
        self.assertIn("45.32.10", alerts[0]["ip"])
        self.assertEqual(alerts[0]["target_username"], "root")

    def test_does_not_trigger_on_single_ip(self):
        # even 10 fails from one ip should not trigger distributed rule
        base = datetime(2026, 1, 12, 3, 0, 0)
        events = [make_event(base + timedelta(seconds=i*5), "1.1.1.1", "root") for i in range(10)]
        alerts = distributed_attack_rule(events, min_ips=3, window=600)
        self.assertEqual(len(alerts), 0)

    def test_does_not_trigger_on_different_subnets(self):
        # 3 ips from DIFFERENT subnets should not trigger distributed rule
        base = datetime(2026, 1, 12, 3, 0, 0)
        events = []
        for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
            events.append(make_event(base + timedelta(seconds=i*20), ip, "root"))
        alerts = distributed_attack_rule(events, min_ips=3, window=600)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
