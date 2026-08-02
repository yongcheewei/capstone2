# unit tests for the log parser module
# these cover the regex patterns and the normalisation logic
import unittest
import sys
import os
from datetime import datetime

# so we can import modules from parent dir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.log_parser import (
    parse_log, parse_timestamp, normalize_events, build_baseline,
)


class TestParseTimestamp(unittest.TestCase):
    def test_valid_timestamp(self):
        # standard "Mon DD HH:MM:SS" format
        ts = parse_timestamp("Jan 12 14:30:00")
        self.assertIsNotNone(ts)
        self.assertEqual(ts.hour, 14)
        self.assertEqual(ts.minute, 30)
        self.assertEqual(ts.second, 0)

    def test_invalid_timestamp(self):
        # garbage input should return None, not crash
        self.assertIsNone(parse_timestamp("not a timestamp"))


class TestParseLog(unittest.TestCase):
    def setUp(self):
        # tiny inline log file for the test
        self.tmp = "tests/_tmp_test.log"
        with open(self.tmp, "w") as f:
            f.write("Jan 12 10:00:00 server01 sshd[100]: Failed password for root from 1.2.3.4 port 22 ssh2\n")
            f.write("Jan 12 10:00:05 server01 sshd[100]: Accepted password for yong from 1.2.3.4 port 22 ssh2\n")
            f.write("Jan 12 10:00:10 server01 sshd[100]: Invalid user admin from 5.6.7.8\n")
            f.write("Jan 12 10:00:15 server01 sshd[100]: Failed password for invalid user admin from 5.6.7.8 port 22 ssh2\n")
            f.write("this is garbage and should be skipped\n")

    def tearDown(self):
        if os.path.exists(self.tmp):
            os.remove(self.tmp)

    def test_parses_failed_and_accepted(self):
        events, skipped = parse_log(self.tmp)
        # 4 valid events, 1 garbage line
        self.assertEqual(len(events), 4)
        self.assertEqual(skipped, 1)
        statuses = [e["status"] for e in events]
        self.assertIn("failed", statuses)
        self.assertIn("success", statuses)

    def test_extracts_fields(self):
        events, _ = parse_log(self.tmp)
        first = events[0]
        self.assertEqual(first["ip"], "1.2.3.4")
        self.assertEqual(first["username"], "root")
        self.assertEqual(first["status"], "failed")
        self.assertIsInstance(first["timestamp"], datetime)


class TestNormalizeEvents(unittest.TestCase):
    def test_lowercases_usernames(self):
        events = [{
            "timestamp": datetime(2026, 1, 12, 10, 0),
            "username": "YONG",
            "ip": "1.2.3.4",
            "status": "success",
        }]
        normalised = normalize_events(events)
        self.assertEqual(normalised[0]["username"], "yong")

    def test_strips_whitespace(self):
        events = [{
            "timestamp": datetime(2026, 1, 12, 10, 0),
            "username": "  alice  ",
            "ip": "  1.2.3.4  ",
            "status": "success",
        }]
        normalised = normalize_events(events)
        self.assertEqual(normalised[0]["username"], "alice")
        self.assertEqual(normalised[0]["ip"], "1.2.3.4")

    def test_sorts_by_timestamp(self):
        events = [
            {"timestamp": datetime(2026, 1, 12, 11, 0), "username": "a", "ip": "1.1.1.1", "status": "failed"},
            {"timestamp": datetime(2026, 1, 12, 9, 0), "username": "b", "ip": "1.1.1.1", "status": "failed"},
        ]
        normalised = normalize_events(events)
        self.assertEqual(normalised[0]["username"], "b")  # earlier one first


class TestBuildBaseline(unittest.TestCase):
    def test_uses_quiet_ips(self):
        # one quiet IP with 1 fail per hour, one noisy IP with 10 fails per hour
        events = []
        for h in range(3):
            events.append({
                "timestamp": datetime(2026, 1, 12, h, 0),
                "username": "u", "ip": "1.1.1.1", "status": "failed",
            })
        for _ in range(10):
            events.append({
                "timestamp": datetime(2026, 1, 12, 5, 0),
                "username": "u", "ip": "9.9.9.9", "status": "failed",
            })
        baseline = build_baseline(events)
        # baseline should be a positive integer, robust to the noisy ip
        self.assertIn("1.1.1.1", baseline)
        self.assertGreaterEqual(baseline["1.1.1.1"], 3)


if __name__ == "__main__":
    unittest.main()
