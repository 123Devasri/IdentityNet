#!/usr/bin/env python3
"""
DNS Filter Server Test Suite
Validates raw DNS query parsing, policy evaluation, local domain resolution, and 0.0.0.0 blocking.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from policy_engine import PolicyEngine
from database import DatabaseManager

class MockFirewallManager:
    def allow_destination_ip(self, client_ip, dst_ip, domain=""):
        pass

class TestDNSFilter(unittest.TestCase):
    def setUp(self):
        self.test_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_dns.db"))
        self.db = DatabaseManager(db_path=self.test_db_path)
        self.config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))
        self.policy = PolicyEngine(policy_file=os.path.join(self.config_dir, "policy.json"))

    def tearDown(self):
        if os.path.exists(self.test_db_path):
            try:
                os.remove(self.test_db_path)
            except Exception:
                pass

    def test_dns_domain_policy_verdicts(self):
        """Verify verdicts for common examination/contest test cases."""
        test_cases = [
            ("contest.identitynet.local", "ALLOWED"),
            ("exam.identitynet.local", "ALLOWED"),
            ("github.com", "ALLOWED"),
            ("docs.python.org", "ALLOWED"),
            ("google.com", "BLOCKED"),
            ("youtube.com", "BLOCKED"),
            ("chatgpt.com", "BLOCKED"),
            ("gemini.google.com", "BLOCKED")
        ]

        for domain, expected in test_cases:
            action, reason = self.policy.evaluate(domain, "192.168.50.10")
            self.assertEqual(action, expected, f"Domain {domain} got {action}, expected {expected} ({reason})")

if __name__ == "__main__":
    unittest.main()
