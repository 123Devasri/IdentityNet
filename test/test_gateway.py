#!/usr/bin/env python3
"""
IdentityNet Gateway Unit & Integration Test Suite
Validates Control Plane Policy Engine, Database Operations, and Authentication.
"""

import sys
import os
import unittest

# Ensure src/ is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from database import DatabaseManager
from policy_engine import PolicyEngine

class TestIdentityNetGateway(unittest.TestCase):
    def setUp(self):
        self.test_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_identitynet.db"))
        self.db = DatabaseManager(db_path=self.test_db_path)
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM participants WHERE participant_id = 'P099';")
            conn.commit()
        
        self.config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))
        self.policy = PolicyEngine(policy_file=os.path.join(self.config_dir, "policy.json"))

    def tearDown(self):
        try:
            with self.db.get_connection() as conn:
                conn.execute("DELETE FROM participants WHERE participant_id = 'P099';")
                conn.commit()
        except Exception:
            pass
        if os.path.exists(self.test_db_path):
            try:
                os.remove(self.test_db_path)
            except Exception:
                pass

    def test_database_authentication(self):
        """Test participant credential verification."""
        user = self.db.authenticate_participant("P001", "pass123")
        self.assertIsNotNone(user)
        self.assertEqual(user["participant_id"], "P001")
        self.assertEqual(user["name"], "Alice Johnson")

        invalid = self.db.authenticate_participant("P001", "wrongpass")
        self.assertIsNone(invalid)

    def test_session_management(self):
        """Test active participant session creation and lookup."""
        session_id = self.db.create_session("P001", "192.168.50.10", "AA:BB:CC:DD:EE:FF")
        self.assertTrue(len(session_id) > 10)

        session = self.db.get_session_by_id(session_id)
        self.assertIsNotNone(session)
        self.assertEqual(session["participant_id"], "P001")
        self.assertEqual(session["ip_address"], "192.168.50.10")

        active = self.db.get_active_sessions()
        self.assertTrue(len(active) >= 1)

    def test_admin_participant_creation(self):
        """Test creating a new participant account and rejecting duplicate IDs."""
        created = self.db.create_participant("P099", "New User", "secure-pass")
        self.assertEqual(created["participant_id"], "P099")
        self.assertEqual(created["status"], "OFFLINE")
        self.assertIsNotNone(self.db.authenticate_participant("P099", "secure-pass"))

        with self.assertRaises(ValueError):
            self.db.create_participant("P099", "Another User", "another-pass")

    def test_policy_evaluation(self):
        """Test Allowlist policy evaluation matching rules."""
        # 1. Local gateway domains -> ALLOWED
        action, _ = self.policy.evaluate("contest.identitynet.local")
        self.assertEqual(action, "ALLOWED")

        # 2. Contest policy default allowed -> github.com
        action, _ = self.policy.evaluate("github.com")
        self.assertEqual(action, "ALLOWED")

        # 3. Subdomain wildcard matching -> raw.githubusercontent.com
        action, _ = self.policy.evaluate("raw.githubusercontent.com")
        self.assertEqual(action, "ALLOWED")

        # 4. Default-deny policy -> google.com, youtube.com, chatgpt.com
        for blocked_site in ["google.com", "youtube.com", "chatgpt.com", "gemini.google.com"]:
            action, _ = self.policy.evaluate(blocked_site)
            self.assertEqual(action, "BLOCKED", f"Expected {blocked_site} to be BLOCKED under default-deny policy.")

    def test_dynamic_policy_updates(self):
        """Test adding/removing domains dynamically."""
        # Initially blocked
        action, _ = self.policy.evaluate("example.com")
        self.assertEqual(action, "BLOCKED")

        # Add to allowlist
        self.policy.add_allowed_domain("example.com")
        action, _ = self.policy.evaluate("example.com")
        self.assertEqual(action, "ALLOWED")

        # Remove from allowlist
        self.policy.remove_allowed_domain("example.com")
        action, _ = self.policy.evaluate("example.com")
        self.assertEqual(action, "BLOCKED")

if __name__ == "__main__":
    unittest.main()
