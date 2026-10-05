#!/usr/bin/env python3
"""Focused V2 tests for signatures, policy, DNS correlation, and TLS SNI."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dns_cache import DNSCache
from firewall_enforcer import FirewallEnforcer
from policy_engine import PolicyEngine
from signature_engine import SignatureEngine
from tls_sni_inspector import TLSSNIInspector


class TestIdentityNetV2(unittest.TestCase):
    def test_signature_matching(self):
        engine = SignatureEngine()
        match = engine.match("gateway.discord.com")
        self.assertIsNotNone(match)
        self.assertEqual(match.name, "Discord")
        self.assertEqual(match.category, "Messaging")

    def test_application_policy(self):
        policy = PolicyEngine()
        action, _ = policy.evaluate_application("WhatsApp", "Messaging")
        self.assertEqual(action, "BLOCKED")
        action, _ = policy.evaluate_application("Python", "Education")
        self.assertEqual(action, "ALLOWED")

    def test_dns_correlation(self):
        cache = DNSCache()
        cache.put("discord.com", "203.0.113.10", "Discord", "Messaging")
        entry = cache.get("203.0.113.10")
        self.assertEqual(entry.application, "Discord")
        self.assertEqual(cache.get_application("203.0.113.10"), "Discord")

    def test_tls_sni_client_hello(self):
        host = b"discord.com"
        server_name = b"\x00" + len(host).to_bytes(2, "big") + host
        server_names = len(server_name).to_bytes(2, "big") + server_name
        extension = b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
        extensions = len(extension).to_bytes(2, "big") + extension
        hello_body = (
            b"\x03\x03" + b"0" * 32 + b"\x00" +
            b"\x00\x02\x13\x01" + b"\x01\x00" + extensions
        )
        handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
        record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
        self.assertEqual(TLSSNIInspector().extract_sni(record), "discord.com")

    def test_dry_run_enforcement(self):
        enforcer = FirewallEnforcer(dry_run=True)
        self.assertTrue(enforcer.block("192.168.137.10", "203.0.113.10", "Discord", "Messaging"))


if __name__ == "__main__":
    unittest.main()
