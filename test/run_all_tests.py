#!/usr/bin/env python3
"""
IdentityNet Automated Test Suite
Executes and validates all 4 mandatory testing scenarios.
"""

import sys
import os

# Ensure src/ is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from policy_engine import PolicyEngine

def run_suite():
    print("""
=============================================================================
             IdentityNet Firewall - Automated Test Suite
=============================================================================
""")

    engine = PolicyEngine()

    test_scenarios = [
        {"id": 1, "user": "Contestant_A", "ip": "192.168.56.11", "domain": "github.com", "expected": "ALLOWED"},
        {"id": 2, "user": "Contestant_A", "ip": "192.168.56.11", "domain": "youtube.com", "expected": "BLOCKED"},
        {"id": 3, "user": "Contestant_B", "ip": "192.168.56.12", "domain": "instagram.com", "expected": "BLOCKED"},
        {"id": 4, "user": "Contestant_C", "ip": "192.168.56.13", "domain": "youtube.com", "expected": "BLOCKED"},
    ]

    all_passed = True
    print(f"{'ID':<4} | {'User':<14} | {'Client IP':<14} | {'Domain':<16} | {'Expected':<8} | {'Result':<8} | {'Status'}")
    print("-" * 90)

    for tc in test_scenarios:
        action, reason = engine.evaluate(tc["domain"], tc["ip"])
        passed = (action == tc["expected"])
        if not passed:
            all_passed = False
            status_str = "\033[91m[FAILED]\033[0m"
        else:
            status_str = "\033[92m[PASSED]\033[0m"

        print(f"{tc['id']:<4} | {tc['user']:<14} | {tc['ip']:<14} | {tc['domain']:<16} | {tc['expected']:<8} | {action:<8} | {status_str}")

    print("=" * 90)
    if all_passed:
        print("\033[92mALL TEST SCENARIOS PASSED SUCCESSFULLY!\033[0m\n")
    else:
        print("\033[91mSOME TEST SCENARIOS FAILED!\033[0m\n")

    return all_passed

if __name__ == "__main__":
    success = run_suite()
    sys.exit(0 if success else 1)
