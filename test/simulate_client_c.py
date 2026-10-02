#!/usr/bin/env python3
"""
Traffic Simulator - Client VM C (Contestant_C)
IP: 192.168.56.13

Policy Expectations for Contestant_C:
- youtube.com -> ALLOW
- github.com  -> ALLOW
- google.com  -> ALLOW
"""

import sys
import os
import argparse

# Ensure src/ is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from policy_engine import PolicyEngine

try:
    from scapy.all import IP, UDP, DNS, DNSQR, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

CLIENT_IP = "192.168.56.13"
CLIENT_NAME = "Contestant_C"

def run_simulation(send_raw_packets=False):
    print(f"\n==================================================")
    print(f" Simulating Traffic for {CLIENT_NAME} ({CLIENT_IP})")
    print(f"==================================================")

    engine = PolicyEngine()

    test_domains = [
        ("youtube.com", "BLOCKED"),
        ("github.com", "ALLOWED"),
        ("google.com", "BLOCKED")
    ]

    passed_count = 0

    for domain, expected in test_domains:
        action, reason = engine.evaluate(domain, CLIENT_IP)
        status = "PASSED" if action == expected else "FAILED"
        if status == "PASSED":
            passed_count += 1
            color_fmt = "\033[92m"  # Green
        else:
            color_fmt = "\033[91m"  # Red

        print(f"[{CLIENT_NAME}] Request domain: {domain:<15} | Expected: {expected:<5} | Got: {action:<5} => {color_fmt}[{status}]\033[0m")
        print(f"   |- Reason: {reason}")

        if send_raw_packets and SCAPY_AVAILABLE:
            try:
                pkt = IP(src=CLIENT_IP, dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                send(pkt, verbose=False)
                print(f"   |- Sent live raw DNS query packet for {domain} (src: {CLIENT_IP})")
            except Exception as e:
                print(f"   |- Note: Raw packet send requires sudo: {e}")

    print(f"\nSummary for {CLIENT_NAME}: {passed_count}/{len(test_domains)} test cases passed.")
    return passed_count == len(test_domains)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"Simulate Client C ({CLIENT_NAME}) traffic")
    parser.add_argument("--send-raw", action="store_true", help="Send live raw Scapy packets with spoofed source IP")
    args = parser.parse_args()

    success = run_simulation(send_raw_packets=args.send_raw)
    sys.exit(0 if success else 1)
