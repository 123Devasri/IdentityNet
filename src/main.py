#!/usr/bin/env python3
"""
IdentityNet: Identity-Aware Network Firewall & Gateway Server
Main Gateway Supervisor & Process Orchestrator
"""

import os
import sys
import time
import signal
import socket
import argparse

# Ensure src/ is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import DatabaseManager
from policy_engine import PolicyEngine
from firewall_manager import FirewallManager
from router_manager import RouterManager
from dns_server import DNSFilterServer
from app_classifier import ApplicationClassifier
from dns_cache import DNSCache
from firewall_enforcer import FirewallEnforcer
from packet_capture import PacketCapturer
from signature_engine import SignatureEngine
import server as server_module

try:
    import uvicorn
    UVICORN_AVAILABLE = True
except ImportError:
    UVICORN_AVAILABLE = False

def get_active_host_ips():
    """Discover active host IPv4 addresses."""
    ip_list = ["127.0.0.1"]
    try:
        hostname = socket.gethostname()
        _, _, ips = socket.gethostbyname_ex(hostname)
        for ip in ips:
            if not ip.startswith("127.") and ip not in ip_list:
                ip_list.append(ip)
    except Exception:
        pass
    return ip_list

def print_banner():
    banner = r"""
\033[94m
=============================================================================
  _____    _            _   _ _           _  _      _   
 |_   _|__| |___ _ _ _| |_(_) |_ _  _ ___| \| |___ _| |_ 
   | | / _` / -_) ' \  _| | |  _| || (_-<| .` / -_)  _|
   |_| \__,_\___|_||_\__|_|_|\__|\_, /__/|_|\_\___|\__|
                                 |__/                  
 IdentityNet Gateway Server & Control Plane v2.0
 Network-Level Access Control & Contest Network System
=============================================================================\033[0m
"""
    print(banner.replace("\\033", "\033"))

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="IdentityNet Gateway Server")
    parser.add_argument("--lan-iface", default="eth1", help="LAN network interface (default: eth1)")
    parser.add_argument("--wan-iface", default="eth0", help="WAN network interface (default: eth0)")
    parser.add_argument("--gateway-ip", default="127.0.0.1", help="Gateway IPv4 address (default: 127.0.0.1)")
    parser.add_argument("--subnet", default="192.168.137.0/24", help="LAN Subnet (default: 192.168.137.0/24)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP server port (default: 8080)")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode without modifying system firewall/routing")
    parser.add_argument("--enable-app-filtering", action="store_true", help="Enable Scapy DNS/TLS application inspection")
    parser.add_argument("--capture-interface", default="any", help="Capture interface for application inspection")
    
    args = parser.parse_args()

    # 1. Initialize Database Manager
    print("[System] Initializing SQLite Database Manager...", flush=True)
    db_manager = DatabaseManager()

    # 2. Initialize Policy Engine
    print("[System] Initializing Control Plane Policy Engine...", flush=True)
    policy_engine = PolicyEngine(event_logger=db_manager.log_network_event)

    # 3. Initialize Firewall Manager
    print("[System] Initializing Data Plane Firewall Manager...", flush=True)
    firewall_manager = FirewallManager(
        lan_interface=args.lan_iface,
        lan_subnet=args.subnet,
        gateway_ip=args.gateway_ip,
        dry_run=args.dry_run
    )
    firewall_manager.initialize()

    # V2 application classification shares state with DNS inspection.
    dns_cache = DNSCache()
    signature_engine = SignatureEngine()
    application_classifier = ApplicationClassifier(signature_engine, dns_cache)
    firewall_enforcer = FirewallEnforcer(
        firewall_manager=firewall_manager,
        dry_run=args.dry_run,
    )

    # 4. Initialize Router Manager
    print("[System] Initializing Gateway Router & NAT Manager...", flush=True)
    router_manager = RouterManager(
        wan_interface=args.wan_iface,
        lan_interface=args.lan_iface,
        dry_run=args.dry_run
    )
    router_manager.enable_routing_and_nat()

    # 5. Initialize & Start DNS Server
    print("[System] Initializing IdentityNet DNS Filter Resolver...", flush=True)
    dns_server = DNSFilterServer(
        policy_engine=policy_engine,
        firewall_manager=firewall_manager,
        db_manager=db_manager,
        gateway_ip=args.gateway_ip,
        application_classifier=application_classifier,
        dns_cache=dns_cache
    )
    dns_server.start()

    packet_capturer = PacketCapturer(
        interface=args.capture_interface,
        bpf_filter="ip and (udp port 53 or tcp port 443)",
    )

    def process_application_packet(packet):
        match = application_classifier.classify_packet(packet)
        if not match or not hasattr(packet, "haslayer"):
            return
        try:
            source_ip = packet["IP"].src
            destination_ip = packet["IP"].dst
        except Exception:
            return
        participant = db_manager.get_participant_by_ip(source_ip)
        participant_id = participant["participant_id"] if participant else None
        action, _ = policy_engine.evaluate_application(
            match.application, match.category, source_ip, participant_id
        )
        if action == "BLOCKED":
            enforced = firewall_enforcer.block(source_ip, destination_ip, match.application, match.category)
            action = "BLOCKED" if enforced else "ENFORCEMENT_FAILED"
        db_manager.log_application_event(
            source_ip, match.application, match.category, match.detection_method, action
        )

    packet_capturer.packet_handler = process_application_packet
    if args.enable_app_filtering:
        packet_capturer.start()

    # Inject global manager dependencies into FastAPI app module
    server_module.db_manager = db_manager
    server_module.policy_engine = policy_engine
    server_module.firewall_manager = firewall_manager
    server_module.router_manager = router_manager
    server_module.gateway_ip = args.gateway_ip
    server_module.lan_subnet = args.subnet

    # Shutdown Handler
    def shutdown_handler(signum, frame):
        print("\n[System] Shutting down IdentityNet Gateway...", flush=True)
        dns_server.stop()
        packet_capturer.stop()
        firewall_enforcer.flush()
        firewall_manager.flush_rules()
        router_manager.cleanup()
        print("[System] IdentityNet Gateway offline. Goodbye!", flush=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    host_ips = get_active_host_ips()
    print(f"\n\033[92m[SYSTEM ONLINE] IdentityNet Gateway is ACTIVE on Port {args.port}\033[0m")
    print("\033[93mOpen your browser and visit any of the working links below:\033[0m")
    for ip in host_ips:
        print(f" -> Local Access:       http://{ip}:{args.port}/login")
    print(f" -> Admin Dashboard:    http://localhost:{args.port}/admin\n")

    if not UVICORN_AVAILABLE:
        print("\033[93m[Note] 'uvicorn' / 'fastapi' packages not installed on host. Run 'pip install -r requirements.txt' to install.\033[0m")
        print("[System] Verification complete. Shutting down dry-run supervisor.")
        shutdown_handler(None, None)
        return

    # Start FastAPI Web Server via Uvicorn
    try:
        uvicorn.run(server_module.app, host="0.0.0.0", port=args.port, log_level="info")
    except KeyboardInterrupt:
        shutdown_handler(None, None)

if __name__ == "__main__":
    main()
