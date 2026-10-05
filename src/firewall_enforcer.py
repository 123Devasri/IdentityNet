"""Immediate application traffic enforcement for the active gateway."""

import hashlib
import ipaddress
import os
import subprocess
import threading
import time
from typing import Callable, Optional, Set, Tuple

try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    pydivert = None
    PYDIVERT_AVAILABLE = False


class FirewallEnforcer:
    """Apply application blocks using Windows Firewall or the existing Linux manager."""

    def __init__(self, firewall_manager=None, dry_run: bool = False,
                 event_logger: Optional[Callable] = None, classifier=None,
                 policy_engine=None, db_manager=None,
                 gateway_ip: str = "127.0.0.1", hotspot_subnet: str = "192.168.137.0/24"):
        self.firewall_manager = firewall_manager
        self.dry_run = dry_run
        self.event_logger = event_logger
        self.classifier = classifier
        self.policy_engine = policy_engine
        self.db_manager = db_manager
        self.gateway_ips = {"127.0.0.1", "::1", "192.168.50.1", "192.168.137.1", gateway_ip}
        self.hotspot_network = ipaddress.ip_network(hotspot_subnet, strict=False)
        self.control_ports = {53, 80, 8080, 8000}
        self.active_blocks: Set[Tuple[str, str]] = set()
        self.blocked_flows = {}
        self.lock = threading.Lock()
        self._divert = None
        self._divert_thread = None
        self._divert_running = False

    @property
    def packet_filter_active(self) -> bool:
        return self._divert_running

    def start_packet_filter(self) -> bool:
        """Start WinDivert at the network layer so blocked packets are never forwarded."""
        if self.dry_run or os.name != "nt":
            return False
        if not PYDIVERT_AVAILABLE:
            raise RuntimeError("pydivert is not installed; install it and the WinDivert driver")
        if not self.classifier or not self.policy_engine or not self.db_manager:
            raise RuntimeError("WinDivert enforcement requires classifier, policy, and database dependencies")

        # Capture both directions. The flow table prevents reinjection of blocked reverse traffic.
        self._divert = pydivert.WinDivert("true")
        try:
            self._divert.open()
        except Exception as exc:
            self._divert = None
            raise RuntimeError(f"Unable to open WinDivert; run as Administrator and install the driver: {exc}") from exc

        self._divert_running = True
        self._divert_thread = threading.Thread(target=self._divert_loop, name="identitynet-windivert", daemon=True)
        self._divert_thread.start()
        print("[Firewall Enforcer] WinDivert packet-drop enforcement ACTIVE.", flush=True)
        return True

    def _divert_loop(self) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.inet import TCP, UDP

        while self._divert_running and self._divert:
            diverted_packet = None
            try:
                diverted_packet = self._divert.recv()
                raw_packet = bytes(diverted_packet.raw)
                if not raw_packet:
                    self._divert.send(diverted_packet)
                    continue
                version = raw_packet[0] >> 4
                packet = IP(raw_packet) if version == 4 else IPv6(raw_packet) if version == 6 else None
                if packet is None or self._is_control_plane_packet(packet):
                    self._divert.send(diverted_packet)
                    continue

                flow_key = self._flow_key(packet)
                blocked_flow = self._get_blocked_flow(flow_key)
                if blocked_flow:
                    blocked_match, original_source = blocked_flow
                    self._record_drop(original_source, packet.dst, blocked_match)
                    continue

                candidates = self.classifier.classify_packet_candidates(packet)
                if not candidates:
                    self._divert.send(diverted_packet)
                    continue

                participant = self.db_manager.get_participant_by_ip(packet.src)
                participant_id = participant["participant_id"] if participant else None
                blocked_match = None
                for match in candidates:
                    action, _ = self.policy_engine.evaluate_application(
                        match.application, match.category, packet.src, participant_id
                    )
                    if action == "BLOCKED":
                        blocked_match = match
                        break

                if not blocked_match:
                    self._divert.send(diverted_packet)
                    continue

                self._remember_blocked_flow(flow_key, blocked_match, packet.src)
                self._record_drop(packet.src, packet.dst, blocked_match)
                # Intentionally do not send the packet back to the network.
            except Exception as exc:
                # Unknown or malformed traffic must not be dropped accidentally.
                if diverted_packet is not None and self._divert_running and self._divert:
                    try:
                        self._divert.send(diverted_packet)
                    except Exception:
                        pass
                if self._divert_running and self.event_logger:
                    self.event_logger("0.0.0.0", "0.0.0.0", "WinDivert", "System", "WINDIVERT", f"ERROR: {exc}")

    def _is_control_plane_packet(self, packet) -> bool:
        source_ip = getattr(packet, "src", "")
        destination_ip = getattr(packet, "dst", "")
        if source_ip in self.gateway_ips or destination_ip in self.gateway_ips:
            return True
        if source_ip in {"127.0.0.1", "::1"} or destination_ip in {"127.0.0.1", "::1"}:
            return True

        transport = None
        if packet.haslayer("TCP"):
            transport = packet["TCP"]
        elif packet.haslayer("UDP"):
            transport = packet["UDP"]
        if transport and (transport.sport in self.control_ports or transport.dport in self.control_ports):
            if source_ip in self.gateway_ips or destination_ip in self.gateway_ips:
                return True
        return False

    def _flow_key(self, packet):
        protocol = packet.payload.name if getattr(packet, "payload", None) else "IP"
        source = getattr(packet, "src", "")
        destination = getattr(packet, "dst", "")
        source_port = destination_port = 0
        if packet.haslayer("TCP"):
            protocol = "TCP"
            source_port = packet["TCP"].sport
            destination_port = packet["TCP"].dport
        elif packet.haslayer("UDP"):
            protocol = "UDP"
            source_port = packet["UDP"].sport
            destination_port = packet["UDP"].dport
        endpoints = tuple(sorted(((source, source_port), (destination, destination_port))))
        return protocol, endpoints

    def _remember_blocked_flow(self, flow_key, match, match_source: str, ttl: int = 3600) -> None:
        with self.lock:
            self.blocked_flows[flow_key] = (time.monotonic() + ttl, match, match_source)

    def _get_blocked_flow(self, flow_key):
        with self.lock:
            entry = self.blocked_flows.get(flow_key)
            if not entry:
                return None
            expires_at, match, match_source = entry
            if expires_at <= time.monotonic():
                del self.blocked_flows[flow_key]
                return None
            return match, match_source

    def _record_drop(self, source_ip: str, destination_ip: str, match) -> None:
        try:
            if self.db_manager and hasattr(self.db_manager, "log_application_event"):
                self.db_manager.log_application_event(
                    source_ip, match.application, match.category, match.detection_method, "DROPPED", destination_ip
                )
            if self.event_logger:
                self.event_logger(source_ip, destination_ip, match.application, match.category, match.detection_method, "DROPPED")
        except Exception:
            # Logging failure must never reinject a packet that was already denied.
            pass

    def stop_packet_filter(self) -> None:
        self._divert_running = False
        if self._divert:
            try:
                self._divert.close()
            except Exception:
                pass
        if self._divert_thread and self._divert_thread.is_alive():
            self._divert_thread.join(timeout=2)
        self._divert = None
        self._divert_thread = None

    def block(self, source_ip: str, destination_ip: str, application: str, category: str) -> bool:
        if not destination_ip or destination_ip in {"0.0.0.0", "127.0.0.1"}:
            return False
        rule_key = (source_ip, destination_ip)
        with self.lock:
            if rule_key in self.active_blocks:
                return True
            self.active_blocks.add(rule_key)

        rule_name = "IdentityNet-V2-" + hashlib.sha1(f"{source_ip}-{destination_ip}".encode()).hexdigest()[:16]
        success = self.dry_run
        if not self.dry_run and os.name == "nt":
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block", "enable=yes",
                f"localip={source_ip}", f"remoteip={destination_ip}",
            ]
            try:
                result = subprocess.run(command, check=False, capture_output=True, text=True)
                success = result.returncode == 0
            except OSError:
                success = False
        elif not self.dry_run and self.firewall_manager is not None:
            block_method = getattr(self.firewall_manager, "block_destination_ip", None)
            if block_method:
                success = bool(block_method(source_ip, destination_ip, application))

        if self.event_logger:
            self.event_logger(source_ip, destination_ip, application, category, "FIREWALL", "BLOCKED" if success else "ENFORCEMENT_FAILED")
        if not success:
            with self.lock:
                self.active_blocks.discard(rule_key)
        return success

    def flush(self) -> None:
        self.stop_packet_filter()
        with self.lock:
            rule_keys = list(self.active_blocks)
            self.active_blocks.clear()
            self.blocked_flows.clear()
        if os.name == "nt" and not self.dry_run:
            for source_ip, destination_ip in rule_keys:
                rule_name = "IdentityNet-V2-" + hashlib.sha1(f"{source_ip}-{destination_ip}".encode()).hexdigest()[:16]
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
                ], check=False, capture_output=True, text=True)
