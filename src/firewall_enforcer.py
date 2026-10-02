"""Immediate application traffic enforcement for the active gateway."""

import hashlib
import os
import subprocess
import threading
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
                 policy_engine=None, db_manager=None):
        self.firewall_manager = firewall_manager
        self.dry_run = dry_run
        self.event_logger = event_logger
        self.classifier = classifier
        self.policy_engine = policy_engine
        self.db_manager = db_manager
        self.active_blocks: Set[Tuple[str, str]] = set()
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

        # Inspect all outbound IP traffic except DNS, which is handled by the existing DNS path.
        self._divert = pydivert.WinDivert("outbound and ip and !(tcp.DstPort == 53 or udp.DstPort == 53)")
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

        while self._divert_running and self._divert:
            try:
                diverted_packet = self._divert.recv()
                packet = IP(bytes(diverted_packet.raw))
                match = self.classifier.classify_packet(packet)
                if not match:
                    self._divert.send(diverted_packet)
                    continue

                participant = self.db_manager.get_participant_by_ip(packet.src)
                participant_id = participant["participant_id"] if participant else None
                action, _ = self.policy_engine.evaluate_application(
                    match.application, match.category, packet.src, participant_id
                )
                if action != "BLOCKED":
                    self._divert.send(diverted_packet)
                    continue

                self._record_drop(packet.src, packet.dst, match)
                # Intentionally do not send the packet back to the network.
            except Exception as exc:
                if self._divert_running and self.event_logger:
                    self.event_logger("0.0.0.0", "0.0.0.0", "WinDivert", "System", "WINDIVERT", f"ERROR: {exc}")

    def _record_drop(self, source_ip: str, destination_ip: str, match) -> None:
        if self.db_manager and hasattr(self.db_manager, "log_application_event"):
            self.db_manager.log_application_event(
                source_ip, match.application, match.category, match.detection_method, "DROPPED"
            )
        if self.event_logger:
            self.event_logger(source_ip, destination_ip, match.application, match.category, match.detection_method, "DROPPED")

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
        if os.name == "nt" and not self.dry_run:
            for source_ip, destination_ip in rule_keys:
                rule_name = "IdentityNet-V2-" + hashlib.sha1(f"{source_ip}-{destination_ip}".encode()).hexdigest()[:16]
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
                ], check=False, capture_output=True, text=True)
