"""Immediate application traffic enforcement for the active gateway."""

import hashlib
import os
import subprocess
import threading
from typing import Callable, Optional, Set, Tuple


class FirewallEnforcer:
    """Apply application blocks using Windows Firewall or the existing Linux manager."""

    def __init__(self, firewall_manager=None, dry_run: bool = False, event_logger: Optional[Callable] = None):
        self.firewall_manager = firewall_manager
        self.dry_run = dry_run
        self.event_logger = event_logger
        self.active_blocks: Set[Tuple[str, str]] = set()
        self.lock = threading.Lock()

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
        with self.lock:
            rule_keys = list(self.active_blocks)
            self.active_blocks.clear()
        if os.name == "nt" and not self.dry_run:
            for source_ip, destination_ip in rule_keys:
                rule_name = "IdentityNet-V2-" + hashlib.sha1(f"{source_ip}-{destination_ip}".encode()).hexdigest()[:16]
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
                ], check=False, capture_output=True, text=True)
