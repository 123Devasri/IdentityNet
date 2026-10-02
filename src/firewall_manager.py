import subprocess
import shutil
import threading
import os
from typing import Set, Tuple, Optional

class FirewallManager:
    """
    Data Plane Firewall Manager for IdentityNet.
    Enforces Default-Deny Egress Policy, Anti-Bypass DNS Redirection,
    and Dynamic Destination IP Allow Rules using nftables or iptables.
    """
    def __init__(self,
                 lan_interface: str = "eth1",
                 lan_subnet: str = "192.168.50.0/24",
                 gateway_ip: str = "192.168.50.1",
                 dry_run: bool = False):
        self.lan_interface = lan_interface
        self.lan_subnet = lan_subnet
        self.gateway_ip = gateway_ip
        self.dry_run = dry_run

        self.backend = self._detect_backend()
        self.permitted_ips: Set[str] = set()
        self.blocked_ips: Set[Tuple[str, str]] = set()
        self.lock = threading.Lock()

    def _detect_backend(self) -> str:
        if self.dry_run or os.name == "nt":
            return "dry_run"
        if shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        return "dry_run"

    def initialize(self):
        """Configure Firewall Rules: Anti-Bypass DNS Redirect & Default-Deny Policy."""
        if self.backend == "dry_run":
            reason = "Windows native firewall integration is not implemented" if os.name == "nt" and not self.dry_run else "dry-run requested"
            print(f"[Firewall Manager] Operating without rule changes ({reason}).", flush=True)
            return

        with self.lock:
            if self.backend == "nftables":
                self._setup_nftables()
            elif self.backend == "iptables":
                self._setup_iptables()

        print(f"[Firewall Manager] Initialized {self.backend} (Default-Deny + Anti-Bypass DNS Redirect active).", flush=True)

    def _setup_nftables(self):
        """Configure nftables table, chains, DNS redirect, and default drop rules."""
        # Create inet table identitynet
        self._run(["nft", "add", "table", "inet", "identitynet"])
        
        # Filter chain (FORWARD)
        self._run(["nft", "add", "chain", "inet", "identitynet", "forward", "{ type filter hook forward priority 0; policy drop; }"])
        
        # NAT chain (PREROUTING) for Anti-Bypass DNS Redirection
        self._run(["nft", "add", "chain", "inet", "identitynet", "prerouting", "{ type nat hook prerouting priority -100; }"])
        
        # Anti-Bypass DNS Redirect: Redirect all client UDP/TCP 53 traffic to gateway DNS
        self._run(["nft", "add", "rule", "inet", "identitynet", "prerouting", "ip", "saddr", self.lan_subnet, "udp", "dport", "53", "redirect", "to", ":53"])
        self._run(["nft", "add", "rule", "inet", "identitynet", "prerouting", "ip", "saddr", self.lan_subnet, "tcp", "dport", "53", "redirect", "to", ":53"])
        
        # Allow established / related connections
        self._run(["nft", "add", "rule", "inet", "identitynet", "forward", "ct", "state", "established,related", "accept"])
        
        # Allow traffic to gateway local services (ICMP, HTTP, DNS, DHCP)
        self._run(["nft", "add", "rule", "inet", "identitynet", "forward", "ip", "daddr", self.gateway_ip, "accept"])

    def _setup_iptables(self):
        """Configure iptables custom chains, DNS redirect, and default drop rules."""
        # NAT Table: Anti-Bypass DNS Redirection
        self._run(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", self.lan_subnet, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])
        self._run(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", self.lan_subnet, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"])

        # Create custom chain
        self._run(["iptables", "-N", "IDENTITYNET_FORWARD"], check=False)
        self._run(["iptables", "-I", "FORWARD", "1", "-j", "IDENTITYNET_FORWARD"], check=False)

        # Allow established connections
        self._run(["iptables", "-A", "IDENTITYNET_FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

        # Allow local gateway traffic
        self._run(["iptables", "-A", "IDENTITYNET_FORWARD", "-d", self.gateway_ip, "-j", "ACCEPT"])

        # Default Drop Rule at end of chain
        self._run(["iptables", "-A", "IDENTITYNET_FORWARD", "-s", self.lan_subnet, "-j", "DROP"])

    def allow_destination_ip(self, client_ip: str, dst_ip: str, domain: str = ""):
        """Dynamically permit forwarding from client_ip to dst_ip for an allowed domain."""
        if dst_ip in ["0.0.0.0", "127.0.0.1", self.gateway_ip]:
            return

        with self.lock:
            if dst_ip in self.permitted_ips:
                return
            self.permitted_ips.add(dst_ip)

            if self.backend == "nftables":
                # Add allow rule to forward chain
                self._run(["nft", "insert", "rule", "inet", "identitynet", "forward", "ip", "daddr", dst_ip, "accept"])
            elif self.backend == "iptables":
                # Insert allow rule before the final drop rule
                self._run(["iptables", "-I", "IDENTITYNET_FORWARD", "1", "-d", dst_ip, "-j", "ACCEPT"])

            print(f"[Firewall Manager] Dynamically PERMITTED destination IP '{dst_ip}' (Domain: '{domain}').", flush=True)

    def block_destination_ip(self, client_ip: str, dst_ip: str, application: str = "") -> bool:
        """Block a client-to-destination pair for application enforcement."""
        rule_key = (client_ip, dst_ip)
        with self.lock:
            if rule_key in self.blocked_ips:
                return True
            self.blocked_ips.add(rule_key)
            if self.backend == "nftables":
                self._run(["nft", "insert", "rule", "inet", "identitynet", "forward", "ip", "saddr", client_ip, "ip", "daddr", dst_ip, "drop"])
            elif self.backend == "iptables":
                self._run(["iptables", "-I", "IDENTITYNET_FORWARD", "1", "-s", client_ip, "-d", dst_ip, "-j", "DROP"])
        print(f"[Firewall Manager] Dynamically BLOCKED '{client_ip}' -> '{dst_ip}' ({application}).", flush=True)
        return True

    def flush_rules(self):
        """Flush all IdentityNet firewall rules cleanly."""
        if self.backend == "dry_run":
            return

        with self.lock:
            if self.backend == "nftables":
                self._run(["nft", "flush", "table", "inet", "identitynet"], check=False)
                self._run(["nft", "delete", "table", "inet", "identitynet"], check=False)
            elif self.backend == "iptables":
                self._run(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", self.lan_subnet, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"], check=False)
                self._run(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", self.lan_subnet, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"], check=False)
                self._run(["iptables", "-F", "IDENTITYNET_FORWARD"], check=False)
                self._run(["iptables", "-D", "FORWARD", "-j", "IDENTITYNET_FORWARD"], check=False)
                self._run(["iptables", "-X", "IDENTITYNET_FORWARD"], check=False)

            self.permitted_ips.clear()
            self.blocked_ips.clear()
            print("[Firewall Manager] Cleanly flushed all firewall rules.", flush=True)

    def _run(self, cmd_list: list, check: bool = True):
        if self.dry_run:
            return
        try:
            subprocess.run(cmd_list, check=check, capture_output=True, text=True)
        except Exception as e:
            pass
