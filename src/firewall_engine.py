import subprocess
import shutil
import sys
from typing import Set, Tuple

class FirewallEngine:
    """
    Linux Firewall Engine for IdentityNet.
    Uses nftables (preferred) or iptables to dynamically enforce traffic filtering rules.
    Supports dry-run mode for simulation/testing without sudo.
    """
    def __init__(self, dry_run: bool = False, logger=None):
        self.dry_run = dry_run
        self.logger = logger
        self.active_blocks: Set[Tuple[str, str]] = set()  # (src_ip, dst_ip)
        self.backend = self._detect_backend()

    def _detect_backend(self) -> str:
        """
        Detect whether nftables or iptables is available on the host system.
        """
        if self.dry_run:
            return "dry_run"
            
        if shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        else:
            if self.logger:
                self.logger.log_system("WARN", "Neither nftables nor iptables found. Falling back to dry-run simulation mode.")
            return "dry_run"

    def initialize(self):
        """
        Initialize custom firewall tables/chains for IdentityNet.
        """
        if self.backend == "nftables":
            self._run_cmd(["nft", "add", "table", "inet", "identitynet"])
            self._run_cmd(["nft", "add", "chain", "inet", "identitynet", "filter", "{ type filter hook forward priority 0; policy accept; }"])
            if self.logger:
                self.logger.log_system("INFO", "Initialized nftables firewall chain 'inet identitynet filter'.")
                
        elif self.backend == "iptables":
            # Create custom chain if not exists
            self._run_cmd(["iptables", "-N", "IDENTITYNET_FW"], check=False)
            # Insert chain into FORWARD table if not present
            res = subprocess.run(["iptables", "-C", "FORWARD", "-j", "IDENTITYNET_FW"], capture_output=True)
            if res.returncode != 0:
                self._run_cmd(["iptables", "-I", "FORWARD", "1", "-j", "IDENTITYNET_FW"])
            if self.logger:
                self.logger.log_system("INFO", "Initialized iptables firewall chain 'IDENTITYNET_FW'.")
        else:
            if self.logger:
                self.logger.log_system("INFO", "Firewall Engine initialized in DRY-RUN mode.")

    def block_traffic(self, src_ip: str, dst_ip: str, reason: str = ""):
        """
        Dynamically block IPv4 traffic from src_ip to dst_ip.
        """
        rule_key = (src_ip, dst_ip)
        if rule_key in self.active_blocks:
            return  # Rule already enforced

        self.active_blocks.add(rule_key)
        
        if self.backend == "nftables":
            # nft add rule inet identitynet filter ip saddr <src_ip> ip daddr <dst_ip> drop
            cmd = ["nft", "add", "rule", "inet", "identitynet", "filter", "ip", "saddr", src_ip, "ip", "daddr", dst_ip, "drop"]
            self._run_cmd(cmd)
            
        elif self.backend == "iptables":
            # iptables -A IDENTITYNET_FW -s <src_ip> -d <dst_ip> -j DROP
            cmd = ["iptables", "-A", "IDENTITYNET_FW", "-s", src_ip, "-d", dst_ip, "-j", "DROP"]
            self._run_cmd(cmd)

        if self.logger:
            self.logger.log_system("INFO", f"Enforced FIREWALL DROP rule: {src_ip} -> {dst_ip} ({self.backend})")

    def flush_rules(self):
        """
        Flush all IdentityNet rules and cleanup chains.
        """
        if not self.active_blocks:
            return

        if self.backend == "nftables":
            self._run_cmd(["nft", "flush", "table", "inet", "identitynet"], check=False)
            self._run_cmd(["nft", "delete", "table", "inet", "identitynet"], check=False)
        elif self.backend == "iptables":
            self._run_cmd(["iptables", "-F", "IDENTITYNET_FW"], check=False)
            self._run_cmd(["iptables", "-D", "FORWARD", "-j", "IDENTITYNET_FW"], check=False)
            self._run_cmd(["iptables", "-X", "IDENTITYNET_FW"], check=False)

        self.active_blocks.clear()
        if self.logger:
            self.logger.log_system("INFO", "Flushed all IdentityNet firewall rules cleanly.")

    def _run_cmd(self, cmd_list, check=True):
        """
        Execute system command safely.
        """
        if self.dry_run:
            if self.logger:
                self.logger.log_system("DEBUG", f"[DRY-RUN CMD] {' '.join(cmd_list)}")
            return
            
        try:
            subprocess.run(cmd_list, check=check, capture_output=True, text=True)
        except Exception as e:
            if self.logger:
                self.logger.log_system("WARN", f"Firewall command failed ({' '.join(cmd_list)}): {e}")
