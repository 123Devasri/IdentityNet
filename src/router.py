import os
import subprocess
import shutil
from typing import List, Dict

class Router:
    """
    Routing & Gateway Module for IdentityNet.
    Enables Linux kernel IP Forwarding and configures NAT Masquerade on gateway interfaces.
    """
    def __init__(self, dry_run: bool = False, logger=None):
        self.dry_run = dry_run
        self.logger = logger
        self._original_ip_forward = "0"

    def enable_ip_forwarding(self):
        """
        Enable IPv4 forwarding in Linux kernel.
        """
        if self.dry_run:
            if self.logger:
                self.logger.log_system("INFO", "[DRY-RUN] IPv4 Forwarding enabled.")
            return

        # Record original setting
        try:
            if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    self._original_ip_forward = f.read().strip()
                
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1\n")
            else:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True)

            if self.logger:
                self.logger.log_system("INFO", "Linux Kernel IPv4 Forwarding successfully ENABLED.")
        except Exception as e:
            if self.logger:
                self.logger.log_system("WARN", f"Failed to set ip_forward: {e}. Ensure script is run with sudo.")

    def setup_nat_masquerade(self, wan_interface: str):
        """
        Configure NAT Masquerade on the WAN interface for client traffic reaching external Internet.
        """
        if self.dry_run or not wan_interface:
            return

        try:
            if shutil.which("iptables"):
                subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan_interface, "-j", "MASQUERADE"], check=False)
                if self.logger:
                    self.logger.log_system("INFO", f"Configured NAT Masquerade on interface '{wan_interface}'.")
            elif shutil.which("nft"):
                subprocess.run(["nft", "add", "table", "ip", "nat"], check=False)
                subprocess.run(["nft", "add", "chain", "ip", "nat", "postrouting", "{ type nat hook postrouting priority 100; }"], check=False)
                subprocess.run(["nft", "add", "rule", "ip", "nat", "postrouting", "oifname", wan_interface, "masquerade"], check=False)
                if self.logger:
                    self.logger.log_system("INFO", f"Configured nftables NAT Masquerade on interface '{wan_interface}'.")
        except Exception as e:
            if self.logger:
                self.logger.log_system("WARN", f"Failed to set NAT masquerade on interface {wan_interface}: {e}")

    def restore_ip_forwarding(self):
        """
        Restore original IPv4 forwarding setting.
        """
        if self.dry_run:
            return

        try:
            if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(f"{self._original_ip_forward}\n")
            if self.logger:
                self.logger.log_system("INFO", f"Restored IPv4 Forwarding to original state ({self._original_ip_forward}).")
        except Exception as e:
            pass

    @staticmethod
    def list_network_interfaces() -> List[str]:
        """
        List available active network interfaces on Linux.
        """
        interfaces = []
        try:
            if os.path.exists("/proc/net/dev"):
                with open("/proc/net/dev", "r") as f:
                    lines = f.readlines()[2:]  # Skip header lines
                    for line in lines:
                        ifname = line.split(":")[0].strip()
                        if ifname:
                            interfaces.append(ifname)
        except Exception:
            pass
        return interfaces if interfaces else ["eth0", "vboxnet0", "lo"]
