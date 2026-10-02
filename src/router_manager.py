import os
import subprocess
import shutil

class RouterManager:
    """
    Routing & NAT Manager for IdentityNet Gateway.
    Enables kernel IPv4 forwarding and configures NAT Masquerade on WAN interface.
    """
    def __init__(self, wan_interface: str = "eth0", lan_interface: str = "eth1", dry_run: bool = False):
        self.wan_interface = wan_interface
        self.lan_interface = lan_interface
        self.dry_run = dry_run
        self._orig_forwarding = "0"

    def enable_routing_and_nat(self):
        """Enable IPv4 forwarding and NAT masquerade."""
        if self.dry_run or os.name == "nt":
            if os.name == "nt" and not self.dry_run:
                print("[Router Manager] Windows Mobile Hotspot/ICS must provide routing and NAT.", flush=True)
            else:
                print("[Router Manager] Operating in DRY-RUN mode. Kernel forwarding skipped.", flush=True)
            return

        # 1. IPv4 Forwarding
        try:
            if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    self._orig_forwarding = f.read().strip()
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1\n")
            else:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True)
            print("[Router Manager] Kernel IPv4 Forwarding ENABLED.", flush=True)
        except Exception as e:
            print(f"[Router Manager] Warning: Could not set ip_forwarding: {e}", flush=True)

        # 2. NAT Masquerade on WAN Interface
        try:
            if shutil.which("nft"):
                subprocess.run(["nft", "add", "table", "ip", "identitynet_nat"], check=False)
                subprocess.run(["nft", "add", "chain", "ip", "identitynet_nat", "postrouting", "{ type nat hook postrouting priority 100; }"], check=False)
                subprocess.run(["nft", "add", "rule", "ip", "identitynet_nat", "postrouting", "oifname", self.wan_interface, "masquerade"], check=False)
                print(f"[Router Manager] Configured nftables NAT Masquerade on '{self.wan_interface}'.", flush=True)
            elif shutil.which("iptables"):
                subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", self.wan_interface, "-j", "MASQUERADE"], check=False)
                print(f"[Router Manager] Configured iptables NAT Masquerade on '{self.wan_interface}'.", flush=True)
        except Exception as e:
            print(f"[Router Manager] Warning: NAT setup failed: {e}", flush=True)

    def cleanup(self):
        """Restore original forwarding state."""
        if self.dry_run or os.name == "nt":
            return
        try:
            if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(f"{self._orig_forwarding}\n")
            if shutil.which("nft"):
                subprocess.run(["nft", "flush", "table", "ip", "identitynet_nat"], check=False)
                subprocess.run(["nft", "delete", "table", "ip", "identitynet_nat"], check=False)
            elif shutil.which("iptables"):
                subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", self.wan_interface, "-j", "MASQUERADE"], check=False)
            print("[Router Manager] Restored routing and NAT state.", flush=True)
        except Exception:
            pass
