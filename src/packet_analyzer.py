from typing import Dict, Any, Optional

try:
    from scapy.all import Packet, IP, IPv6, TCP, UDP, ICMP, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = object

class PacketAnalyzer:
    """
    Packet Analyzer Engine for IdentityNet.
    Extracts L3/L4 headers, determines user identity, inspects domains,
    and applies policy decisions via Firewall and Logger engines.
    """
    def __init__(self, dns_inspector, policy_engine, firewall_engine, logger):
        self.dns_inspector = dns_inspector
        self.policy_engine = policy_engine
        self.firewall_engine = firewall_engine
        self.logger = logger

    def process_packet(self, packet):
        """
        Main entry point for packet processing.
        Parses packet layer headers and evaluates policy.
        """
        if not SCAPY_AVAILABLE or packet is None or not hasattr(packet, "haslayer"):
            return

        # We process IPv4 packets
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Determine L4 protocol and ports
        protocol = "IP"
        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if packet.haslayer(DNS):
                protocol = "DNS"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        # 1. DNS / Host / SNI Inspection
        domain = self.dns_inspector.inspect_packet(packet)
        if not domain:
            domain = self.dns_inspector.get_domain_for_ip(dst_ip) or f"ip:{dst_ip}"

        # 2. Evaluate Policy
        user_identity, action, reason = self.policy_engine.evaluate(src_ip, domain)

        # 3. Enforce Firewall Decision
        if action == "BLOCK":
            self.firewall_engine.block_traffic(src_ip, dst_ip, reason)

        # 4. Log Action
        proto_str = f"{protocol}:{dst_port}" if dst_port else protocol
        self.logger.log_traffic(
            user=user_identity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            domain=domain,
            protocol=proto_str,
            action=action,
            reason=reason
        )
