import threading
from typing import Optional, Dict

try:
    from scapy.all import Packet, DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = object

class DNSInspector:
    """
    DNS & TLS SNI Inspection Engine for IdentityNet.
    Extracts requested domains from live DNS queries/responses and TLS Client Hello packets.
    Maintains a dynamic IP-to-Domain mapping cache.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self._ip_to_domain: Dict[str, str] = {}

    def register_ip_domain(self, ip: str, domain: str):
        """
        Manually or dynamically register an IP to domain mapping.
        """
        domain_clean = domain.rstrip(".").lower()
        with self.lock:
            self._ip_to_domain[ip] = domain_clean

    def get_domain_for_ip(self, ip: str) -> Optional[str]:
        """
        Lookup cached domain for a target IP address.
        """
        with self.lock:
            return self._ip_to_domain.get(ip)

    def inspect_packet(self, packet) -> Optional[str]:
        """
        Inspect a Scapy packet to extract domain name if present via DNS, TLS SNI, or HTTP Host.
        """
        if not SCAPY_AVAILABLE or packet is None:
            return None

        domain = None

        # 1. DNS Packet Inspection
        if hasattr(packet, "haslayer") and packet.haslayer(DNS):
            dns_layer = packet[DNS]
            
            # DNS Query
            if dns_layer.qr == 0 and packet.haslayer(DNSQR):
                qname = dns_layer[DNSQR].qname.decode('utf-8', errors='ignore').rstrip(".")
                domain = qname.lower()
                
            # DNS Response - map resolved A records to domain name
            elif dns_layer.qr == 1 and packet.haslayer(DNSRR):
                qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip(".").lower() if dns_layer.qd else ""
                for i in range(dns_layer.ancount):
                    rr = dns_layer.an[i]
                    if rr.type == 1:  # A record (IPv4)
                        resolved_ip = rr.rdata
                        if isinstance(resolved_ip, str):
                            self.register_ip_domain(resolved_ip, qname)
                if qname:
                    domain = qname

        # 2. TLS Client Hello SNI (HTTPS port 443)
        if not domain and hasattr(packet, "haslayer") and packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            domain = self._extract_tls_sni(payload)

        # 3. HTTP Host Header (HTTP port 80)
        if not domain and hasattr(packet, "haslayer") and packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            domain = self._extract_http_host(payload)

        # 4. Fallback to cached IP-to-Domain mapping
        if not domain and hasattr(packet, "haslayer") and packet.haslayer(IP):
            dst_ip = packet[IP].dst
            domain = self.get_domain_for_ip(dst_ip)

        return domain

    def _extract_tls_sni(self, payload: bytes) -> Optional[str]:
        """
        Extract Server Name Indication (SNI) from TLS Client Hello handshake payload.
        """
        try:
            if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
                return None
            
            session_id_len = payload[43]
            offset = 44 + session_id_len
            if len(payload) < offset + 2:
                return None
                
            cipher_suites_len = int.from_bytes(payload[offset:offset+2], 'big')
            offset += 2 + cipher_suites_len
            if len(payload) < offset + 1:
                return None
                
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            if len(payload) < offset + 2:
                return None
                
            extensions_len = int.from_bytes(payload[offset:offset+2], 'big')
            offset += 2
            ext_end = offset + extensions_len
            
            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type = int.from_bytes(payload[offset:offset+2], 'big')
                ext_len = int.from_bytes(payload[offset+2:offset+4], 'big')
                offset += 4
                
                # SNI Extension Type is 0x0000
                if ext_type == 0:
                    if offset + 5 <= len(payload):
                        sni_len = int.from_bytes(payload[offset+3:offset+5], 'big')
                        sni_bytes = payload[offset+5:offset+5+sni_len]
                        return sni_bytes.decode('utf-8', errors='ignore').lower()
                offset += ext_len
        except Exception:
            pass
        return None

    def _extract_http_host(self, payload: bytes) -> Optional[str]:
        """
        Extract Host header from plain HTTP GET/POST payload.
        """
        try:
            text = payload.decode('utf-8', errors='ignore')
            lines = text.split("\r\n")
            for line in lines:
                if line.lower().startswith("host:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        host = parts[1].strip().split(":")[0]
                        return host.lower()
        except Exception:
            pass
        return None
