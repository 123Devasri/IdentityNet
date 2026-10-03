"""Classify network packets using DNS, TLS SNI, and DNS-IP correlation."""

from dataclasses import dataclass
import threading
from typing import Dict, List, Optional, Tuple

from dns_cache import DNSCache
from signature_engine import ApplicationSignature, SignatureEngine
from tls_sni_inspector import TLSSNIInspector

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass(frozen=True)
class ApplicationMatch:
    application: str
    category: str
    domain: str
    detection_method: str


class ApplicationClassifier:
    def __init__(self, signature_engine: SignatureEngine, dns_cache: DNSCache):
        self.signature_engine = signature_engine
        self.dns_cache = dns_cache
        self.tls_inspector = TLSSNIInspector()
        self._tls_buffers: Dict[Tuple[str, int, str, int], Tuple[int, bytearray]] = {}
        self._tls_lock = threading.RLock()

    def classify_domain(self, domain: str, method: str = "DNS") -> Optional[ApplicationMatch]:
        matches = self.classify_domain_candidates(domain, method)
        return matches[0] if matches else None

    def classify_domain_candidates(self, domain: str, method: str = "DNS") -> List[ApplicationMatch]:
        return [
            ApplicationMatch(signature.name, signature.category, domain.lower().rstrip("."), method)
            for signature in self.signature_engine.match_all(domain)
        ]

    def classify_packet(self, packet) -> Optional[ApplicationMatch]:
        matches = self.classify_packet_candidates(packet)
        return matches[0] if matches else None

    def classify_packet_candidates(self, packet) -> List[ApplicationMatch]:
        """Return every application associated with a packet's domain or IP."""
        if not SCAPY_AVAILABLE or packet is None or not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return []
        network_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        destination_ip = network_layer.dst

        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0 and packet.haslayer(DNSQR):
                domain = dns_layer[DNSQR].qname.decode(errors="ignore").rstrip(".")
                matches = self.classify_domain_candidates(domain, "DNS_QUERY")
                if matches:
                    return matches
            if dns_layer.qr == 1 and dns_layer.qd and packet.haslayer(DNSRR):
                domain = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
                matches = self.classify_domain_candidates(domain, "DNS_RESPONSE")
                if matches:
                    answer = dns_layer.an
                    for index in range(int(dns_layer.ancount or 0)):
                        record = answer[index]
                        if getattr(record, "type", None) in {1, 28}:
                            for match in matches:
                                self.dns_cache.put(domain, str(record.rdata), match.application, match.category)
                    return matches

        if packet.haslayer(TCP) and packet.haslayer(Raw):
            sni = self._extract_stream_sni(packet)
            if sni:
                matches = self.classify_domain_candidates(sni, "TLS_SNI")
                if matches:
                    for match in matches:
                        self.dns_cache.put(sni, destination_ip, match.application, match.category)
                    return matches

        return [
            ApplicationMatch(entry.application, entry.category, entry.domain, "DNS_IP_CACHE")
            for entry in self.dns_cache.get_all(destination_ip)
            if entry.application and entry.category
        ]

    def _extract_stream_sni(self, packet) -> Optional[str]:
        tcp = packet[TCP]
        payload = bytes(packet[Raw])
        network_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        flow_key = (network_layer.src, tcp.sport, network_layer.dst, tcp.dport)
        sequence = int(tcp.seq)
        with self._tls_lock:
            state = self._tls_buffers.get(flow_key)
            if state is None or sequence > state[0]:
                next_sequence = sequence + len(payload)
                buffer = bytearray(payload)
                self._tls_buffers[flow_key] = (next_sequence, buffer)
            elif sequence == state[0]:
                next_sequence = sequence + len(payload)
                buffer = state[1]
                buffer.extend(payload)
                self._tls_buffers[flow_key] = (next_sequence, buffer)
            else:
                return None

            buffer = self._tls_buffers[flow_key][1]
            if len(buffer) > 65536:
                del self._tls_buffers[flow_key]
                return None
            sni = self.tls_inspector.extract_sni(bytes(buffer))
            if sni:
                del self._tls_buffers[flow_key]
            return sni
