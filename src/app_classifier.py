"""Classify network packets using DNS, TLS SNI, and DNS-IP correlation."""

from dataclasses import dataclass
from typing import Optional

from dns_cache import DNSCache
from signature_engine import ApplicationSignature, SignatureEngine
from tls_sni_inspector import TLSSNIInspector

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP, UDP
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

    def classify_domain(self, domain: str, method: str = "DNS") -> Optional[ApplicationMatch]:
        signature = self.signature_engine.match(domain)
        if not signature:
            return None
        return ApplicationMatch(signature.name, signature.category, domain.lower().rstrip("."), method)

    def classify_packet(self, packet) -> Optional[ApplicationMatch]:
        if not SCAPY_AVAILABLE or packet is None or not packet.haslayer(IP):
            return None
        destination_ip = packet[IP].dst

        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0 and packet.haslayer(DNSQR):
                domain = dns_layer[DNSQR].qname.decode(errors="ignore").rstrip(".")
                match = self.classify_domain(domain, "DNS_QUERY")
                if match:
                    return match
            if dns_layer.qr == 1 and dns_layer.qd and packet.haslayer(DNSRR):
                domain = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
                match = self.classify_domain(domain, "DNS_RESPONSE")
                if match:
                    answer = dns_layer.an
                    for index in range(int(dns_layer.ancount or 0)):
                        record = answer[index]
                        if getattr(record, "type", None) == 1:
                            self.dns_cache.put(domain, str(record.rdata), match.application, match.category)
                    return match

        if packet.haslayer(TCP) and packet.haslayer(Raw):
            sni = self.tls_inspector.extract_sni(bytes(packet[Raw]))
            if sni:
                match = self.classify_domain(sni, "TLS_SNI")
                if match:
                    self.dns_cache.put(sni, destination_ip, match.application, match.category)
                    return match

        cached = self.dns_cache.get(destination_ip)
        if cached and cached.application and cached.category:
            return ApplicationMatch(cached.application, cached.category, cached.domain, "DNS_IP_CACHE")
        return None
