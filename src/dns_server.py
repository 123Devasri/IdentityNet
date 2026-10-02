import socket
import threading
import time
import struct
from typing import Dict, Optional, Callable, List

from app_classifier import ApplicationClassifier
from dns_cache import DNSCache

class DNSFilterServer:
    """
    IdentityNet DNS Resolver & Policy Filter Server.
    Listens on UDP port 53. Intercepts DNS queries, resolves local contest domains,
    enforces allowlist policy on external domains, dynamically notifies Firewall Manager of allowed IPs,
    and returns 0.0.0.0 for unauthorized queries.
    """
    def __init__(self,
                 policy_engine,
                 firewall_manager,
                 db_manager,
                 host: str = "0.0.0.0",
                 port: int = 53,
                 gateway_ip: str = "192.168.50.1",
                 upstream_dns: str = "8.8.8.8",
                 application_classifier: Optional[ApplicationClassifier] = None,
                 dns_cache: Optional[DNSCache] = None):
        self.policy_engine = policy_engine
        self.firewall_manager = firewall_manager
        self.db_manager = db_manager
        self.host = host
        self.port = port
        self.gateway_ip = gateway_ip
        self.upstream_dns = upstream_dns
        self.application_classifier = application_classifier
        self.dns_cache = dns_cache

        self.running = False
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Start UDP DNS Server thread."""
        if self.running:
            return
        self.running = True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.thread = threading.Thread(target=self._serve_loop, daemon=True)
            self.thread.start()
            print(f"[DNS Server] Listening on {self.host}:{self.port} (Gateway IP: {self.gateway_ip})...", flush=True)
        except Exception as e:
            print(f"[DNS Server] Warning: Could not bind to port {self.port}: {e}. (Run with sudo for port 53)", flush=True)

    def stop(self):
        """Stop DNS server."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def _serve_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                if not data:
                    continue
                threading.Thread(target=self._handle_dns_query, args=(data, addr), daemon=True).start()
            except Exception:
                if not self.running:
                    break

    def _handle_dns_query(self, data: bytes, client_addr: tuple):
        """Parse raw DNS query, evaluate policy, and construct reply."""
        client_ip = client_addr[0]
        try:
            transaction_id = data[:2]
            domain, query_type = self._parse_dns_query(data)
            if not domain:
                return

            # Evaluate Policy
            action, reason = self.policy_engine.evaluate(domain, client_ip)
            application_match = self.application_classifier.classify_domain(domain, "DNS_QUERY") if self.application_classifier else None
            if application_match:
                app_action, app_reason = self.policy_engine.evaluate_application(
                    application_match.application, application_match.category, client_ip
                )
                if app_action == "BLOCKED":
                    response = self._build_dns_response(data, "0.0.0.0")
                    self.sock.sendto(response, client_addr)
                    self._log_application(client_ip, application_match, "BLOCKED")
                    return

            # Local Gateway Domains
            if domain in ["contest.identitynet.local", "exam.identitynet.local"]:
                response = self._build_dns_response(data, self.gateway_ip)
                self.sock.sendto(response, client_addr)
                self.db_manager.log_network_event(client_ip, domain, "ALLOWED", "Local gateway domain")
                return

            if action == "ALLOWED":
                # Forward query to Upstream DNS (e.g. 8.8.8.8)
                upstream_response, resolved_ips = self._forward_upstream_dns(data)
                if upstream_response:
                    # Dynamically allow resolved destination IPs in Firewall Manager
                    for ip in resolved_ips:
                        if self.dns_cache:
                            self.dns_cache.put(
                                domain,
                                ip,
                                application_match.application if application_match else None,
                                application_match.category if application_match else None,
                            )
                        self.firewall_manager.allow_destination_ip(client_ip, ip, domain)
                    
                    self.sock.sendto(upstream_response, client_addr)
                    self.db_manager.log_network_event(client_ip, domain, "ALLOWED", f"Resolved to {resolved_ips}")
                    if application_match:
                        self._log_application(client_ip, application_match, "ALLOWED")
                else:
                    # Fallback to gateway IP if upstream fails
                    response = self._build_dns_response(data, "0.0.0.0")
                    self.sock.sendto(response, client_addr)
                    self.db_manager.log_network_event(client_ip, domain, "BLOCKED", "Upstream DNS resolution failed")
            else:
                # BLOCKED Domain -> Return 0.0.0.0
                response = self._build_dns_response(data, "0.0.0.0")
                self.sock.sendto(response, client_addr)
                self.db_manager.log_network_event(client_ip, domain, "BLOCKED", reason)

        except Exception as e:
            pass

    def _log_application(self, client_ip: str, match, action: str) -> None:
        if hasattr(self.db_manager, "log_application_event"):
            self.db_manager.log_application_event(
                client_ip, match.application, match.category, match.detection_method, action
            )

    def _parse_dns_query(self, data: bytes) -> tuple:
        """Extract requested domain name and record type from raw DNS header."""
        try:
            # Header is 12 bytes
            idx = 12
            labels = []
            while idx < len(data):
                length = data[idx]
                if length == 0:
                    idx += 1
                    break
                labels.append(data[idx+1:idx+1+length].decode('utf-8', errors='ignore'))
                idx += 1 + length
            domain = ".".join(labels).lower()
            query_type = struct.unpack(">H", data[idx:idx+2])[0] if idx+2 <= len(data) else 1
            return domain, query_type
        except Exception:
            return "", 1

    def _build_dns_response(self, query_data: bytes, ip_address: str) -> bytes:
        """Construct raw DNS response packet with A record."""
        try:
            transaction_id = query_data[:2]
            flags = b"\x81\x80"  # Standard query response, No error
            qdcount = b"\x00\x01"
            ancount = b"\x00\x01"
            nscount = b"\x00\x00"
            arcount = b"\x00\x00"

            # Locate Question section
            idx = 12
            while idx < len(query_data) and query_data[idx] != 0:
                idx += 1 + query_data[idx]
            idx += 5  # Null byte + qtype (2) + qclass (2)
            question_section = query_data[12:idx]

            # Answer section (A record)
            name_ptr = b"\xc0\x0c"  # Pointer to qname
            type_a = b"\x00\x01"    # A record
            class_in = b"\x00\x01"  # IN class
            ttl = b"\x00\x00\x00\x3c"  # TTL 60 seconds
            rdlength = b"\x00\x04"  # 4 bytes IPv4
            rdata = socket.inet_aton(ip_address)

            answer_section = name_ptr + type_a + class_in + ttl + rdlength + rdata
            return transaction_id + flags + qcount_ans(query_data) + question_section + answer_section
        except Exception:
            return query_data

    def _forward_upstream_dns(self, query_data: bytes) -> tuple:
        """Forward DNS query packet to upstream resolver and extract IPv4 A records."""
        resolved_ips = []
        try:
            up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up_sock.settimeout(2.0)
            up_sock.sendto(query_data, (self.upstream_dns, 53))
            resp_data, _ = up_sock.recvfrom(2048)
            up_sock.close()

            # Extract resolved IPv4 addresses from response
            idx = 12
            # Skip Question section
            while idx < len(resp_data) and resp_data[idx] != 0:
                idx += 1 + resp_data[idx]
            idx += 5

            ancount = struct.unpack(">H", resp_data[6:8])[0]
            for _ in range(ancount):
                if idx >= len(resp_data):
                    break
                # Skip Name
                if resp_data[idx] >= 192:  # Compressed pointer
                    idx += 2
                else:
                    while idx < len(resp_data) and resp_data[idx] != 0:
                        idx += 1 + resp_data[idx]
                    idx += 1
                
                rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp_data[idx:idx+10])
                idx += 10
                if rtype == 1 and rdlen == 4:  # A record
                    ip_bytes = resp_data[idx:idx+4]
                    resolved_ips.append(socket.inet_ntoa(ip_bytes))
                idx += rdlen

            return resp_data, resolved_ips
        except Exception:
            return None, []

def qcount_ans(query_data: bytes) -> bytes:
    """Helper to return Question & Answer counts."""
    return b"\x00\x01\x00\x01\x00\x00\x00\x00"
