"""Thread-safe DNS-to-application correlation cache."""

from dataclasses import dataclass
import threading
import time
from typing import Dict, Optional


@dataclass(frozen=True)
class DNSCacheEntry:
    domain: str
    ip_address: str
    application: Optional[str]
    category: Optional[str]
    expires_at: float


class DNSCache:
    """Correlate resolved addresses with the application that owns a domain."""

    def __init__(self, default_ttl: int = 300):
        self.default_ttl = default_ttl
        self._entries: Dict[str, DNSCacheEntry] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _clean_domain(domain: str) -> str:
        return domain.strip().lower().rstrip(".")

    def put(self, domain: str, ip_address: str, application=None, category=None, ttl=None) -> None:
        domain = self._clean_domain(domain)
        if not domain or not ip_address:
            return
        expires_at = time.monotonic() + (ttl or self.default_ttl)
        entry = DNSCacheEntry(domain, ip_address, application, category, expires_at)
        with self._lock:
            self._entries[ip_address] = entry

    def get(self, ip_address: str) -> Optional[DNSCacheEntry]:
        with self._lock:
            entry = self._entries.get(ip_address)
            if not entry:
                return None
            if entry.expires_at <= time.monotonic():
                del self._entries[ip_address]
                return None
            return entry

    def get_application(self, ip_address: str) -> Optional[str]:
        entry = self.get(ip_address)
        return entry.application if entry else None

    def purge_expired(self) -> int:
        now = time.monotonic()
        with self._lock:
            expired = [ip for ip, entry in self._entries.items() if entry.expires_at <= now]
            for ip in expired:
                del self._entries[ip]
            return len(expired)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
