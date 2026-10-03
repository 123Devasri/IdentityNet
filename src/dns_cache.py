"""Thread-safe DNS-to-application correlation cache."""

from dataclasses import dataclass
import threading
import time
from typing import Dict, List, Optional, Set


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
        self._entries: Dict[str, Set[DNSCacheEntry]] = {}
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
            entries = self._entries.setdefault(ip_address, set())
            entries_copy = {
                existing for existing in entries
                if existing.expires_at > time.monotonic()
                and not (existing.application == application and existing.category == category)
            }
            entries_copy.add(entry)
            self._entries[ip_address] = entries_copy

    def get(self, ip_address: str) -> Optional[DNSCacheEntry]:
        entries = self.get_all(ip_address)
        return entries[0] if entries else None

    def get_all(self, ip_address: str) -> List[DNSCacheEntry]:
        with self._lock:
            entries = self._entries.get(ip_address, set())
            valid_entries = [entry for entry in entries if entry.expires_at > time.monotonic()]
            if valid_entries:
                self._entries[ip_address] = set(valid_entries)
            else:
                self._entries.pop(ip_address, None)
            return valid_entries

    def get_applications(self, ip_address: str) -> Set[str]:
        return {
            entry.application for entry in self.get_all(ip_address)
            if entry.application
        }

    def get_categories(self, ip_address: str) -> Set[str]:
        return {
            entry.category for entry in self.get_all(ip_address)
            if entry.category
        }

    def remove(self, ip_address: str) -> None:
        with self._lock:
            self._entries.pop(ip_address, None)

    def _remove_expired(self, ip_address: str) -> None:
        if not self._entries.get(ip_address):
            self._entries.pop(ip_address, None)
            return
        if all(entry.expires_at <= time.monotonic() for entry in self._entries[ip_address]):
            self._entries.pop(ip_address, None)

    def _legacy_get(self, ip_address: str) -> Optional[DNSCacheEntry]:
        """Retained internally for callers that need one representative entry."""
        entries = self.get_all(ip_address)
        return entries[0] if entries else None

    def get_application(self, ip_address: str) -> Optional[str]:
        entry = self.get(ip_address)
        return entry.application if entry else None

    def purge_expired(self) -> int:
        now = time.monotonic()
        with self._lock:
            expired = [
                ip for ip, entries in self._entries.items()
                if not any(entry.expires_at > now for entry in entries)
            ]
            for ip in expired:
                del self._entries[ip]
            return len(expired)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
