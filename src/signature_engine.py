"""Application signature loading and wildcard matching."""

import fnmatch
import json
import os
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class ApplicationSignature:
    name: str
    category: str
    domains: List[str]


class SignatureEngine:
    def __init__(self, signature_file: Optional[str] = None):
        default_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config/application_signatures.json"))
        self.signature_file = os.path.abspath(signature_file or default_file)
        self.signatures = self._load()

    def _load(self) -> List[ApplicationSignature]:
        with open(self.signature_file, "r", encoding="utf-8") as file:
            data = json.load(file)
        return [
            ApplicationSignature(
                name=item["name"],
                category=item["category"],
                domains=[self._clean_domain(pattern) for pattern in item.get("domains", [])],
            )
            for item in data.get("applications", [])
        ]

    @staticmethod
    def _clean_domain(domain: str) -> str:
        return domain.strip().lower().rstrip(".")

    def match(self, domain: str) -> Optional[ApplicationSignature]:
        domain = self._clean_domain(domain)
        if not domain:
            return None
        for signature in self.signatures:
            for pattern in signature.domains:
                if pattern == "*" or fnmatch.fnmatch(domain, pattern):
                    return signature
                if pattern.startswith("*.") and domain.endswith(pattern[1:]):
                    return signature
        return None

    def reload(self) -> None:
        self.signatures = self._load()
