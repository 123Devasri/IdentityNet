import json
import os
import fnmatch
import threading
from typing import Dict, Any, List, Tuple, Callable, Optional

POLICY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config/policy.json"))

class PolicyEngine:
    """
    Control Plane Policy Engine for IdentityNet.
    Manages allowlist network policies, evaluates domain requests,
    and broadcasts dynamic policy changes to network enforcement layers.
    """
    def __init__(self, policy_file: str = POLICY_PATH, event_logger: Optional[Callable] = None):
        self.policy_file = os.path.abspath(policy_file)
        self.event_logger = event_logger
        self.lock = threading.Lock()
        
        self.active_profile_name = "contest-2026"
        self.mode = "allowlist"
        self.allowed_domains: List[str] = []
        self.blocked_explicit: List[str] = []
        
        self.change_listeners: List[Callable] = []
        self.reload_policy()

    def reload_policy(self):
        """Reload configuration from policy.json."""
        with self.lock:
            if not os.path.exists(self.policy_file):
                raise FileNotFoundError(f"Policy file not found: {self.policy_file}")
                
            with open(self.policy_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            self.active_profile_name = data.get("active_profile", "contest-2026")
            self.mode = data.get("mode", "allowlist")
            
            profiles = data.get("profiles", {})
            profile = profiles.get(self.active_profile_name, {})
            
            self.allowed_domains = profile.get("allowed", [
                "contest.identitynet.local",
                "exam.identitynet.local"
            ])
            self.blocked_explicit = profile.get("blocked_explicit", [])

        self._notify_listeners()

    def register_change_listener(self, callback: Callable):
        """Register a callback function to be invoked when policy rules change."""
        self.change_listeners.append(callback)

    def _notify_listeners(self):
        """Invoke registered change listeners."""
        for callback in self.change_listeners:
            try:
                callback(self.allowed_domains)
            except Exception as e:
                pass

    def evaluate(self, domain: str, client_ip: str = "0.0.0.0") -> Tuple[str, str]:
        """
        Evaluate destination domain against active policy.
        Returns: Tuple (action ['ALLOWED'|'BLOCKED'], reason)
        """
        domain_clean = domain.lower().strip().rstrip(".")

        # 1. Local IdentityNet Gateway Domains (Always Allowed)
        if domain_clean in ["contest.identitynet.local", "exam.identitynet.local", "192.168.50.1", "localhost"]:
            reason = "Local IdentityNet Gateway destination"
            return "ALLOWED", reason

        # 2. Check Explicit Block List
        for pattern in self.blocked_explicit:
            if self._matches_pattern(domain_clean, pattern):
                reason = f"Explicitly blocked by policy rule '{pattern}'"
                if self.event_logger:
                    self.event_logger(client_ip, domain_clean, "BLOCKED", reason)
                return "BLOCKED", reason

        # 3. Check Allowed List
        for pattern in self.allowed_domains:
            if pattern == "*" or self._matches_pattern(domain_clean, pattern):
                reason = f"Matched allowed domain policy '{pattern}'"
                if self.event_logger:
                    self.event_logger(client_ip, domain_clean, "ALLOWED", reason)
                return "ALLOWED", reason

        # 4. Default-Deny Policy Enforcement
        reason = f"Default-deny policy enforced (domain '{domain_clean}' not in allowlist)"
        if self.event_logger:
            self.event_logger(client_ip, domain_clean, "BLOCKED", reason)
        return "BLOCKED", reason

    def _matches_pattern(self, domain: str, pattern: str) -> bool:
        """Check if domain matches pattern (exact, wildcard, or domain hierarchy)."""
        pattern = pattern.lower().strip()
        if pattern == "*":
            return True
        if fnmatch.fnmatch(domain, pattern):
            return True
        if pattern.startswith("*."):
            base = pattern[2:]
            if domain == base or domain.endswith("." + base):
                return True
        return False

    def add_allowed_domain(self, domain: str) -> bool:
        """Dynamically add a domain to active policy allowlist."""
        domain_clean = domain.lower().strip().rstrip(".")
        with self.lock:
            if domain_clean not in self.allowed_domains:
                self.allowed_domains.append(domain_clean)
                self._save_policy_to_disk()
                self._notify_listeners()
                return True
        return False

    def remove_allowed_domain(self, domain: str) -> bool:
        """Dynamically remove a domain from active policy allowlist."""
        domain_clean = domain.lower().strip().rstrip(".")
        with self.lock:
            if domain_clean in self.allowed_domains:
                self.allowed_domains.remove(domain_clean)
                self._save_policy_to_disk()
                self._notify_listeners()
                return True
        return False

    def set_active_profile(self, profile_name: str) -> bool:
        """Switch active policy profile (e.g., 'contest-2026' or 'exam-2026')."""
        with self.lock:
            if not os.path.exists(self.policy_file):
                return False
            with open(self.policy_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if profile_name in data.get("profiles", {}):
                data["active_profile"] = profile_name
                with open(self.policy_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                self.active_profile_name = profile_name
                self.reload_policy()
                return True
        return False

    def _save_policy_to_disk(self):
        """Save updated policy structure back to policy.json."""
        if not os.path.exists(self.policy_file):
            return
        with open(self.policy_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if self.active_profile_name in data.get("profiles", {}):
            data["profiles"][self.active_profile_name]["allowed"] = self.allowed_domains
            data["profiles"][self.active_profile_name]["blocked_explicit"] = self.blocked_explicit

        with open(self.policy_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
