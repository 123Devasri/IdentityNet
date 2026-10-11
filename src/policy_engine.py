import json
import os
import fnmatch
import threading
from typing import Dict, Any, List, Tuple, Callable, Optional

POLICY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config/policy.json"))
LEGACY_POLICY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config/policies.json"))

class PolicyEngine:
    """
    Control Plane Policy Engine for IdentityNet.
    Manages allowlist network policies, evaluates domain requests,
    and broadcasts dynamic policy changes to network enforcement layers.
    """
    def __init__(self, policy_file: str = POLICY_PATH,
                 event_logger: Optional[Callable] = None,
                 users_config_path: Optional[str] = None,
                 policies_config_path: Optional[str] = None):
        self.policy_file = os.path.abspath(policy_file)
        self.event_logger = event_logger
        self.lock = threading.RLock()
        
        self.active_profile_name = "contest-2026"
        self.mode = "allowlist"
        self.allowed_domains: List[str] = []
        self.blocked_explicit: List[str] = []
        self.blocked_categories: List[str] = []
        self.blocked_apps: List[str] = []
        self.legacy_policies: Dict[str, Dict[str, Any]] = {}
        self.legacy_policy_file = os.path.abspath(policies_config_path or LEGACY_POLICY_PATH)
        
        self.change_listeners: List[Callable] = []
        self.reload_policy()

    def reload_policy(self):
        """Reload configuration from policy.json."""
        with self.lock:
            if not os.path.exists(self.policy_file):
                raise FileNotFoundError(f"Policy file not found: {self.policy_file}")
                
            with open(self.policy_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            self.active_profile_name = data.get("active_profile", data.get("profile", "contest-2026"))
            self.mode = data.get("mode", "allowlist")

            profiles = data.get("profiles", {})
            profile = profiles.get(self.active_profile_name)
            if profile is None and "allowed_domains" in data:
                profile = {
                    "allowed": data.get("allowed_domains", []),
                    "blocked_explicit": data.get("blocked_domains", [])
                }
            profile = profile or {}

            self.allowed_domains = list(profile.get("allowed", [
                "contest.identitynet.local",
                "exam.identitynet.local"
            ]))
            self.blocked_explicit = list(profile.get("blocked_explicit", profile.get("blocked_domains", [])))
            self.blocked_categories = list(profile.get("blocked_categories", data.get("blocked_categories", [])))
            self.blocked_apps = list(profile.get("blocked_apps", data.get("blocked_apps", [])))

            if os.path.exists(self.legacy_policy_file):
                with open(self.legacy_policy_file, "r", encoding="utf-8") as legacy_file:
                    self.legacy_policies = json.load(legacy_file).get("policies", {})

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

    def evaluate(self, domain: str, client_ip: str = "0.0.0.0", user: Optional[str] = None) -> Tuple[str, str]:
        """
        Evaluate destination domain against active policy.
        Returns: Tuple (action ['ALLOWED'|'BLOCKED'], reason)
        """
        domain_clean = domain.lower().strip().rstrip(".")
        allowed_domains = self.allowed_domains
        blocked_explicit = self.blocked_explicit
        if user and user in self.legacy_policies:
            user_policy = self.legacy_policies[user]
            allowed_domains = user_policy.get("allowed_domains", allowed_domains)
            blocked_explicit = user_policy.get("blocked_domains", [])

        # 1. Local IdentityNet Gateway Domains (Always Allowed)
        if domain_clean in ["contest.identitynet.local", "exam.identitynet.local", "127.0.0.1", "192.168.137.1", "192.168.50.1", "localhost"]:
            reason = "Local IdentityNet Gateway destination"
            return "ALLOWED", reason

        # 2. Check Explicit Block List
        for pattern in blocked_explicit:
            if self._matches_pattern(domain_clean, pattern):
                reason = f"Explicitly blocked by policy rule '{pattern}'"
                if self.event_logger:
                    self.event_logger(client_ip, domain_clean, "BLOCKED", reason)
                return "BLOCKED", reason

        # 3. Check Allowed List
        for pattern in allowed_domains:
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

    def evaluate_application(self, application: str, category: str,
                             client_ip: str = "0.0.0.0", user: Optional[str] = None) -> Tuple[str, str]:
        """Evaluate an identified application without decrypting its traffic."""
        blocked_categories = self.blocked_categories
        blocked_apps = self.blocked_apps
        if user and user in self.legacy_policies:
            user_policy = self.legacy_policies[user]
            blocked_categories = user_policy.get("blocked_categories", blocked_categories)
            blocked_apps = user_policy.get("blocked_apps", blocked_apps)

        if application in blocked_apps:
            reason = f"Application '{application}' is blocked by policy"
            if self.event_logger:
                self.event_logger(client_ip, application, "BLOCKED", reason)
            return "BLOCKED", reason
        if category in blocked_categories:
            reason = f"Application category '{category}' is blocked by policy"
            if self.event_logger:
                self.event_logger(client_ip, application, "BLOCKED", reason)
            return "BLOCKED", reason
        return "ALLOWED", f"Application '{application}' is allowed by policy"

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

    def get_user_allowed_domains(self) -> Dict[str, List[str]]:
        """Return local allowlists keyed by participant ID or configured user name."""
        with self.lock:
            return {
                user: list(policy.get("allowed_domains", []))
                for user, policy in self.legacy_policies.items()
            }

    def add_user_allowed_domain(self, user: str, domain: str) -> bool:
        """Add a site to one user's local allowlist and persist the legacy policy."""
        user = user.strip()
        domain = domain.lower().strip().rstrip(".")
        if not user or not domain:
            return False
        with self.lock:
            policy = self.legacy_policies.setdefault(user, {
                "default_action": "BLOCK",
                "allowed_domains": [],
                "blocked_domains": []
            })
            allowed = policy.setdefault("allowed_domains", [])
            if domain in allowed:
                return False
            allowed.append(domain)
            self._save_legacy_policies()
            return True

    def remove_user_allowed_domain(self, user: str, domain: str) -> bool:
        """Remove a site from one user's local allowlist and persist the policy."""
        domain = domain.lower().strip().rstrip(".")
        with self.lock:
            policy = self.legacy_policies.get(user)
            allowed = policy.get("allowed_domains", []) if policy else []
            if domain not in allowed:
                return False
            allowed.remove(domain)
            self._save_legacy_policies()
            return True

    def set_active_profile(self, profile_name: str) -> bool:
        """Switch active policy profile (e.g., 'contest-2026' or 'exam-2026')."""
        with self.lock:
            if not os.path.exists(self.policy_file):
                return False
            with open(self.policy_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            profiles = data.setdefault("profiles", {})
            if profile_name in profiles:
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
        
        profiles = data.setdefault("profiles", {})
        profile = profiles.setdefault(self.active_profile_name, {})
        profile["allowed"] = self.allowed_domains
        profile["blocked_explicit"] = self.blocked_explicit
        profile["blocked_categories"] = self.blocked_categories
        profile["blocked_apps"] = self.blocked_apps

        with open(self.policy_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _save_legacy_policies(self):
        """Persist per-user rules without changing the active global profile."""
        with open(self.legacy_policy_file, "w", encoding="utf-8") as f:
            json.dump({"policies": self.legacy_policies}, f, indent=2)
