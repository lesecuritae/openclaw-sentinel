"""Auth-monitoring adapter — Phase 4.5 (real configurable parsers).

Real regex/field rules for Linux auth, Vaultwarden, Nextcloud, Gitea.
Sensitive fields (passwords, tokens, secrets) never stored in metadata.
No service-specific hardcodes outside configurable rules.
"""
import logging
import re
from typing import Any

from core.models import SecurityEvent, Severity
from core.normalizer import EventNormalizer

log = logging.getLogger(__name__)

# Configurable regex rules — no embedded service logic.
DEFAULT_RULES = {
    "linux_auth_failed": [
        {"pattern": re.compile(
            r"Failed password for .* from ([\d\.]+)"
        ), "fields": {"ip": 1, "service": "ssh"}},
        {"pattern": re.compile(
            r"authentication failure; .* rhost=([\d\.]+)"
        ), "fields": {"ip": 1, "service": "ssh"}},
    ],
    "vaultwarden_failed": [
        {"pattern": re.compile(
            re.escape("Failed login for"), flags=re.IGNORECASE
        ), "fields": {"service": "vaultwarden", "event_subtype": "login_failed"}},
    ],
    "nextcloud_failed": [
        {"pattern": re.compile(
            r"Login failed: .* from ([\d\.]+)"
        ), "fields": {"ip": 1, "service": "nextcloud", "event_subtype": "login_failed"}},
    ],
    "gitea_failed": [
        {"pattern": re.compile(
            r"Failed authentication attempt: .* from ([\d\.]+)"
        ), "fields": {"ip": 1, "service": "gitea", "event_subtype": "login_failed"}},
    ],
    "bruteforce_indicator": [
        {"pattern": re.compile(r"(Failed|Invalid)"), "fields": {"indicator": "repeated_failures"}},
    ],
}


class AuthParser:
    def __init__(self, rules: dict[str, Any] | None = None):
        self.rules = rules or DEFAULT_RULES.copy()
        self.normalizer = EventNormalizer()

    def parse_line(self, line: str, source: str = "auth") -> SecurityEvent | None:
        for category, patterns in self.rules.items():
            for rule in patterns:
                pattern = rule.get("pattern", re.compile(""))
                match = pattern.search(line)
                if match:
                    return self._build_event(
                        line, source, category, match, rule.get("fields", {})
                    )
        return None

    def _build_event(
        self, line: str, source: str, category: str,
        match, fields: dict
    ) -> SecurityEvent:
        ip = "unknown"
        if isinstance(fields.get("ip"), int):
            ip = match.group(fields["ip"]) or "unknown"
        # Sensitive data (passwords, tokens) explicitly excluded from metadata.
        return self.normalizer.normalize(
            {
                "source": source,
                "ip": ip,
                "service": fields.get("service", "auth"),
                "event_type": category,
                "severity": Severity.MEDIUM,
                "metadata": {
                    "category": category,
                    "subtype": fields.get("event_subtype"),
                    "indicator": fields.get("indicator"),
                    # Raw log lines may contain credentials and are never retained.
                },
            },
            source=source,
        )


class AuthMonitoringAdapter:
    def __init__(self, parser: AuthParser | None = None):
        self.parser = parser or AuthParser()

    async def process_line(self, line: str, source: str = "auth") -> SecurityEvent | None:
        return self.parser.parse_line(line, source=source)
