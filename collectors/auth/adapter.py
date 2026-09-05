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
# Configured expected UTC hours for login anomaly detection (no invented geolocation)
EXPECTED_LOGIN_HOURS = list(range(8, 20))  # 08:00 - 19:59 UTC
EXPECTED_COUNTRIES = [
    "US",
    "GB",
    "DE",
    "FR",
    "NL",
    "CA",
]  # structured country codes only; no invented geolocation

# Real regex rules — no catchall inventing auth events.
# Each adapter handles its own format; unsupported formats return None.
# This avoids fabricated Failure/Invalid events.
IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
IPV6_PATTERN = r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|::1"
IP_EXTRACT = r"([\d\.]+)|([0-9a-fA-F:]+)"

DEFAULT_RULES = {
    "linux_auth_failed": [
        {
            "pattern": re.compile(
                r"Failed password for (?:invalid user )?[^ ]+ from (" + IPV4_PATTERN + r")"
            ),
            "fields": {"ip": 1, "service": "ssh"},
        },
        {
            "pattern": re.compile(r"authentication failure; .* rhost=(" + IPV4_PATTERN + r")"),
            "fields": {"ip": 1, "service": "ssh"},
        },
        {
            "pattern": re.compile(r"Failed password for .* from (" + IPV6_PATTERN + r")"),
            "fields": {"ip": 1, "service": "ssh"},
        },
    ],
    "linux_auth_success": [
        {
            "pattern": re.compile(
                r"Accepted (?:password|publickey) for .* from (" + IPV4_PATTERN + r")"
            ),
            "fields": {"ip": 1, "service": "ssh", "subtype": "successful_auth"},
        },
        {
            "pattern": re.compile(
                r"Accepted (?:password|publickey) for .* from (" + IPV6_PATTERN + r")"
            ),
            "fields": {"ip": 1, "service": "ssh", "subtype": "successful_auth"},
        },
    ],
    "vaultwarden_failed": [
        {
            "pattern": re.compile(
                r"Failed login for .* from (" + IPV4_PATTERN + r")", re.IGNORECASE
            ),
            "fields": {"ip": 1, "service": "vaultwarden", "event_subtype": "login_failed"},
        },
    ],
    "nextcloud_failed": [
        {
            "pattern": re.compile(r"Login failed: .* from (" + IPV4_PATTERN + r")"),
            "fields": {"ip": 1, "service": "nextcloud", "event_subtype": "login_failed"},
        },
    ],
    "gitea_failed": [
        {
            "pattern": re.compile(
                r"Failed authentication attempt: .* from (" + IPV4_PATTERN + r")"
            ),
            "fields": {"ip": 1, "service": "gitea", "event_subtype": "login_failed"},
        },
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
                    return self._build_event(line, source, category, match, rule.get("fields", {}))
        return None

    def _build_event(
        self, line: str, source: str, category: str, match, fields: dict
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
                    "subtype": fields.get("event_subtype") or fields.get("subtype"),
                    "indicator": fields.get("indicator"),
                    # Raw log lines may contain credentials and are never retained.
                },
            },
            source=source,
        )


class AuthMonitoringAdapter:
    def __init__(self, parser: AuthParser | None = None):
        self.parser = parser or AuthParser()
        # Injectable read-only interface for journald / auth.log sources
        self._reader: Any = None
        self._max_lines_per_read: int = 500

    def inject_reader(self, reader: Any) -> None:
        """Inject a read-only bounded reader (e.g., journald interface or file tail)."""
        self._reader = reader

    async def process_line(self, line: str, source: str = "auth") -> SecurityEvent | None:
        # Standardize failed logins, SSH bruteforce, and login-time metadata
        # No raw lines or credentials stored; only normalized SecurityEvent emitted.
        event = self.parser.parse_line(line, source=source)
        if event and event.event_type in {
            "linux_auth_failed",
            "vaultwarden_failed",
            "nextcloud_failed",
            "gitea_failed",
            "linux_auth_success",
        }:
            # Ensure login-time metadata is standardized without exposing credentials
            event.metadata.setdefault(
                "login_time_metadata",
                {
                    "normalized_time": event.timestamp.isoformat(),
                    "event_subtype": event.event_type,
                    "indicator": event.metadata.get("indicator"),
                },
            )
        return event

    async def collect_lines(self, source: str = "auth") -> list[str]:
        if self._reader is not None:
            # Use injectable bounded reader if available
            lines = await self._reader.read_lines(self._max_lines_per_read)
            return lines
        return []
