"""Service-specific adapters — Phase 4.5 (Vaultwarden, Nextcloud, Gitea, Plex).
No service-specific if/else in core; each adapter is registered/configurable.
Plex adapter has no invented login semantics (only media/session events).
"""
import logging
import re
from typing import Any

from core.models import SecurityEvent
from core.normalizer import EventNormalizer

log = logging.getLogger(__name__)


class ServiceAdapterBase:
    """Base adapter for configurable service log parsing."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.normalizer = EventNormalizer()

    def parse_line(self, line: str, source: str = "service") -> SecurityEvent | None:
        raise NotImplementedError("Subclasses must implement parse_line")


class VaultwardenAdapter(ServiceAdapterBase):
    """Vaultwarden adapter — login failure events only; no invented semantics."""

    def __init__(self):
        super().__init__("vaultwarden")
        self.pattern = re.compile(r"Failed login for .* from ([\d\.]+)", re.IGNORECASE)

    def parse_line(self, line: str, source: str = "service") -> SecurityEvent | None:
        match = self.pattern.search(line)
        if match:
            return self.normalizer.normalize(
                {
                    "source": source,
                    "ip": match.group(1) or "unknown",
                    "service": self.service_name,
                    "event_type": "vaultwarden_failed",
                    "severity": "medium",
                    "metadata": {
                        "service": self.service_name,
                        "subtype": "login_failed",
                        # Raw lines never stored; only normalized event emitted
                    },
                },
                source=source,
            )
        return None


class NextcloudAdapter(ServiceAdapterBase):
    """Nextcloud adapter — login failure events only."""

    def __init__(self):
        super().__init__("nextcloud")
        self.pattern = re.compile(r"Login failed: .* from ([\d\.]+)")

    def parse_line(self, line: str, source: str = "service") -> SecurityEvent | None:
        match = self.pattern.search(line)
        if match:
            return self.normalizer.normalize(
                {
                    "source": source,
                    "ip": match.group(1) or "unknown",
                    "service": self.service_name,
                    "event_type": "nextcloud_failed",
                    "severity": "medium",
                    "metadata": {"service": self.service_name, "subtype": "login_failed"},
                },
                source=source,
            )
        return None


class GiteaAdapter(ServiceAdapterBase):
    """Gitea adapter — failed authentication events only."""

    def __init__(self):
        super().__init__("gitea")
        self.pattern = re.compile(r"Failed authentication attempt: .* from ([\d\.]+)")

    def parse_line(self, line: str, source: str = "service") -> SecurityEvent | None:
        match = self.pattern.search(line)
        if match:
            return self.normalizer.normalize(
                {
                    "source": source,
                    "ip": match.group(1) or "unknown",
                    "service": self.service_name,
                    "event_type": "gitea_failed",
                    "severity": "medium",
                    "metadata": {"service": self.service_name, "subtype": "login_failed"},
                },
                source=source,
            )
        return None


class PlexAdapter(ServiceAdapterBase):
    """Plex adapter — NO invented login semantics. Only media/session/status events."""

    def __init__(self):
        super().__init__("plex")
        # No login-failure patterns; only session/stream/activity events if configured
        self.status_pattern = re.compile(r"Playback.*started|Playback.*stopped|Session.*created")

    def parse_line(self, line: str, source: str = "service") -> SecurityEvent | None:
        # Plex adapter explicitly does NOT invent login failure events.
        # Only emit events for explicitly configured media/session patterns.
        if self.status_pattern.search(line):
            return self.normalizer.normalize(
                {
                    "source": source,
                    "ip": "unknown",  # Plex events typically lack source IP in logs
                    "service": self.service_name,
                    "event_type": "plex_media_event",
                    "severity": "info",
                    "metadata": {
                        "service": self.service_name,
                        "subtype": "media_session",
                        "note": "No invented login semantics",
                    },
                },
                source=source,
            )
        return None


# Configurable adapter registry — no service-specific if/else in core
SERVICE_ADAPTERS: dict[str, Any] = {
    "vaultwarden": VaultwardenAdapter,
    "nextcloud": NextcloudAdapter,
    "gitea": GiteaAdapter,
    "plex": PlexAdapter,
}
