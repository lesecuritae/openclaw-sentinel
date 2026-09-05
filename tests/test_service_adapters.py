"""Service adapter tests — separate registered adapters, synthetic fixtures,
real supported JSON/log patterns, unsupported formats clarified, no catchall inventing."""

from collectors.service.adapter import (
    SERVICE_ADAPTERS,
    GiteaAdapter,
    NextcloudAdapter,
    PlexAdapter,
    VaultwardenAdapter,
)


def test_service_adapters_registered():
    assert "vaultwarden" in SERVICE_ADAPTERS
    assert "nextcloud" in SERVICE_ADAPTERS
    assert "gitea" in SERVICE_ADAPTERS
    assert "plex" in SERVICE_ADAPTERS


def test_vaultwarden_adapter_real_pattern():
    adapter = VaultwardenAdapter()
    event = adapter.parse_line("Failed login for user from 192.168.1.50", source="service")
    assert event is not None
    assert event.event_type == "vaultwarden_failed"
    assert event.ip == "192.168.1.50"
    assert event.service == "vaultwarden"


def test_vaultwarden_unsupported_format_returns_none():
    adapter = VaultwardenAdapter()
    # Unsupported format (not matching real Vaultwarden pattern) must not invent event
    event = adapter.parse_line("Random unsupported log line", source="service")
    assert event is None


def test_nextcloud_adapter_real_pattern():
    adapter = NextcloudAdapter()
    event = adapter.parse_line("Login failed: user from 10.0.0.1", source="service")
    assert event is not None
    assert event.event_type == "nextcloud_failed"


def test_gitea_adapter_real_pattern():
    adapter = GiteaAdapter()
    event = adapter.parse_line(
        "Failed authentication attempt: user from 172.16.0.5", source="service"
    )
    assert event is not None
    assert event.event_type == "gitea_failed"


def test_plex_adapter_no_invented_login_semantics():
    adapter = PlexAdapter()
    # Plex only supports media/session events; no login failure events invented
    event_media = adapter.parse_line("Playback started for movie", source="service")
    assert event_media is not None
    assert event_media.event_type == "plex_media_event"

    event_failed = adapter.parse_line("Failed login for plex", source="service")
    assert event_failed is None


def test_custom_adapter_registration():
    from collectors.service.adapter import ServiceAdapterBase

    class CustomAdapter(ServiceAdapterBase):
        def parse_line(self, line, source="service"):
            return None

    SERVICE_ADAPTERS["custom"] = CustomAdapter
    assert SERVICE_ADAPTERS.get("custom") is not None
