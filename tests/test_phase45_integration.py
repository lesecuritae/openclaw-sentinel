from pathlib import Path

import pytest

from collectors.auth.adapter import AuthParser
from collectors.auth.collector import LinuxAuthCollector
from collectors.docker.collector import DockerEventCollector
from collectors.service.collector import ServiceLogCollector
from core.config import Settings
from core.web_auth import WebSessionManager, totp


class DockerStream:
    async def read_events(self, timeout: float):
        assert timeout <= 30
        return [
            {
                "Type": "container",
                "Action": "die",
                "Actor": {"ID": "abc", "Attributes": {"name": "web", "image": "nginx"}},
                "time": 1,
            },
            {
                "event_type": "docker_privileged",
                "container_name": "unsafe",
                "attributes": {"privileged": True},
            },
        ]


@pytest.mark.asyncio
async def test_docker_collector_normalizes_bounded_read_only_events():
    collector = DockerEventCollector(enabled=True, stream_client=DockerStream())
    events = await collector.collect()
    assert [(event.source, event.service, event.event_type) for event in events] == [
        ("docker", "web", "docker_crash"),
        ("docker", "unsafe", "docker_privileged"),
    ]
    assert events[1].metadata["privileged"] is True


def test_auth_parser_extracts_ip_without_retaining_raw_credentials():
    event = AuthParser().parse_line(
        "sshd: Failed password for root from 192.0.2.44 port 22 ssh2",
        source="linux_auth",
    )
    assert event is not None
    assert event.ip == "192.0.2.44"
    assert event.event_type == "linux_auth_failed"
    assert "password" not in str(event.metadata).lower()
    assert "root" not in str(event.metadata).lower()


@pytest.mark.asyncio
async def test_auth_collector_incrementally_reads_file(tmp_path: Path):
    path = tmp_path / "auth.log"
    path.write_text("sshd: Failed password for root from 192.0.2.4 port 22\n")
    collector = LinuxAuthCollector(enabled=True, log_paths=[str(path)], max_lines=10)
    assert len(await collector.collect()) == 1
    assert await collector.collect() == []


@pytest.mark.asyncio
async def test_service_collector_uses_shared_parser(tmp_path: Path):
    path = tmp_path / "service.log"
    path.write_text("Login failed: account from 198.51.100.7\n")
    collector = ServiceLogCollector(enabled=True, log_path=str(path), max_lines=10)
    events = await collector.collect()
    assert len(events) == 1
    assert events[0].service == "nextcloud"


def test_collectors_are_opt_in_by_default():
    settings = Settings(_env_file=None)
    assert settings.docker_collector_enabled is False
    assert settings.auth_collector_enabled is False
    assert settings.service_log_collector_enabled is False


def test_optional_totp_sessions_rate_limit_expire_and_logout():
    secret = "JBSWY3DPEHPK3PXP"
    manager = WebSessionManager(
        enabled=True, api_key="api-secret", secret=secret, ttl_seconds=60, max_attempts=2
    )
    assert manager.login("client-a", "wrong", "000000", now=1_000) is None
    assert manager.login("client-a", "wrong", "000000", now=1_001) is None
    assert manager.login("client-a", "api-secret", totp(secret, 1_002), now=1_002) is None
    token = manager.login("client-b", "api-secret", totp(secret, 1_002), now=1_002)
    assert token and manager.validate(token, now=1_010)
    assert not manager.validate(token, now=1_063)
    token = manager.login("client-b", "api-secret", totp(secret, 2_000), now=2_000)
    assert token
    manager.logout(token)
    assert not manager.validate(token, now=2_001)
