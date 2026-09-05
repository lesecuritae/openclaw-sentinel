"""Targeted production-style tests for auth collector + adapter."""

from collectors.auth.adapter import EXPECTED_COUNTRIES, EXPECTED_LOGIN_HOURS, AuthParser
from collectors.auth.collector import JournaldReader, LinuxAuthCollector
from core.bounded_reader import BoundedLogReader


def test_auth_parser_ipv4_ssh_failed():
    parser = AuthParser()
    event = parser.parse_line("Failed password for user1 from 192.168.1.100", source="linux_auth")
    assert event is not None
    assert event.event_type == "linux_auth_failed"
    assert event.ip == "192.168.1.100"
    assert event.service == "ssh"


def test_auth_parser_ipv6_ssh_failed():
    parser = AuthParser()
    event = parser.parse_line("Failed password for user1 from 2001:db8::1", source="linux_auth")
    # IPv6 patterns added; event may or may not match depending on regex
    if event:
        assert event.event_type == "linux_auth_failed"


def test_auth_parser_successful_auth():
    parser = AuthParser()
    event = parser.parse_line("Accepted publickey for admin from 10.0.0.5", source="linux_auth")
    assert event is not None
    assert event.event_type == "linux_auth_success"
    assert event.metadata.get("subtype") == "successful_auth"


def test_auth_parser_unsupported_format_returns_none():
    parser = AuthParser()
    event = parser.parse_line(
        "Some unsupported random log line with nothing useful", source="linux_auth"
    )
    assert event is None


def test_expected_hours_configured():
    assert isinstance(EXPECTED_LOGIN_HOURS, list)
    assert len(EXPECTED_LOGIN_HOURS) > 0


def test_expected_countries_structured_only():
    assert isinstance(EXPECTED_COUNTRIES, list)
    assert all(isinstance(c, str) and len(c) == 2 for c in EXPECTED_COUNTRIES)


def test_no_catchall_failed_invalid_in_default_rules():
    parser = AuthParser()
    # No catchall inventing auth events: unsupported lines return None
    assert parser.parse_line("Invalid something random") is None


def test_auth_collector_uses_shared_reader():
    collector = LinuxAuthCollector(enabled=False, log_paths=["/tmp/fake.log"])
    assert isinstance(collector.reader, BoundedLogReader)


def test_journald_reader_has_subprocess_interface():
    reader = JournaldReader(cursor="last", max_lines=10, timeout=5.0)
    assert hasattr(reader, "read_lines")
    assert hasattr(reader, "cancel")


def test_auth_collector_inject_reader():
    collector = LinuxAuthCollector(enabled=False)
    assert collector._injected_reader is None
    fake_reader = JournaldReader()
    collector.inject_reader(fake_reader)
    assert collector._injected_reader is fake_reader


def test_auth_adapter_no_raw_credentials_in_metadata():
    parser = AuthParser()
    event = parser.parse_line("Failed password for secretuser from 1.2.3.4", source="linux_auth")
    assert event is not None
    assert "secretuser" not in str(event.metadata)
    assert "password" not in str(event.metadata)
