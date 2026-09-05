from datetime import UTC, datetime, timedelta

from core.models import Action
from database.store import SecurityStore


def test_trusted_entities_match_ip_network_and_device(tmp_path):
    store = SecurityStore(tmp_path / "safety.db")
    store.add_trusted_entity("network", "10.0.0.0/8", "internal network")
    store.add_trusted_entity("device", "laptop-1", "known device")
    assert store.trusted_match("10.2.3.4")
    assert store.trusted_match("203.0.113.5", "laptop-1")
    assert not store.trusted_match("203.0.113.5")


def test_trusted_entity_expiry_and_action_expiry(tmp_path):
    store = SecurityStore(tmp_path / "safety.db")
    expired = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    store.add_trusted_entity("ip", "203.0.113.9", "temporary", expired)
    assert not store.trusted_match("203.0.113.9")
    assert store.action_duration_minutes(Action.BLOCK) == 30
    assert store.action_expiry(Action.BLOCK) is not None
