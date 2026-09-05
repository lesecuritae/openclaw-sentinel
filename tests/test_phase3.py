import sqlite3

import pytest

from actions.anubis import AnubisChallengeAdapter
from actions.haproxy import HAProxyActionAdapter
from core.auth import Principal
from core.config import DetectionRule, PolicyConfig, RulesConfig
from core.models import Action, RiskFactor, SecurityEvent
from core.permissions import Role
from core.service import SentinelService
from database.store import SecurityStore
from engine.baseline.engine import BaselineEngine
from engine.client.analyzer import ClientMismatchAnalyzer
from engine.detection import DetectionEngine
from engine.geo_time.analyzer import GeoTimeAnalyzer
from engine.policy import PolicyEngine
from engine.risk import RiskEngine
from engine.trust.engine import TrustEngine
from intelligence import IntelligenceResult
from mcp.server import SecurityTools


class RuntimeMock:
    async def command(self, _command):
        return ""


def make_service(store, rules=None):
    return SentinelService(
        store,
        DetectionEngine(rules or RulesConfig(rules={})),
        RiskEngine(),
        PolicyEngine(PolicyConfig()),
        HAProxyActionAdapter(RuntimeMock(), "/acl.lst", enabled=False),
        AnubisChallengeAdapter(),
    )


def test_event_roundtrip_preserves_adaptive_fields(tmp_path):
    store = SecurityStore(tmp_path / "roundtrip.db")
    event = SecurityEvent(
        source="test",
        ip="192.0.2.1",
        service="web",
        event_type="request",
        accept_language="de-DE",
        client_timezone="Europe/Berlin",
        device_id="device-1",
        tls_fingerprint="sha256:example",
    )
    store.add_event(event)
    restored = store.events()[0]
    assert restored.accept_language == "de-DE"
    assert restored.client_timezone == "Europe/Berlin"
    assert restored.device_id == "device-1"
    assert restored.tls_fingerprint == "sha256:example"


def test_baseline_composite_key_and_legacy_migration(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute(
            """CREATE TABLE behavior_baselines (
            service TEXT, pattern TEXT PRIMARY KEY, confidence REAL, sample_count INTEGER,
            first_seen TEXT, last_seen TEXT, recommendation TEXT)"""
        )
        db.execute(
            "INSERT INTO behavior_baselines VALUES('one','request',0.5,3,'a','b','observe')"
        )
    store = SecurityStore(path)
    baseline = BaselineEngine(store)
    baseline.observe("two", "request")
    assert baseline.get_recommendation("one", "request")["sample_count"] == 3
    assert baseline.get_recommendation("two", "request")["sample_count"] == 1


def test_trust_is_neutral_and_poisoning_is_excluded():
    engine = TrustEngine()
    assert engine.calculate_trust({}) == 50
    poisoned = {
        "positive_event_count": 10,
        "negative_event_count": 0,
        "blocked_event_count": 8,
        "positive_confidence": 0.9,
    }
    assert engine.calculate_trust(poisoned) == 50
    assert engine.calculate_trust({"negative_event_count": 3}) == 35
    assert engine.calculate_trust(
        {"positive_event_count": 3, "positive_confidence": 0.9}
    ) == 50


def test_geo_time_requires_confident_complete_evidence():
    analyzer = GeoTimeAnalyzer()
    event = SecurityEvent(
        source="test",
        ip="192.0.2.1",
        service="web",
        event_type="request",
        country="CN",
        client_timezone="Asia/Shanghai",
    )
    assert analyzer.explain_geo_time_mismatch(event, {"known_regions": ["DE"]}) == []
    profile = {
        "positive_event_count": 5,
        "positive_confidence": 0.8,
        "known_regions": ["DE"],
        "typical_hours": [(event.timestamp.hour + 1) % 24],
        "timezones": ["Europe/Berlin"],
    }
    assert len(analyzer.explain_geo_time_mismatch(event, profile)) == 3


def test_client_mismatch_and_missing_features():
    analyzer = ClientMismatchAnalyzer()
    empty = SecurityEvent(
        source="test", ip="192.0.2.1", service="web", event_type="request"
    )
    assert analyzer.analyze_client(empty, {"user_agents": ["Firefox"]}) == []
    changed = empty.model_copy(update={"user_agent": "curl", "accept_language": "en"})
    factors = analyzer.analyze_client(
        changed, {"user_agents": ["Firefox"], "languages": ["de"]}
    )
    assert factors[0].source == "client:mismatch"
    assert factors[0].score == 16


def test_single_feed_plus_trust_cannot_bypass_ceiling():
    feed = IntelligenceResult(
        source="feed", ip="8.8.8.8", listed=True, score=90, reason="listed"
    )
    trust = RiskFactor(source="trust", score=10, reason="unknown", kind="trust")
    assert RiskEngine().assess("8.8.8.8", [], [feed], [trust]).risk_score == 89


@pytest.mark.asyncio
async def test_service_trains_only_safe_events_and_persists_anomalies(tmp_path):
    store = SecurityStore(tmp_path / "service.db")
    service = make_service(store)
    safe = SecurityEvent(
        source="test",
        ip="192.0.2.1",
        service="web",
        event_type="request",
        method="GET",
        path="/home",
        country="DE",
        device_id="device-safe",
        user_agent="Firefox",
    )
    result = await service.process(safe)
    assert result.action == Action.ALLOW
    assert store.get_device_profile("device-safe")["positive_event_count"] == 1
    assert store.baselines("web")

    rules = RulesConfig(rules={"scanner": DetectionRule(paths=["/.env"], score=95)})
    blocked_service = make_service(store, rules)
    blocked = safe.model_copy(
        update={"event_id": "blocked-event", "path": "/.env", "device_id": "device-bad"}
    )
    result = await blocked_service.process(blocked)
    assert result.action == Action.BLOCK
    bad = store.get_device_profile("device-bad")
    assert bad["positive_event_count"] == 0
    assert bad["negative_event_count"] == 1
    assert bad["blocked_event_count"] == 1

    for index in range(4):
        await service.process(
            safe.model_copy(update={"event_id": f"repeat-{index}", "device_id": None})
        )
    assert store.behavior_anomalies(ip="192.0.2.1")


@pytest.mark.asyncio
async def test_mcp_phase3_tools_read_persisted_state(tmp_path):
    store = SecurityStore(tmp_path / "mcp.db")
    event = SecurityEvent(
        source="test",
        ip="192.0.2.1",
        service="web",
        event_type="request",
        device_id="device-1",
    )
    store.update_device_profile("device-1", event, safe=True)
    factor = RiskFactor(source="client:mismatch", score=8, reason="changed", kind="client")
    store.add_anomalies(event, [factor])
    tools = SecurityTools(None, store, None)
    from functools import partial
    tools.call = partial(tools.call, principal=Principal("test", Role.ANALYST, "test-session"))

    profile = await tools.call("security.get_device_profile", {"device_id": "device-1"})
    assert profile["positive_event_count"] == 1
    anomalies = await tools.call("security.get_behavior_anomalies", {"service": "web"})
    assert anomalies[0]["reason"] == "changed"
    explained = await tools.call(
        "security.explain_anomaly", {"anomaly_id": anomalies[0]["id"]}
    )
    assert explained == anomalies[0]
