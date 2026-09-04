import pytest

from actions.haproxy import HAProxyActionAdapter
from collectors.haproxy.collector import HAProxyCollector
from collectors.haproxy.structured import HAProxyStructuredEventDecoder
from core.config import DetectionRule, RulesConfig
from core.models import SecurityEvent
from database.store import SecurityStore
from engine.detection import DetectionEngine
from engine.risk import RiskEngine


class Runtime:
    async def command(self, command):
        if command == "show sess":
            return "0x1: proto=tcp src=1.2.3.4:12345 fe=public be=web\n"
        return (
            "# pxname,svname,scur,stot,hrsp_4xx,hrsp_5xx,ereq,econ,eresp\n"
            "web,BACKEND,1,2,0,0,0,0,0\n"
        )


@pytest.mark.asyncio
async def test_collector_parses_session():
    events = await HAProxyCollector(Runtime()).collect()
    assert events[0].ip == "1.2.3.4"
    assert events[0].service == "public"


@pytest.mark.asyncio
async def test_action_rejects_command_injection():
    with pytest.raises(ValueError):
        await HAProxyActionAdapter(Runtime(), "/acl", True).block("1.2.3.4\nshow info")


def test_structured_request_event_parsing():
    payload = (
        '<134> sentinel {"ip":"1.2.3.4","host":"vaultwarden.example.com",'
        '"path":"/login","method":"post","status":401,"frontend":"https",'
        '"backend":"vaultwarden","service":"vaultwarden","user_agent":"curl/8",'
        '"timestamp":"2026-09-04T12:00:00Z"}'
    )
    event = HAProxyStructuredEventDecoder().decode(payload)
    assert event.hostname == "vaultwarden.example.com"
    assert event.method == "POST"
    assert event.path == "/login"
    assert event.user_agent == "curl/8"
    assert event.metadata == {"status": 401, "frontend": "https", "backend": "vaultwarden"}


def test_scanner_pattern_uses_distinct_paths():
    engine = DetectionEngine(
        RulesConfig(
            rules={
                "scanner_pattern": DetectionRule(
                    paths=["/.env", "/wp-admin", "/admin", "/login"],
                    distinct_by="path",
                    threshold=4,
                    window=60,
                    score=30,
                )
            }
        )
    )
    events = [
        SecurityEvent(source="haproxy", ip="1.2.3.4", service="web", event_type="request", path=p)
        for p in ["/.env", "/wp-admin", "/admin", "/login"]
    ]
    detections = engine.evaluate(events[-1], lambda _window: events)
    assert detections[0].reason == "scanner_pattern"


def test_login_bruteforce_and_risk_reasons_are_stored(tmp_path):
    rule = DetectionRule(
        event_types=["request"],
        methods=["POST"],
        paths=["/login"],
        threshold=3,
        window=60,
        score=30,
    )
    events = [
        SecurityEvent(
            source="haproxy",
            ip="1.2.3.4",
            service="web",
            event_type="request",
            path="/login",
            method="POST",
        )
        for _ in range(3)
    ]
    detections = DetectionEngine(RulesConfig(rules={"login_bruteforce": rule})).evaluate(
        events[-1], lambda _window: events
    )
    assessment = RiskEngine().assess("1.2.3.4", detections)
    store = SecurityStore(tmp_path / "events.db")
    store.add_event(events[-1])
    store.update_profile(assessment)
    assert store.events()[0].path == "/login"
    assert store.profile("1.2.3.4")["reasons"] == ["login_bruteforce"]
