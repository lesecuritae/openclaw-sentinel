from pathlib import Path

import pytest

from actions.anubis import AnubisChallengeAdapter
from actions.haproxy import HAProxyActionAdapter
from core.config import DetectionRule, PolicyConfig, RulesConfig
from core.models import Action, Detection, SecurityEvent
from core.normalizer import EventNormalizer
from core.service import SentinelService
from database.store import SecurityStore
from engine.detection import DetectionEngine
from engine.policy import PolicyEngine
from engine.risk import RiskEngine


class RuntimeMock:
    def __init__(self):
        self.commands = []

    async def command(self, command):
        self.commands.append(command)
        return ""


def test_event_parsing_generates_id_and_utc_timestamp():
    event = EventNormalizer().normalize(
        {"ip": "192.0.2.10", "service": "application", "event_type": "failed_login", "status": 401},
        source="haproxy",
    )
    assert event.event_id and event.timestamp.tzinfo
    assert event.ip == "192.0.2.10"
    assert event.metadata["status"] == 401


def test_risk_is_additive_unique_and_capped():
    detections = [
        Detection(rule="login", score=30, reason="login"),
        Detection(rule="scanner", score=80, reason="scanner"),
    ]
    result = RiskEngine().assess("192.0.2.10", detections)
    assert result.risk_score == 100
    assert result.reasons == ["login", "scanner"]


@pytest.mark.parametrize(
    ("score", "challenge", "expected"),
    [
        (10, True, Action.ALLOW),
        (70, True, Action.CHALLENGE),
        (95, True, Action.BLOCK),
        (70, False, Action.ALLOW),
    ],
)
def test_policy(score, challenge, expected):
    policy = PolicyEngine(PolicyConfig(challenge_enabled=challenge))
    from core.models import RiskAssessment

    assert policy.decide(RiskAssessment(ip="192.0.2.10", risk_score=score, reasons=[])) == expected


@pytest.mark.asyncio
async def test_simulated_event_blocks_via_runtime(tmp_path: Path):
    runtime = RuntimeMock()
    store = SecurityStore(tmp_path / "test.db")
    rules = RulesConfig(rules={"scanner": DetectionRule(paths=["/.env"], score=95)})
    service = SentinelService(
        store,
        DetectionEngine(rules),
        RiskEngine(),
        PolicyEngine(PolicyConfig()),
        HAProxyActionAdapter(runtime, "/acl.lst", enabled=True),
        AnubisChallengeAdapter(),
    )
    event = SecurityEvent(
        source="haproxy",
        ip="192.0.2.10",
        service="web",
        event_type="request",
        path="/.env",
    )
    result = await service.process(event)
    assert result.action == Action.BLOCK
    assert runtime.commands == ["add acl /acl.lst 192.0.2.10"]


@pytest.mark.asyncio
async def test_llm_provider_mock():
    from llm.gateway import LLMGateway, LLMProvider

    class Mock(LLMProvider):
        async def analyze(self, prompt):
            return "mock analysis"

    assert await LLMGateway(Mock()).explain("event") == "mock analysis"
