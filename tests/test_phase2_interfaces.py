import json

import pytest

from core.auth import Principal
from core.models import Action, RiskAssessment, RiskFactor
from core.permissions import Role
from database.store import SecurityStore
from llm.gateway import LLMGateway, LLMProvider
from mcp.server import SecurityTools


class RecordingProvider(LLMProvider):
    def __init__(self):
        self.prompt = ""

    async def analyze(self, prompt: str) -> str:
        self.prompt = prompt
        return "explanation"


@pytest.mark.asyncio
async def test_llm_risk_context_contains_only_normalized_signals():
    provider = RecordingProvider()
    gateway = LLMGateway(provider)
    result = await gateway.explain_risk(
        ip="8.8.8.8",
        risk_score=95,
        factors=[
            {
                "source": "spamhaus",
                "score": 80,
                "reason": "listed",
                "kind": "intelligence",
                "raw_feed_record": "must-not-leak",
            }
        ],
        event_types=["scanner", "scanner"],
        services=["example"],
    )

    assert result == "explanation"
    assert "must-not-leak" not in provider.prompt
    payload = json.loads(provider.prompt.rsplit("\n", 1)[1])
    assert payload["factors"] == [
        {
            "source": "spamhaus",
            "score": 80,
            "reason": "listed",
            "kind": "intelligence",
        }
    ]
    assert payload["event_types"] == ["scanner"]


@pytest.mark.asyncio
async def test_mcp_exposes_threat_tools_and_explainable_profile(tmp_path):
    store = SecurityStore(tmp_path / "sentinel.db")
    assessment = RiskAssessment(
        ip="8.8.8.8",
        risk_score=80,
        reasons=["spamhaus: listed"],
        factors=[
            RiskFactor(
                source="spamhaus", score=80, reason="listed", kind="intelligence"
            )
        ],
        action=Action.ALLOW,
    )
    store.update_profile(assessment)
    tools = SecurityTools(service=None, store=store, llm=None)
    from functools import partial
    tools.call = partial(tools.call, principal=Principal("test", Role.ANALYST, "test-session"))

    names = {definition["name"] for definition in tools.definitions()}
    assert {
        "security.check_ip_reputation",
        "security.get_threat_sources",
        "security.get_ip_history",
        "security.explain_risk_score",
    } <= names
    explanation = await tools.call("security.explain_risk_score", {"ip": "8.8.8.8"})
    assert explanation["risk_score"] == 80
    assert explanation["factors"][0]["source"] == "spamhaus"
