from datetime import UTC, datetime, timedelta

import httpx
import pytest

from core.config import IntelligenceConfig, IntelligenceProviderConfig
from core.models import Action, Detection, RiskFactor
from database.store import SecurityStore
from engine.policy import PolicyEngine
from engine.risk import RiskEngine
from intelligence.abusech import AbuseCHProvider
from intelligence.base import IntelligenceResult, ProviderError
from intelligence.blocklist_de import BlocklistDEProvider
from intelligence.cache import IntelligenceCache
from intelligence.dshield import DShieldProvider
from intelligence.manager import IntelligenceManager, parse_duration
from intelligence.spamhaus import SpamhausProvider


class FakeProvider:
    name = "fake"

    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, 0

    async def check(self, ip):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


def intelligence_config(**providers):
    return IntelligenceConfig(
        providers={name: IntelligenceProviderConfig(**value) for name, value in providers.items()},
        cache_time={"default": "24h"},
    )


@pytest.mark.asyncio
async def test_provider_interface_and_cache_hit(tmp_path):
    ip = "8.8.8.8"
    result = IntelligenceResult(source="fake", ip=ip, listed=True, score=70, reason="test signal")
    provider = FakeProvider(result)
    cache = IntelligenceCache(SecurityStore(tmp_path / "cache.db"), timedelta(hours=24))
    manager = IntelligenceManager(
        intelligence_config(fake={"enabled": True, "weight": 70}), cache, {"fake": provider}
    )
    assert (await manager.check(ip))[0] == result
    assert (await manager.check(ip))[0] == result
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_expired_cache_is_refreshed(tmp_path):
    ip = "8.8.4.4"
    store = SecurityStore(tmp_path / "cache.db")
    old = IntelligenceResult(source="fake", ip=ip, listed=False, score=0)
    now = datetime.now(UTC)
    store.put_intelligence(old, now - timedelta(days=2), now - timedelta(days=1))
    fresh = IntelligenceResult(source="fake", ip=ip, listed=True, score=60, reason="fresh")
    provider = FakeProvider(fresh)
    manager = IntelligenceManager(
        intelligence_config(fake={"enabled": True, "weight": 60}),
        IntelligenceCache(store, timedelta(hours=24)),
        {"fake": provider},
    )
    assert (await manager.check(ip))[0].reason == "fresh"
    assert provider.calls == 1
    assert len(store.intelligence_history(ip)) == 2


@pytest.mark.asyncio
async def test_provider_failure_is_non_scoring(tmp_path):
    provider = FakeProvider(error=ProviderError("offline"))
    manager = IntelligenceManager(
        intelligence_config(fake={"enabled": True, "weight": 80}),
        IntelligenceCache(SecurityStore(tmp_path / "cache.db"), timedelta(hours=1)),
        {"fake": provider},
    )
    assert await manager.check("8.8.8.8") == []


def test_private_and_reserved_ips_are_not_queried(tmp_path):
    provider = FakeProvider()
    manager = IntelligenceManager(
        intelligence_config(fake={"enabled": True, "weight": 80}),
        IntelligenceCache(SecurityStore(tmp_path / "cache.db"), timedelta(hours=1)),
        {"fake": provider},
    )

    async def run():
        assert await manager.check("192.0.2.10") == []
        assert await manager.check("10.0.0.1") == []

    import asyncio

    asyncio.run(run())
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_spamhaus_listing_and_error_codes():
    async def listed(_query):
        return ["127.0.0.2"]

    result = await SpamhausProvider(score=80, resolver=listed).check("8.8.8.8")
    assert result.listed and result.score == 80

    async def error(_query):
        return ["127.255.255.254"]

    with pytest.raises(ProviderError):
        await SpamhausProvider(resolver=error).check("8.8.8.8")


@pytest.mark.asyncio
async def test_http_provider_parsers_with_simulated_feeds():
    def handler(request):
        if "threatfox" in str(request.url):
            return httpx.Response(200, json={"query_status": "ok", "data": [{"ioc": "ip"}]})
        if "dshield" in str(request.url):
            return httpx.Response(200, json={"ip": {"count": "4", "attacks": "2"}})
        return httpx.Response(200, json={"attacks": 3, "reports": 1})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        abuse = AbuseCHProvider("key", endpoint="https://threatfox.test/", client=client)
        dshield = DShieldProvider(endpoint="https://dshield.test/{ip}", client=client)
        blocklist = BlocklistDEProvider(endpoint="https://blocklist.test/", client=client)
        assert (await abuse.check("8.8.8.8")).listed
        assert (await dshield.check("8.8.8.8")).attributes["reports"] == 4
        assert (await blocklist.check("8.8.8.8")).listed


def test_risk_combination_is_explainable_and_single_source_cannot_block():
    reputation = IntelligenceResult(
        source="abusech", ip="8.8.8.8", listed=True, score=90, reason="malware IOC"
    )
    only_feed = RiskEngine().assess("8.8.8.8", [], [reputation])
    assert only_feed.risk_score == 89
    assert (
        PolicyEngine(__import__("core.config", fromlist=["PolicyConfig"]).PolicyConfig()).decide(
            only_feed
        )
        == Action.ALLOW
    )
    combined = RiskEngine().assess(
        "8.8.8.8",
        [Detection(rule="scanner", score=40, reason="scanner behavior")],
        [reputation],
    )
    assert combined.risk_score == 100
    assert [(factor.source, factor.score) for factor in combined.factors] == [
        ("scanner", 40),
        ("abusech", 90),
    ]
    trusted = RiskEngine().assess(
        "8.8.8.8",
        [],
        additional_factors=[
            RiskFactor(source="trusted_network", score=-50, reason="trusted IP", kind="trust")
        ],
    )
    assert trusted.risk_score == 0


def test_duplicate_results_from_one_source_do_not_bypass_ceiling():
    result = IntelligenceResult(
        source="abusech", ip="8.8.8.8", listed=True, score=90, reason="malware IOC"
    )
    assert RiskEngine().assess("8.8.8.8", [], [result, result]).risk_score == 89


@pytest.mark.parametrize(
    ("value", "seconds"), [("30s", 30), ("5m", 300), ("24h", 86400), ("7d", 604800)]
)
def test_cache_duration(value, seconds):
    assert parse_duration(value).total_seconds() == seconds
