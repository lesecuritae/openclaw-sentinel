from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from core.config import PolicyConfig, Settings
from core.models import SecurityEvent
from core.service import SentinelService
from database.store import SecurityStore
from engine.detection import DetectionEngine
from engine.policy import PolicyEngine
from engine.risk import RiskEngine


@pytest.mark.asyncio
async def test_container_restart_history_is_isolated_and_never_blocks_ip(tmp_path):
    store = SecurityStore(tmp_path / "risk.db")
    haproxy, anubis, intelligence = AsyncMock(), AsyncMock(), AsyncMock()
    service = SentinelService(
        store,
        DetectionEngine(Settings(rules_path=Path("config/rules.yaml")).load_rules()),
        RiskEngine(),
        PolicyEngine(PolicyConfig(allow_below=1, challenge_below=2)),
        haproxy,
        anubis,
        intelligence,
    )
    for name in ("one", "two", "three"):
        result = await service.process(
            SecurityEvent(
                source="docker",
                ip="unknown",
                service=name,
                event_type="docker_restart",
                metadata={"actor_id": name},
            )
        )
        assert result.risk_score == 0
    for _ in range(2):
        result = await service.process(
            SecurityEvent(
                source="docker",
                ip="unknown",
                service="one",
                event_type="docker_restart",
                metadata={"actor_id": "one"},
            )
        )
    assert result.risk_score >= 35
    assert "docker_restart_loop" in result.reasons
    # Even if a Docker event includes an address, it is not an attacking client.
    await service.process(
        SecurityEvent(
            source="docker",
            ip="192.0.2.1",
            service="one",
            event_type="docker_privileged",
            metadata={"actor_id": "one"},
        )
    )
    intelligence.check.assert_not_awaited()
    haproxy.block.assert_not_awaited()
    anubis.challenge.assert_not_awaited()
    assert store.profile("192.0.2.1") is None
