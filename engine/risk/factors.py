from typing import Protocol

from core.models import SecurityEvent


class RiskFactorProvider(Protocol):
    """Extension point for threat intelligence, reputation, geo and future ML factors."""

    async def factors(self, event: SecurityEvent) -> dict[str, int]: ...
