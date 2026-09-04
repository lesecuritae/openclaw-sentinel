from typing import Protocol

from core.models import ActionResult, RiskAssessment


class ActionProvider(Protocol):
    """Response boundary for proxies, firewalls and future cloud APIs."""

    async def execute(self, assessment: RiskAssessment) -> ActionResult: ...


class ChallengeProvider(Protocol):
    """External challenge boundary; Sentinel does not implement CAPTCHA logic."""

    async def challenge(self, ip: str) -> ActionResult: ...
