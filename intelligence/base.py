from typing import Protocol

from pydantic import BaseModel, Field

from core.models import SecurityEvent


class IntelligenceResult(BaseModel):
    provider: str
    score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    attributes: dict[str, str | int | bool | None] = Field(default_factory=dict)


class IntelligenceProvider(Protocol):
    """Passive enrichment contract for reputation and network intelligence providers."""

    name: str

    async def lookup(self, event: SecurityEvent) -> IntelligenceResult: ...
