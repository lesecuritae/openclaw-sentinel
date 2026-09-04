from typing import Protocol

from pydantic import BaseModel, Field


class IntelligenceResult(BaseModel):
    source: str
    ip: str
    listed: bool = False
    score: int = Field(ge=0, le=100)
    reason: str = "not listed"
    attributes: dict[str, str | int | bool | None] = Field(default_factory=dict)


class IntelligenceProvider(Protocol):
    """Passive enrichment contract for reputation and network intelligence providers."""

    name: str

    async def check(self, ip: str) -> IntelligenceResult: ...


class ProviderError(RuntimeError):
    """A provider could not produce a trustworthy reputation result."""
