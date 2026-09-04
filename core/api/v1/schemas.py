from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DashboardSummary(StrictModel):
    current_risk: int = Field(ge=0, le=100)
    events_24h: int = Field(ge=0)
    blocks_24h: int = Field(ge=0)
    challenges_24h: int = Field(ge=0)
    top_attackers: list[dict[str, Any]]
    affected_services: list[str]


class Page(StrictModel):
    items: list[dict[str, Any]]
    limit: int
    offset: int


class ConfigUpdate(StrictModel):
    value: dict[str, Any]
