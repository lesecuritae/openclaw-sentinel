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
    container_count: int = Field(default=0, ge=0)
    service_health: list[dict[str, Any]] = Field(default_factory=list)
    warnings_24h: int = Field(default=0, ge=0)
    last_events: list[dict[str, Any]] = Field(default_factory=list)


class Page(StrictModel):
    items: list[dict[str, Any]]
    limit: int
    offset: int


class ConfigUpdate(StrictModel):
    value: dict[str, Any]


class WebLogin(StrictModel):
    api_key: str = Field(min_length=1, max_length=1024)
    totp_code: str = Field(pattern=r"^\d{6}$")
