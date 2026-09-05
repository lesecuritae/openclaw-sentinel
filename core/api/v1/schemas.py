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


class ServiceItem(StrictModel):
    service: str
    observed_status: str = Field(
        ..., description="derived from latest lifecycle/backend evidence; unknown when none"
    )
    current_risk: int = Field(ge=0, le=100)
    rolling_window_hours: int = Field(default=24, ge=1)
    last_activity: str | None = None
    last_event_type: str = Field(default="unknown")
    event_count: int = Field(default=0, ge=0)
    warnings_24h: int = Field(default=0, ge=0)


class ServicesResponse(StrictModel):
    services: list[ServiceItem]
    rolling_window_hours: int = Field(default=24, ge=1)
    container_services: list[str] = Field(default_factory=list)
    warnings_summary: int = Field(default=0, ge=0)
    incidents_summary: int = Field(default=0, ge=0)


class WebLogin(StrictModel):
    api_key: str = Field(min_length=1, max_length=1024)
    totp_code: str = Field(pattern=r"^\d{6}$")
