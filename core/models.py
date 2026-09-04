from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    BLOCK = "block"


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str
    ip: str
    service: str
    event_type: str
    path: str | None = None
    method: str | None = None
    user_agent: str | None = None
    hostname: str | None = None
    country: str | None = None
    asn: str | None = None
    severity: Severity = Severity.INFO
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Detection(BaseModel):
    rule: str
    score: int = Field(ge=0, le=100)
    reason: str


class RiskFactor(BaseModel):
    source: str
    score: int = Field(ge=-100, le=100)
    reason: str
    kind: str


class RiskAssessment(BaseModel):
    ip: str
    risk_score: int = Field(ge=0, le=100)
    reasons: list[str]
    factors: list[RiskFactor] = Field(default_factory=list)
    action: Action = Action.ALLOW


class ActionResult(BaseModel):
    action: Action
    ip: str
    provider: str
    applied: bool
    detail: str = ""
