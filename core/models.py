from __future__ import annotations

import json
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
    LOG_ONLY = "log_only"
    ALERT = "alert"
    CHALLENGE = "challenge"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"


class IncidentStatus(StrEnum):
    NEW = "neu"
    ANALYZED = "analysiert"
    CONFIRMED = "bestätigt"
    CLOSED = "geschlossen"


class IncidentPriority(StrEnum):
    LOW = "niedrig"
    MEDIUM = "mittel"
    HIGH = "hoch"
    CRITICAL = "kritisch"


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()), max_length=128)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str
    ip: str
    service: str
    event_type: str
    path: str | None = Field(default=None, max_length=2048)
    method: str | None = Field(default=None, max_length=2048)
    user_agent: str | None = Field(default=None, max_length=2048)
    accept_language: str | None = Field(default=None, max_length=256)
    client_timezone: str | None = Field(default=None, max_length=128)
    device_id: str | None = Field(default=None, max_length=256)
    tls_fingerprint: str | None = Field(default=None, max_length=256)
    hostname: str | None = Field(default=None, max_length=2048)
    country: str | None = Field(default=None, max_length=2048)
    asn: str | None = Field(default=None, max_length=2048)
    severity: Severity = Severity.INFO
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def bounded_metadata(cls, value):
        if len(value) > 32 or len(json.dumps(value, allow_nan=False).encode()) > 8192:
            raise ValueError("metadata too large")

        def depth(item, level=0):
            if level > 4:
                raise ValueError("metadata too deeply nested")
            if isinstance(item, dict):
                for child in item.values():
                    depth(child, level + 1)
            elif isinstance(item, list):
                for child in item:
                    depth(child, level + 1)

        depth(value)
        return value

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
