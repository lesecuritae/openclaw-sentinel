"""Collector identity is a server-side credential binding, never an event claim.

The identity resolver is the extension point for verified mTLS/signature identities.
External collectors must use TLS termination and a dedicated, scoped credential.
"""

import secrets
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import uuid4

from fastapi import HTTPException, Request
from pydantic import ConfigDict, Field, field_validator

from core.models import SecurityEvent


class IngestEvent(SecurityEvent):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=1, max_length=64)
    service: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=64)
    ip: str = Field(max_length=45)

    @field_validator("ip")
    @classmethod
    def valid_address(cls, value):
        return "unknown" if value == "unknown" else str(ip_address(value))


def collector_identity(request: Request) -> dict:
    header = request.headers.get("authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    matches = [
        (name, config)
        for name, config in request.app.state.settings.collector_credentials.items()
        if token and secrets.compare_digest(token.encode(), config.token.encode())
    ]
    if len(matches) != 1:
        raise HTTPException(401, "valid collector credential required")
    name, config = matches[0]
    return {"id": name, "config": config}


def validate_event(event: IngestEvent, identity: dict) -> SecurityEvent:
    config = identity["config"]
    if (
        event.source != config.source
        or event.event_type not in config.event_types
        or event.service not in config.services
    ):
        raise HTTPException(403, "event outside collector scope")
    if event.ip == "unknown" and config.source not in {"docker", "integrity"}:
        raise HTTPException(422, "network events require an IP address")
    if abs((datetime.now(UTC) - event.timestamp).total_seconds()) > 300:
        raise HTTPException(422, "event timestamp outside allowed window")
    # A sender cannot select IDs or spoof the authenticated provenance.
    event.event_id = str(uuid4())
    event.metadata["collector_id"] = identity["id"]
    return SecurityEvent.model_validate(event.model_dump())
