from datetime import UTC, datetime
from typing import Any

from core.models import SecurityEvent, Severity


class EventNormalizer:
    """Maps collector-specific dictionaries onto the canonical event schema."""

    def normalize(self, raw: dict[str, Any], *, source: str) -> SecurityEvent:
        timestamp = raw.get("timestamp") or datetime.now(UTC)
        metadata = dict(raw.get("metadata") or {})
        for name in ("status", "frontend", "backend", "error"):
            if name in raw:
                metadata[name] = raw[name]
        values = dict(
            timestamp=timestamp,
            source=source,
            ip=str(raw.get("ip") or "unknown"),
            service=str(raw.get("service") or "unknown"),
            event_type=str(raw.get("event_type") or "request"),
            path=str(raw["path"]) if raw.get("path") is not None else None,
            method=str(raw["method"]).upper() if raw.get("method") else None,
            user_agent=str(raw["user_agent"]) if raw.get("user_agent") else None,
            hostname=str(raw["hostname"] if raw.get("hostname") else raw.get("host") or "") or None,
            country=str(raw["country"]) if raw.get("country") else None,
            asn=str(raw["asn"]) if raw.get("asn") else None,
            severity=Severity(str(raw.get("severity") or "info").lower()),
            metadata=metadata,
        )
        if raw.get("event_id"):
            values["event_id"] = str(raw["event_id"])
        return SecurityEvent(**values)
