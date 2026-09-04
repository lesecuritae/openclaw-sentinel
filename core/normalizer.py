from datetime import UTC, datetime
from typing import Any

from core.models import SecurityEvent, Severity


class EventNormalizer:
    """Maps collector-specific dictionaries onto the canonical event schema."""

    def normalize(self, raw: dict[str, Any], *, source: str) -> SecurityEvent:
        timestamp = raw.get("timestamp") or datetime.now(UTC)
        metadata = dict(raw.get("metadata") or {})
        for name in ("status", "path", "method", "frontend", "backend", "error"):
            if name in raw:
                metadata[name] = raw[name]
        values = dict(
            timestamp=timestamp,
            source=source,
            ip=str(raw.get("ip") or "unknown"),
            service=str(raw.get("service") or "unknown"),
            event_type=str(raw.get("event_type") or "request"),
            severity=Severity(str(raw.get("severity") or "info").lower()),
            metadata=metadata,
        )
        if raw.get("event_id"):
            values["event_id"] = str(raw["event_id"])
        return SecurityEvent(**values)
