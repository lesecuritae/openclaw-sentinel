from datetime import UTC, datetime, timedelta

from database.store import SecurityStore
from intelligence.base import IntelligenceResult


class IntelligenceCache:
    def __init__(self, store: SecurityStore, default_ttl: timedelta):
        self.store, self.default_ttl = store, default_ttl

    def get(self, ip: str, source: str) -> IntelligenceResult | None:
        value = self.store.get_intelligence(ip, source)
        return IntelligenceResult.model_validate(value) if value else None

    def put(self, result: IntelligenceResult, ttl: timedelta | None = None) -> IntelligenceResult:
        now = datetime.now(UTC)
        self.store.put_intelligence(result, now, now + (ttl or self.default_ttl))
        return result
