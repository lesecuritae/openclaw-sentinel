from intelligence.base import IntelligenceResult, ProviderError
from intelligence.http import HTTPProvider


class AbuseCHProvider(HTTPProvider):
    name = "abusech"

    def __init__(
        self,
        auth_key: str,
        score: int = 90,
        endpoint: str = "https://threatfox-api.abuse.ch/api/v1/",
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.auth_key, self.score, self.endpoint = auth_key, score, endpoint

    async def check(self, ip: str) -> IntelligenceResult:
        if not self.auth_key:
            raise ProviderError("abuse.ch Auth-Key is not configured")
        response = await self.request(
            "POST",
            self.endpoint,
            headers={"Auth-Key": self.auth_key},
            json={"query": "search_ioc", "search_term": ip},
        )
        payload = response.json()
        status = payload.get("query_status")
        listed = status == "ok" and bool(payload.get("data"))
        if status not in {"ok", "no_result"}:
            raise ProviderError(f"abuse.ch query failed: {status or 'invalid response'}")
        return IntelligenceResult(
            source=self.name,
            ip=ip,
            listed=listed,
            score=self.score if listed else 0,
            reason="malware or botnet IOC in abuse.ch ThreatFox" if listed else "not listed",
            attributes={"matches": len(payload.get("data") or [])},
        )
