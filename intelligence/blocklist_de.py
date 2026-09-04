from intelligence.base import IntelligenceResult, ProviderError
from intelligence.http import HTTPProvider


class BlocklistDEProvider(HTTPProvider):
    name = "blocklist_de"

    def __init__(
        self, score: int = 60, endpoint: str = "https://api.blocklist.de/api.php", **kwargs
    ):
        super().__init__(**kwargs)
        self.score, self.endpoint = score, endpoint

    async def check(self, ip: str) -> IntelligenceResult:
        payload = (
            await self.request("GET", self.endpoint, params={"ip": ip, "format": "json"})
        ).json()
        try:
            attacks, reports = int(payload.get("attacks") or 0), int(payload.get("reports") or 0)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ProviderError("blocklist.de returned invalid counters") from exc
        listed = attacks > 0 or reports > 0
        return IntelligenceResult(
            source=self.name,
            ip=ip,
            listed=listed,
            score=self.score if listed else 0,
            reason="known attacker in blocklist.de" if listed else "not listed",
            attributes={"attacks": attacks, "reports": reports},
        )
