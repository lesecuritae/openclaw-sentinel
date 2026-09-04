from intelligence.base import IntelligenceResult, ProviderError
from intelligence.http import HTTPProvider


class DShieldProvider(HTTPProvider):
    name = "dshield"

    def __init__(
        self,
        score: int = 60,
        endpoint: str = "https://isc.sans.edu/api/ip/{ip}?json",
        minimum_reports: int = 1,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.score, self.endpoint, self.minimum_reports = score, endpoint, minimum_reports

    async def check(self, ip: str) -> IntelligenceResult:
        data = self._record((await self.request("GET", self.endpoint.format(ip=ip))).json())
        try:
            reports = int(str(data.get("count") or data.get("reports") or 0).strip())
            attacks = int(str(data.get("attacks") or 0).strip())
        except (TypeError, ValueError) as exc:
            raise ProviderError("DShield returned invalid counters") from exc
        listed = reports >= self.minimum_reports or attacks >= self.minimum_reports
        return IntelligenceResult(
            source=self.name,
            ip=ip,
            listed=listed,
            score=self.score if listed else 0,
            reason="reported scanner or attacker in DShield" if listed else "not listed",
            attributes={"reports": reports, "attacks": attacks},
        )

    @staticmethod
    def _record(payload):
        data = payload.get("ip", payload)
        if isinstance(data, list):
            return data[0] if data else {}
        if not isinstance(data, dict):
            raise ProviderError("DShield returned an invalid response")
        return data
