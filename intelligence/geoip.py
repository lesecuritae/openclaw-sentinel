from intelligence.base import IntelligenceResult


class GeoIPProvider:
    """Phase-2 enrichment boundary; no external GeoIP lookup is performed yet."""

    name = "geoip"

    async def check(self, ip: str) -> IntelligenceResult:
        return IntelligenceResult(source=self.name, ip=ip, score=0, reason="provider prepared")
