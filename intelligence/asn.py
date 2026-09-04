from intelligence.base import IntelligenceResult


class ASNProvider:
    """Phase-2 enrichment boundary for provider/hosting/cloud ASN metadata."""

    name = "asn"

    async def check(self, ip: str) -> IntelligenceResult:
        return IntelligenceResult(source=self.name, ip=ip, score=0, reason="provider prepared")
