import asyncio
import ipaddress
import socket

from intelligence.base import IntelligenceResult, ProviderError


class SpamhausProvider:
    name = "spamhaus"
    error_codes = {"127.255.255.252", "127.255.255.254", "127.255.255.255"}

    def __init__(self, score: int = 80, zone: str = "zen.spamhaus.org", resolver=None):
        self.score, self.zone, self.resolver = score, zone, resolver

    async def check(self, ip: str) -> IntelligenceResult:
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            return IntelligenceResult(source=self.name, ip=ip, score=0, reason="IPv6 not queried")
        query = f"{'.'.join(reversed(ip.split('.')))}.{self.zone}"
        try:
            if self.resolver:
                answers = await self.resolver(query)
            else:
                loop = asyncio.get_running_loop()
                records = await loop.getaddrinfo(query, 0, type=socket.SOCK_STREAM)
                answers = sorted({record[4][0] for record in records})
        except socket.gaierror as exc:
            if exc.errno in {socket.EAI_NONAME, socket.EAI_NODATA}:
                answers = []
            else:
                raise ProviderError(f"Spamhaus DNS lookup failed: {exc}") from exc
        if self.error_codes.intersection(answers):
            raise ProviderError("Spamhaus returned a DNSBL query error")
        listed = any(answer.startswith("127.") for answer in answers)
        return IntelligenceResult(
            source=self.name,
            ip=ip,
            listed=listed,
            score=self.score if listed else 0,
            reason="listed by Spamhaus ZEN" if listed else "not listed",
            attributes={"return_codes": ",".join(answers)},
        )
