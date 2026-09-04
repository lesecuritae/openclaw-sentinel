import asyncio
import ipaddress
import logging
import re
from datetime import timedelta

from core.config import IntelligenceConfig
from intelligence.base import IntelligenceResult, ProviderError
from intelligence.cache import IntelligenceCache

log = logging.getLogger(__name__)
DURATION = re.compile(r"^(\d+)([smhd])$")


def parse_duration(value: str) -> timedelta:
    match = DURATION.fullmatch(value.strip().lower())
    if not match:
        raise ValueError(f"invalid cache duration: {value}")
    amount, unit = int(match.group(1)), match.group(2)
    return timedelta(seconds=amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit])


class IntelligenceManager:
    def __init__(self, config: IntelligenceConfig, cache: IntelligenceCache, providers: dict):
        self.config, self.cache, self.providers = config, cache, providers

    async def check(self, ip: str) -> list[IntelligenceResult]:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return []
        if not address.is_global:
            return []
        tasks = [
            self._check_provider(ip, name, provider)
            for name, provider in self.providers.items()
            if self.config.providers.get(name) and self.config.providers[name].enabled
        ]
        values = await asyncio.gather(*tasks) if tasks else []
        return [value for value in values if value is not None]

    async def _check_provider(self, ip: str, name: str, provider) -> IntelligenceResult | None:
        cached = self.cache.get(ip, name)
        if cached:
            return cached
        config = self.config.providers[name]
        try:
            result = await asyncio.wait_for(provider.check(ip), config.timeout)
        except (ProviderError, OSError, TimeoutError, ValueError) as exc:
            log.warning("Threat intelligence provider %s failed: %s", name, exc)
            return None
        ttl = parse_duration(config.ttl) if config.ttl else None
        return self.cache.put(result, ttl)

    def sources(self) -> list[dict]:
        return [
            {
                "source": name,
                "enabled": value.enabled,
                "weight": value.weight,
                "ttl": value.ttl or self.config.cache_time["default"],
            }
            for name, value in sorted(self.config.providers.items())
        ]
