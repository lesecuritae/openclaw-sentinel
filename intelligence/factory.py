from core.config import Settings
from database.store import SecurityStore
from intelligence.abusech import AbuseCHProvider
from intelligence.asn import ASNProvider
from intelligence.blocklist_de import BlocklistDEProvider
from intelligence.cache import IntelligenceCache
from intelligence.dshield import DShieldProvider
from intelligence.geoip import GeoIPProvider
from intelligence.manager import IntelligenceManager, parse_duration
from intelligence.spamhaus import SpamhausProvider


def build_intelligence(settings: Settings, store: SecurityStore) -> IntelligenceManager:
    config = settings.load_intelligence()
    providers = {
        "spamhaus": SpamhausProvider(score=config.providers["spamhaus"].weight),
        "abusech": AbuseCHProvider(
            auth_key=settings.abusech_auth_key,
            score=config.providers["abusech"].weight,
            endpoint=config.providers["abusech"].endpoint
            or "https://threatfox-api.abuse.ch/api/v1/",
        ),
        "dshield": DShieldProvider(
            score=config.providers["dshield"].weight,
            endpoint=config.providers["dshield"].endpoint
            or "https://isc.sans.edu/api/ip/{ip}?json",
        ),
        "blocklist_de": BlocklistDEProvider(
            score=config.providers["blocklist_de"].weight,
            endpoint=config.providers["blocklist_de"].endpoint
            or "https://api.blocklist.de/api.php",
        ),
        "geoip": GeoIPProvider(),
        "asn": ASNProvider(),
    }
    ttl = parse_duration(config.cache_time.get("default", "24h"))
    return IntelligenceManager(config, IntelligenceCache(store, ttl), providers)
