# Threat intelligence

Threat intelligence is an input to risk assessment, never an enforcement decision. Every lookup
returns a normalized source, IP, listed flag, bounded score, reason and small attribute set. Raw
feed records are neither stored nor sent to an LLM. Results are cached in SQLite until their YAML
TTL expires; failures add no score and do not overwrite a valid cached result.

## Providers

| Provider | Signal | Query | Credential |
| --- | --- | --- | --- |
| Spamhaus | ZEN IP reputation | reverse-IP DNS | resolver/use terms apply |
| abuse.ch | ThreatFox malware/botnet IOC | `search_ioc` HTTPS API | `ABUSECH_AUTH_KEY` |
| DShield | reports and attacked targets | SANS ISC IP JSON API | none |
| blocklist.de | reported attacks | IP JSON API | none for IP checks |
| GeoIP | country/region enrichment boundary | not implemented | none |
| ASN | provider/hosting/cloud enrichment boundary | not implemented | none |

The implementation follows the providers' published interfaces: [Spamhaus DNSBL usage and return
codes](https://www.spamhaus.org/faqs/dnsbl-usage/), [abuse.ch ThreatFox Community
API](https://threatfox.abuse.ch/api/), [SANS ISC/DShield API](https://isc.sans.edu/api/), and
[blocklist.de API](https://www.blocklist.de/en/api.html). Operators are responsible for current
terms, fair-use limits and commercial licensing requirements.

## Configuration

All providers are disabled by default. Enable only required sources in
`config/intelligence.yaml`; configure weight, timeout, endpoint and TTL there. Credentials stay in
environment variables. A listed provider contributes its configured weight. A single
intelligence source is capped below the default block threshold; multiple independent sources or
local behavioral evidence are required before a combined assessment can reach `BLOCK`.

```yaml
cache_time:
  default: 24h
single_source_ceiling: 89
providers:
  spamhaus:
    enabled: true
    weight: 80
    ttl: 24h
    timeout: 5
```

Only globally routable IP addresses are eligible for external lookup. Private, loopback,
link-local, reserved and malformed addresses never leave Sentinel. Providers execute concurrently
with timeouts. Store/API output contains normalized evidence, not entire upstream records.

## Adding a provider

Implement `IntelligenceProvider.check(ip) -> IntelligenceResult`, add its configuration and
factory registration, then test listed, unlisted, malformed and upstream-failure responses with a
mock transport. A provider must not import the policy/action layer or execute any response. New
providers become risk inputs through `IntelligenceManager`; the Risk Engine itself does not need
provider-specific logic.
