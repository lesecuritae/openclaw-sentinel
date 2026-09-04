# Plugin contracts

Plugins are explicit Python objects registered by type and name; Sentinel does not execute code
discovered from untrusted event data.

- `Collector.run(emit)` produces canonical `SecurityEvent` objects. HAProxy is implemented;
  Nginx, Linux, Windows, Docker and cloud collectors are planned.
- `IntelligenceProvider.lookup(event)` returns passive enrichment and a bounded score. Spamhaus,
  abuse.ch, DShield, CrowdSec, GeoIP and ASN reputation are Phase 2 candidates.
- `ActionProvider.execute(assessment)` is the boundary for HAProxy, firewalls and cloud APIs.
- `ChallengeProvider.challenge(ip)` delegates browser verification to external systems such as
  Anubis.
- `LLMProvider.analyze(prompt)` supports local OpenAI-compatible models and OpenRouter.

Provider construction and credentials must come from configuration. New plugins should be
independently testable, use timeouts, fail closed at their own trust boundary, and never silently
enable automatic actions.
