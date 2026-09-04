# Architecture

Sentinel separates collection, normalization, detection, risk assessment and response. A source
cannot directly invoke an action. Events first pass the canonical schema and persistence layer;
policy alone selects an action adapter.

```text
sources -> Collector -> EventNormalizer -> SecurityStore
                                           |
                                           v
                                    DetectionEngine
                                           |
IntelligenceManager -> TTL cache --> RiskEngine
                                           |
                                      PolicyEngine
                                      /    |     \
                                  allow challenge block
                                           |       |
                                        Anubis  action provider
```

HAProxy currently supplies runtime sessions/statistics and structured request events. Threat
providers are called only for globally routable IPs, concurrently and through a local TTL cache.
Collector,
`IntelligenceProvider`, `ActionProvider`, `ChallengeProvider`, `LLMProvider`, and the explicit
plugin registry form stable extension boundaries. Planned collectors include Nginx, Linux,
Windows, Docker and cloud sources. Planned intelligence providers include Spamhaus, abuse.ch,
DShield, CrowdSec, GeoIP and ASN reputation. Firewall and cloud actions can be added without
coupling them to detection rules.

LLM and MCP integrations query stored observations and prepare explanations or reports. They are
not part of the trusted decision path and cannot authorize or execute security actions.

## Phase 3: Adaptive Risk Intelligence

- `engine/behavior`: request/access pattern observation (no autonomous rule changes)
- `engine/baseline`: service/pattern baselines (observation/recommendation only; safe SQLite migration)
- `engine/trust`: deterministic 0..100 trust engine (neutral start 50), poisoning protection (blocked/challenged events excluded from positive baseline training)
- `engine/geo_time`: explainable geo/time mismatch (missing data = no positive finding)
- `engine/client`: explainable client mismatch (no invented fingerprints when features missing)
- `core/models`: optional normalized fields (`accept_language`, `client_timezone`, `device_id`, `tls_fingerprint`)
- Every score change is a persisted, deterministic factor (`source/score/reason/kind`) with no autonomous rule modification.
