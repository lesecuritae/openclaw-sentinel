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
intelligence providers ------------> RiskEngine
                                           |
                                      PolicyEngine
                                      /    |     \
                                  allow challenge block
                                           |       |
                                        Anubis  action provider
```

HAProxy currently supplies runtime sessions/statistics and structured request events. Collector,
`IntelligenceProvider`, `ActionProvider`, `ChallengeProvider`, `LLMProvider`, and the explicit
plugin registry form stable extension boundaries. Planned collectors include Nginx, Linux,
Windows, Docker and cloud sources. Planned intelligence providers include Spamhaus, abuse.ch,
DShield, CrowdSec, GeoIP and ASN reputation. Firewall and cloud actions can be added without
coupling them to detection rules.

LLM and MCP integrations query stored observations and prepare explanations or reports. They are
not part of the trusted decision path and cannot authorize or execute security actions.
