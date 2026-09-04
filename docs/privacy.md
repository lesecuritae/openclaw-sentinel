# Privacy and data retention

- `tls_fingerprint` and `device_id` are optional normalized fields supplied by a trusted collector;
  Sentinel does not generate invasive browser fingerprints.
- Device observations are deduplicated and bounded to 32 values per category. Baseline counters are
  capped, but operators remain responsible for database-level retention and deletion.
- MCP returns stored normalized observations to authenticated clients. LLM risk explanations receive
  normalized factor summaries, never raw threat-feed records, credentials or fingerprints.
- External threat providers receive only globally routable IP addresses when explicitly enabled.
- Trust and anomaly scores are deterministic. They cannot rewrite detection or policy rules.
