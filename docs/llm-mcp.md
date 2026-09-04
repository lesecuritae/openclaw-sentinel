# LLM and MCP integration

Sentinel supports disabled, local OpenAI-compatible, and OpenRouter LLM providers. These providers
generate explanations and reports only. LLM responses never change risk scores, policies, ACLs or
firewall state.

Risk explanation context is deliberately normalized to the score, factor source/score/reason,
event types and affected services. Raw threat-feed responses and cache records are excluded.

The authenticated `/mcp` JSON-RPC endpoint exposes read-oriented security tools for OpenClaw,
OpenWebUI and other MCP clients. Clients can inspect an IP, events, incidents and risk, or request
an explanation/report. Deployments should place the endpoint behind TLS, set `SENTINEL_API_KEY`,
restrict network access and use a separate low-privilege credential per integration when scoped
credentials become available.

Phase 2 adds `security.check_ip_reputation`, `security.get_threat_sources`,
`security.get_ip_history`, and `security.explain_risk_score`.

OpenRouter credentials are read from `OPENROUTER_API_KEY`; local models use `LOCAL_LLM_URL`. Never
place keys in MCP arguments, event metadata, rule files or Git.
