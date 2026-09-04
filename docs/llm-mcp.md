# LLM and MCP integration

Sentinel supports disabled, local OpenAI-compatible, and OpenRouter LLM providers. These providers
generate explanations and reports only. LLM responses never change risk scores, policies, ACLs or
firewall state.

The authenticated `/mcp` JSON-RPC endpoint exposes read-oriented security tools for OpenClaw,
OpenWebUI and other MCP clients. Clients can inspect an IP, events, incidents and risk, or request
an explanation/report. Deployments should place the endpoint behind TLS, set `SENTINEL_API_KEY`,
restrict network access and use a separate low-privilege credential per integration when scoped
credentials become available.

OpenRouter credentials are read from `OPENROUTER_API_KEY`; local models use `LOCAL_LLM_URL`. Never
place keys in MCP arguments, event metadata, rule files or Git.
