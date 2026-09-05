# LLM security analyst

The LLM gateway supports local OpenAI-compatible endpoints and OpenRouter with
provider, endpoint, model, key and timeout settings. Analyst prompts contain
bounded normalized incident, event, profile and intelligence data. Log values
are untrusted, instruction-like text is removed, and prompts never include
credentials or action-control interfaces.

MCP exposes `security.explain_incident`, `security.generate_report`,
`security.analyze_ip` and `security.summarize_events`. Provider failures return
an unavailable result to MCP instead of changing security state. The dashboard
AI Analysis view is advisory only; policy and action tools remain separate.
