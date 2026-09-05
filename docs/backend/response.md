# Adaptive response layer

Responses follow the deterministic chain `Event → Detection → Risk Score →
Incident → Policy → Action`. Policy rules are ordered by priority and may match
risk score, source and event type. The supported action vocabulary is
`log_only`, `alert`, `anubis_challenge`, `haproxy_block` and `rate_limit`.

The policy engine contains no LLM decision path. Actions remain adapter
boundaries and are recorded for audit; future expiry-aware HAProxy blocks and
Anubis outcomes can be added without changing the policy contract. Policies can
be inspected and tested through the dashboard, API and MCP tools.
