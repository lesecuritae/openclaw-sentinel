# Response providers

Phase 7 connects deterministic policy decisions to provider adapters. Anubis
issues challenges and exposes a status lookup; HAProxy supports expiry-bounded
ACL blocks, rate-limit preparation and rollback. The service computes an expiry
before invoking a provider and stores the provider result in the action audit.

Provider calls are only reached after PolicyEngine evaluation and are skipped
when `RESPONSE_DRY_RUN=true`. Actions can be inspected through `/actions` and
the Actions dashboard, and revoked through the API or MCP.
