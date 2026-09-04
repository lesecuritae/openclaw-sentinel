# Phase 4 Backend

# Phase 4 dashboard backend

## REST API `/api/v1`

- Dashboard summary and affected services
- Paginated events and incidents
- IP detail, history, actions, devices, and threat intelligence
- Atomic, schema-validated configuration reads and updates
- HAProxy status and validated unblock action
- Challenge, LLM, and MCP status

## WebSocket `/api/v1/ws/events`

- Authentication through the first JSON frame within five seconds
- Exact configured origin or same-origin checks
- Bounded per-client queue (maximum 50 events)
- Non-blocking event publication from the processing pipeline

## Security

- API keys are held in browser memory and never returned by status endpoints
- Configuration updates use same-directory atomic replacement and `fsync`
- Pydantic schemas reject unknown keys and invalid threshold ordering
- CORS is disabled by default and security response headers are always set
- LLM integrations remain advisory and cannot trigger an action
