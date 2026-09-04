# Configuration

Copy `.env.example` to `.env` and change only values needed by the deployment. Docker Compose
interpolates these settings into the container; `.env` is excluded from Git.

| Variable | Purpose | Safe default |
| --- | --- | --- |
| `SENTINEL_API_KEY` | Bearer token for REST and MCP | empty for loopback development only |
| `DATABASE_PATH` | SQLite security-memory path | `/data/sentinel.db` |
| `RULES_PATH`, `POLICY_PATH` | YAML configuration paths | image configuration directory |
| `INTELLIGENCE_PATH` | Threat-provider YAML configuration | image configuration directory |
| `HAPROXY_COLLECTOR_ENABLED` | Runtime session/stat collector | `false` |
| `HAPROXY_SOCKET` | Runtime Unix socket in the container | `/run/haproxy/admin.sock` |
| `HAPROXY_BLOCKLIST_PATH` | ACL path as known by HAProxy | example system path |
| `COLLECTOR_INTERVAL_SECONDS` | Runtime polling interval | `5` |
| `HAPROXY_REQUEST_COLLECTOR_ENABLED` | Structured UDP request collector | `false` |
| `HAPROXY_REQUEST_BIND` | Host interface publishing UDP | `127.0.0.1` |
| `HAPROXY_REQUEST_HOST` | Container listen address | `0.0.0.0` |
| `HAPROXY_REQUEST_PORT` | Structured request UDP port | `1514` |
| `ACTIONS_ENABLED` | Permit configured enforcement calls | `false` |
| `LLM_PROVIDER` | `disabled`, `local`, or `openrouter` | `disabled` |
| `MODEL`, `LOCAL_LLM_URL` | Selected model and local endpoint | unset/local example |
| `OPENROUTER_API_KEY` | OpenRouter credential | unset |
| `ABUSECH_AUTH_KEY` | abuse.ch ThreatFox credential | unset |
| `ANUBIS_URL` | Future external challenge endpoint | unset |

Do not expose an unauthenticated API or UDP listener to an untrusted network. Production secrets
should come from an external secret manager or a protected environment file, not Compose YAML.
