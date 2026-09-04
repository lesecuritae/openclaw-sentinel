# OpenClaw Sentinel

OpenClaw Sentinel is a modular security intelligence core. Phase 1 normalizes security
events, evaluates YAML rules, calculates a risk score, applies policy, persists security
memory, and can update an HAProxy ACL through its runtime socket without restarting HAProxy.

```text
HAProxy runtime socket -> collector -> normalizer -> detection -> risk -> policy
                                                                    | allow
                                                                    | Anubis challenge
                                                                    ` HAProxy block
Security memory <-> REST/MCP <-> LLM gateway <-> local model or OpenRouter
```

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8080/health
```

The standalone configuration starts successfully without HAProxy and binds only to localhost.
Set a long `SENTINEL_API_KEY` before exposing the API. Requests to all endpoints except health
then require `Authorization: Bearer <token>`. No secret belongs in Git; `.env` is ignored.

Submit a normalized event:

```bash
curl -X POST http://127.0.0.1:8080/events \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer TOKEN' \
  -d '{"source":"haproxy","ip":"1.2.3.4","service":"vaultwarden","event_type":"failed_login","severity":"medium","metadata":{"status":401}}'
```

## HAProxy setup

Create an empty persistent ACL file on the HAProxy host, configure the administrative runtime
socket, and reject matching clients in the relevant frontend:

```haproxy
global
  stats socket /run/haproxy/admin.sock mode 660 level admin

frontend public
  acl sentinel_blocked src -f /etc/haproxy/sentinel-blocklist.lst
  http-request deny deny_status 403 if sentinel_blocked
```

HAProxy must load the file once during configuration deployment. Afterwards Sentinel uses
`add acl` and `del acl` over the runtime API; it never restarts HAProxy. Grant the container
access to the socket deliberately, then start with the override:

```bash
docker compose -f docker-compose.yml -f docker-compose.haproxy.yml.example up -d --build
```

`ACTIONS_ENABLED=false` is the safe default. Enable it only after verifying the socket,
administrative permissions, ACL path, and recovery access. Source IPs are validated before a
runtime command is formed. Runtime `show sess` supplies active client/session data; `show stat`
supplies aggregate status/error counters. HAProxy's runtime API does not expose historical HTTP
paths per request, so request-level status/path events enter through `/events` (a log collector is
planned). Aggregate events without a source address are stored but never trigger an IP action.

## Rules and policy

Detection is configured in [config/rules.yaml](config/rules.yaml): event type, status, path,
threshold, time window, and score are data—not embedded thresholds. Policy thresholds and
provider switches live in [config/policy.yaml](config/policy.yaml). Phase 1 executes allow/block.
The challenge decision and `actions/anubis` provider boundary exist, but challenge routing is
disabled until an external Anubis deployment is configured in a later phase.

Security memory is SQLite in the `sentinel-data` volume. It stores events, per-IP profiles and
action audit records. Extension protocol `RiskFactorProvider` is the boundary for future threat
feeds, ASN/geo reputation, history, fingerprints and ML-derived factors.

## LLM and MCP

`LLM_PROVIDER` supports `disabled` (default), `local`, or `openrouter`. Local mode expects an
OpenAI-compatible `/v1/chat/completions` endpoint. OpenRouter requires `OPENROUTER_API_KEY` and
`MODEL`; neither is stored in the database or repository. Event content is explicitly wrapped as
untrusted data, but operators should still use a suitably isolated model.

The authenticated `/mcp` endpoint implements the Phase-1 JSON-RPC boundary with these tools:

- `security.check_ip`
- `security.get_events`
- `security.get_incidents`
- `security.get_risk_score`
- `security.explain_event`
- `security.generate_report`

It provides MCP initialize, tools/list and tools/call primitives. Production streaming transports,
authorization scopes and richer report resources are roadmap work.

## Development and tests

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
ruff check .
pytest
docker compose config
docker compose build
```

Tests cover normalization, scoring, policy boundaries, simulated HAProxy collection, runtime ACL
blocking, input rejection and an LLM provider mock. GitHub Actions runs lint, tests and a Docker
build on pushes and pull requests.

## Roadmap

- HAProxy log/SPOE request collector and additional Linux, Windows, Docker and Kubernetes sources
- External threat intelligence and cloud adapters through factor/provider interfaces
- Production Anubis routing and challenge-result feedback
- MCP streaming transport, scoped credentials and incident/report resources
- Audited rule suggestions, optional ML and learning models (never autonomous by default)
