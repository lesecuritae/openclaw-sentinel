<div align="center">
  <img src="assets/logo.svg" width="150" alt="OpenClaw Sentinel shield and analysis core logo">
  <h1>OpenClaw Sentinel</h1>
  <p><strong>Security intelligence for observable, policy-driven protection.</strong></p>
  <p>
    <a href="https://github.com/lesecuritae/openclaw-sentinel/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lesecuritae/openclaw-sentinel/actions/workflows/ci.yml/badge.svg"></a>
    <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache--2.0-blue.svg"></a>
    <img alt="Self hosted" src="https://img.shields.io/badge/deployment-self--hosted-12b8c4">
  </p>
</div>

![OpenClaw Sentinel: data to risk to protection](assets/banner.png)

OpenClaw Sentinel is a modular, self-hosted security intelligence platform. It exists to connect
security observations with explainable risk analysis and controlled response without coupling
every data source directly to a firewall or proxy.

Sentinel is **not a traditional firewall**. It is the intelligence layer between data sources,
risk analysis and independently configured actions. It normalizes events, evaluates YAML rules,
calculates an explainable score, applies policy, preserves security memory and delegates any
enforcement to a least-privilege provider.

## Architecture

```text
HAProxy runtime socket --------> collector -> normalizer -> event store -> detection -> risk -> policy
HAProxy JSON logs / SPOE ------^                                      | allow
                                                                    | Anubis challenge
                                                                    ` HAProxy block
Security memory <-> REST/MCP <-> advisory LLM gateway <-> local model or OpenRouter
```

See [architecture](docs/architecture.md), [security model](docs/security-model.md), and
[plugin contracts](docs/plugins.md) for the trust boundaries and planned providers.

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8080/health
```

For a first deployment, use `docker-compose.example.yml` and copy `.env.example` to `.env`.
Open `/api/v1/setup/status`; when uninitialized, complete `/api/v1/setup/initialize` with an
operator-generated `SETUP_BOOTSTRAP_TOKEN` in the `X-Bootstrap-Token` header and a JSON body
containing `username` and a new `api_key` (at least 32 random characters). The key becomes active
immediately. Bootstrap is atomically single-use and refuses to overwrite existing users.
Generate each token independently using `openssl rand -hex 32`; the wizard never returns or
stores the cleartext key. Without configured credentials, API and WebSocket access is denied.

### Installation and updates

Pin the image tag in Compose, keep `/data` on a persistent volume, and take a configuration
backup before updates. Export/import and backup are available to administrators in the
Configuration API. Validate a restored configuration before enabling response actions; keep
`RESPONSE_DRY_RUN=true` and `ACTIONS_ENABLED=false` until collectors, policies and provider
connectivity have been reviewed.

### Configuration and security

The Configuration view groups General, Collectors, Threat Intelligence, Policies, Response, LLM
and Users. YAML is schema-validated and written atomically. Use a long API key, restrict port
exposure, mount only required sockets, and never commit `.env` or provider credentials. Viewer,
analyst and administrator roles constrain operational access; all changes are recorded in the
audit log.

The standalone configuration starts successfully without HAProxy and binds only to localhost.
Set independent `SENTINEL_ADMIN_KEY`, `SENTINEL_ANALYST_KEY` and/or `SENTINEL_VIEWER_KEY`
credentials (32 characters minimum). `SENTINEL_API_KEY` is a legacy explicitly configured admin
credential. Protected endpoints always require `Authorization: Bearer <token>`. No secret belongs in Git; `.env` is ignored.

Submit a normalized request event (also the HTTP boundary for an SPOE forwarder):

```bash
curl -X POST http://127.0.0.1:8080/events \
  -H 'Content-Type: application/json' -H "Authorization: Bearer ${COLLECTOR_TOKEN}" \
  -d '{"source":"haproxy","ip":"192.0.2.10","hostname":"app.example.org","service":"application","event_type":"request","path":"/login","method":"POST","user_agent":"example-client/1.0","severity":"medium","metadata":{"status":401,"frontend":"public","backend":"application"}}'
```

Ready-to-send canonical and collector-level payloads are provided under `examples/`.

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
runtime command is formed.

### Request event pipeline

Runtime `show sess` and `show stat` collectors read the local HAProxy socket. External events
must use authenticated HTTP `/events` through TLS. The unauthenticated UDP listener is disabled;
setting `HAPROXY_REQUEST_COLLECTOR_ENABLED=true` now fails configuration validation.

Configure an independent credential for each collector, with exact source, event-type and service
allowlists, for example in `.env` (replace the token with a newly generated random secret):

```dotenv
COLLECTOR_CREDENTIALS={"edge":{"token":"REPLACE_WITH_32_OR_MORE_RANDOM_CHARACTERS","source":"haproxy","event_types":["request"],"services":["application"]}}
```

User API keys cannot ingest events. Server-side provenance is attached as `collector_id`; sender
IDs are replaced, timestamps must be within five minutes, and event fields and metadata are bounded.
The identity resolver is prepared for verified signatures or mTLS; neither is claimed as implemented.
Internal in-process collectors retain their local trust boundary.

## Rules and policy

Detection is configured in [config/rules.yaml](config/rules.yaml): event type, status, path,
HTTP method, threshold, distinct field, time window, and score are data—not embedded thresholds.
Rules cover known scanner paths, repeated POSTs to login endpoints and multiple different scanner
paths from one IP in 60 seconds. Policy thresholds and
provider switches live in [config/policy.yaml](config/policy.yaml). Phase 1 executes allow/block.
The challenge decision and `actions/anubis` provider boundary exist, but challenge routing is
disabled until an external Anubis deployment is configured in a later phase.

Security memory is SQLite in the `sentinel-data` volume. It stores every request field, event risk
score, per-IP profiles including score reasons, and action audit records. Existing Phase 1
databases are migrated additively at startup. Extension protocol `RiskFactorProvider` is the boundary for future threat
feeds, ASN/geo reputation, history, fingerprints and ML-derived factors.

## LLM and MCP

`LLM_PROVIDER` supports `disabled` (default), `local`, or `openrouter`. Local mode expects an
OpenAI-compatible `/v1/chat/completions` endpoint. OpenRouter requires `OPENROUTER_API_KEY` and
`MODEL`, explicit `LLM_ALLOWED_PROVIDERS=["disabled","local","openrouter"]` and
`LLM_DATA_CLASSIFICATION=external-redacted`; neither credential is stored in the database or repository. Event content is explicitly wrapped as
untrusted data, but operators should still use a suitably isolated model. LLM output is advisory:
it cannot choose policy outcomes or invoke HAProxy, challenge, firewall, or cloud actions.

The authenticated `/mcp` endpoint implements the Phase-1 JSON-RPC boundary with these tools:

- `security.check_ip`
- `security.get_events`
- `security.get_incidents`
- `security.get_risk_score`
- `security.explain_event`
- `security.generate_report`

It provides MCP initialize, tools/list and tools/call primitives. Production streaming transports,
authorization scopes and richer report resources are roadmap work.
See [LLM and MCP integration](docs/llm-mcp.md) for OpenClaw, OpenWebUI and other clients.

## Threat intelligence

Phase 2 adds optional Spamhaus, abuse.ch ThreatFox, DShield and blocklist.de reputation signals,
backed by a local SQLite TTL cache. GeoIP and ASN enrichment have provider boundaries but perform
no lookup yet. Providers normalize evidence; they cannot call policy or action adapters. The Risk
Engine combines their weighted results with local scanner, request-rate and login evidence while
retaining every factor and reason. One feed alone is capped below the block threshold.

All external providers are disabled by default. Enable only necessary sources in
`config/intelligence.yaml`, set `ABUSECH_AUTH_KEY` through the environment when required, and
review each provider's terms. Sentinel never queries non-global IPs and never forwards raw feed
records to an LLM. See [Threat intelligence](docs/threat-intelligence.md) for configuration,
privacy controls, upstream documentation and custom-provider guidance.

## Adaptive risk intelligence

Phase 3 adds deterministic request-pattern, geo/time and client-change analysis to the live risk
path. Safe observations build bounded per-device profiles and service baselines. Profiles start at
a neutral trust score of 50 and require at least ten consistent, sufficiently confident samples
before trust can lower risk. Challenged, blocked or otherwise risky requests never build positive
trust.

Every anomaly is stored with its event, source, score, reason and factor kind. Missing country,
timezone or client attributes stay neutral; Sentinel does not infer fingerprints or block by
country. Adaptive components only produce evidence for the Risk Engine and never rewrite rules.
The MCP interface exposes read-only profile, anomaly and trust inspection tools. See
[architecture](docs/architecture.md) and [privacy](docs/privacy.md) for details.

## Web dashboard and API

Phase 4 serves a React dashboard at `http://127.0.0.1:8080/`. It provides current risk and
24-hour totals, live WebSocket events, incidents, IP history, HAProxy state, challenge/LLM/MCP
status, and validated editors for policy and threat-intelligence configuration. The API is under
`/api/v1`; live events use `/api/v1/ws/events` and authenticate with the API key in the first
WebSocket frame. The browser keeps that key in memory rather than persistent web storage.

Set `SENTINEL_API_KEY` before making the service reachable beyond localhost. Cross-origin browser
access is denied unless exact origins are listed in `CORS_ORIGIN_ALLOWLIST`; same-origin dashboard
access needs no CORS setting. Configuration updates reject unknown fields, validate thresholds,
and replace YAML files atomically. A successful update reports that Sentinel must be restarted
before the new engine configuration is active. See [Phase 4 backend](docs/backend/phase4.md).

## Security model

Safe defaults matter because Sentinel can sit near enforcement infrastructure. Automatic actions
and collectors are opt-in, the API binds to loopback, the container drops Linux capabilities, and
provider credentials come only from environment configuration. Deploy behind TLS, authenticate
the API, isolate the HAProxy socket, use dedicated HTTP collector credentials, and retain an
independent recovery path. See [SECURITY.md](SECURITY.md) before production use or vulnerability
reporting.

## Extending Sentinel

Interfaces are available for collectors, threat-intelligence enrichment, actions, external
challenges and LLM providers. Planned sources include Nginx, Linux, Windows, Docker and cloud
events. Phase 2 targets Spamhaus, abuse.ch, DShield, GeoIP, ASN reputation and VPN/Tor signals.
Extensions remain explicitly registered and configured; event input never loads executable code.

## Development and tests

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
ruff check .
pytest
cd frontend && npm ci && npm run lint && npm test && npm run build && cd ..
docker compose config
docker compose build
```

Tests cover structured request decoding, persistence, scanner/login detection, distinct paths,
scoring, policy boundaries, simulated HAProxy collection, runtime ACL blocking, input rejection,
dashboard/API authorization, configuration safety, bounded WebSocket delivery and an LLM provider
mock. GitHub Actions runs Python and frontend lint/tests/builds plus a Docker build on pushes and
pull requests.

## Roadmap

- Reliable syslog relay/SPOE adapter and additional Linux, Windows, Docker and Kubernetes sources
- VPN/Tor signals and production GeoIP/ASN enrichment
- Production Anubis routing and challenge-result feedback
- MCP streaming transport, scoped credentials and incident/report resources
- Audited rule suggestions, optional ML and learning models (never autonomous by default)

## License and community

OpenClaw Sentinel is licensed under [Apache License 2.0](LICENSE). Apache-2.0 was selected over
AGPL-3.0 to encourage broad use and integration across self-hosted, proxy and infrastructure
projects while retaining attribution, license notices and an explicit patent grant. Contributions
are welcome under [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Phase 4.5 — Production Integration Layer

Phase 4.5 adds opt-in Docker events, Linux authentication and service-log collectors behind the
shared collector contract. File collectors use bounded incremental reads. Authentication parsers
normalize Linux SSH, Vaultwarden, Nextcloud and Gitea failures without retaining raw log lines.
The dashboard exposes real container, warning and per-service event aggregates from SQLite.

Docker monitoring requires `DOCKER_COLLECTOR_ENABLED=true` and `DOCKER_API_URL` pointing to a
separately administered Docker socket proxy. Direct access to the Docker socket is equivalent to
host-level control and is deliberately not mounted by the supplied Compose file. Restrict the
proxy to read-only `GET /events` and `GET /containers/{id}/json`; never expose it publicly.

For an isolated integration fixture, run:

```bash
docker compose -f docker-compose.test.yml up -d
bash tests/simulate-production-events.sh
docker compose -f docker-compose.test.yml restart testservice
docker compose -f docker-compose.test.yml down -v
```

The test stack binds HAProxy only to localhost. It is a traffic fixture, not a production
deployment. Collector settings and production trust boundaries are documented in
[Production deployment](docs/deployment.md) and [Phase 4.5](docs/backend/phase45.md).

### Service adapter framework

Service log collectors use configurable adapters (`VaultwardenAdapter`, `NextcloudAdapter`, `GiteaAdapter`, `PlexAdapter`) registered under `SERVICE_ADAPTERS`. No service-specific `if/else` logic exists in the core collector interface. Plex adapter has no invented login semantics; only media/session events are emitted when configured patterns match.

### Optional dashboard two-factor authentication

Set `WEB_2FA_ENABLED=true`, retain a strong `SENTINEL_API_KEY`, and provide an existing base32
TOTP secret through `WEB_2FA_SECRET` or preferably a mounted file named by
`WEB_2FA_SECRET_FILE`. Sentinel never generates or returns this secret. When enabled, the browser
exchanges the API key and six-digit authenticator code for a short-lived opaque session; the
session exists only in server and browser memory. Dashboard REST and WebSocket endpoints reject
the permanent API key directly, while machine-oriented ingest and MCP endpoints remain compatible.
If the authenticator is lost, an administrator with host access must disable 2FA or replace the
mounted secret and restart Sentinel. Do not expose the dashboard until enrollment is verified.

## Audit security fixes and release validation

See [security operations](docs/backend/security-operations.md) for scopes, bootstrap, limits,
action expiry and upgrade requirements. Python runtime, test and build dependencies are fixed in
hash-checked `requirements*.lock`; frontend dependencies are fixed by `package-lock.json` and
installed with lifecycle scripts disabled. Docker bases and workflow actions use immutable digests.
CI emits a wheel, CycloneDX runtime SBOM, SHA256SUMS and GitHub build provenance attestations.
Verify downloaded artifacts with `sha256sum -c SHA256SUMS` and
`gh attestation verify <artifact> --repo lesecuritae/openclaw-sentinel`.
