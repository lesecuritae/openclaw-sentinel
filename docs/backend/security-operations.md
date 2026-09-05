# Security operations

All protected REST routes, MCP calls and event WebSockets fail closed. Health, setup status and
auth status disclose minimal readiness information only. Neither `X-Sentinel-Role` nor
`X-Sentinel-User` is an authorization or audit identity source.

| Role | Permissions |
| --- | --- |
| viewer | incident.read, policy.read, action.read |
| analyst | viewer scopes plus report.create, llm.analyze |
| administrator | all of the above plus incident.write, policy.write, action.execute, config.export, config.write, user.read, audit.read |

Configured role keys identify distinct service users; bootstrap users are resolved from the users
table. Sessions bind to a credential digest and re-resolve role and enabled state on every request.
Changing a database user's role takes immediate effect; disabling the user or rotating its credential
invalidates its sessions. Configured key rotation takes effect on restart. `SENTINEL_API_KEY` is the
legacy explicit admin key, superseded by `SENTINEL_ADMIN_KEY`. Keys must be independent and at least
32 random characters. There is no anonymous development bypass.

Bootstrap requires an operator-generated `SETUP_BOOTSTRAP_TOKEN`, sent as `X-Bootstrap-Token` to
`POST /api/v1/setup/initialize`, plus `username` and a new independent `api_key`. One SQLite write
transaction checks existing users and setup state and inserts the first admin. The resulting key
works immediately; subsequent calls return 409. Keep the database on persistent storage. Remove the
bootstrap token from deployment configuration after setup. Bootstrap does not bypass configured 2FA.

Audit records use the authenticated user ID, a non-secret session/credential identifier, UTC time,
action and before/after state. System expiry uses a dedicated system identity. The database remains
an operator-controlled trust boundary: this does not claim cryptographic resistance to a database
administrator rewriting records.

## Input budgets

Defaults per minute, per API process: API 600, collector ingest 300, MCP 60, reports 10, LLM 10,
login/bootstrap 20. Counters are global rather than keyed by spoofable forwarding headers or an
unbounded number of clients. Report and LLM budgets also apply behind MCP. Body limits count actual
bytes, including chunked requests: 32 KiB for events and 256 KiB for other requests. Metadata allows
32 top-level keys, 8 KiB and at most four nested levels. LLM input is at most 16 KiB and only contains
normalized schema fields with secret redaction; raw metadata, paths, user agents, fingerprints and
incident timelines are not sent. Provider output is bounded and advisory, with no tools attached.

Run one API worker per database (the shipped image enforces one worker); distributed deployments
need shared budgets and action ownership before adding replicas. Place public access behind TLS.
The raw UDP collector is disabled because it cannot authenticate provenance. Use the dedicated HTTP
collector credentials documented in the README. Signatures and mTLS are extension points only.

## Action expiry

An expiry task runs every five seconds and reconciles persisted state at startup. HAProxy block
intent is persisted before calling the provider. The adapter validates runtime replies and reads
the ACL back before confirming application or removal. Expired or uncertain blocks remain pending
until removal succeeds; failures are retried. Several leases for one IP keep the longest active
lease. Manual unblock revokes all matching managed leases only after verified removal.
Disabling actions does not falsely mark old blocks removed: enable the adapter or remove the ACL
through the independent operator recovery path. Unsupported per-IP HAProxy rate-limit commands are
disabled; unsupported provider rollbacks return failure rather than a false success.

## Builds

Use Python 3.12 and Node 22. Install `requirements-test.lock` and `requirements-build.lock` using
`pip install --require-hashes`, then install the project with `--no-deps --no-build-isolation`.
Use `npm ci --ignore-scripts`. Runtime wheels are downloaded with hashes and installed offline.
`SOURCE_DATE_EPOCH` is fixed for reproducible wheel metadata. CI generates a runtime SBOM, checksums
and artifact attestations; artifacts are uploaded only after successful validation. Dependencies and
Docker/Action pins must be deliberately refreshed and reviewed for security updates.
