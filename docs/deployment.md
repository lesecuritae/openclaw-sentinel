# Production Deployment

Safe defaults for Phase 4.5 integration layer:

- All new collectors (`docker`, `auth`, `service`) disabled by default.
- Enable only required sources via environment variables.
- Docker access uses read-only events only; compose overrides must
  restrict socket exposure.
- Auth/service log paths are configurable; no hardcoded service logic.
- No credentials stored in repository or database.
- Restart required after policy/intelligence updates.

## Collector Configuration

```yaml
# Example .env overrides (not committed)
DOCKER_COLLECTOR_ENABLED=false
AUTH_COLLECTOR_ENABLED=false
SERVICE_LOG_COLLECTOR_ENABLED=false
```

## Security Boundaries

- Collector disabled by default.
- Read-only/minimal privileges.
- No credentials logged/stored/committed.
- No automatic action from a single collector signal.
- No LLM-controlled actions.

## Optional Web 2FA

Dashboard TOTP is disabled by default. Enable `WEB_2FA_ENABLED` only after supplying both a
non-empty `SENTINEL_API_KEY` and a base32 secret via `WEB_2FA_SECRET` or a root-managed mounted
file configured with `WEB_2FA_SECRET_FILE`. Web sessions expire after
`WEB_SESSION_TTL_SECONDS` (15 minutes by default), remain memory-only, and are invalidated by
logout. Five failed attempts per client address trigger a five-minute login throttle.
