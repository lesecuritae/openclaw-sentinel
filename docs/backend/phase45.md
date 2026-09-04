# Production Integration Layer — Phase 4.5

## Collector System

Modular collector interface (`collectors/base.py`) unifies HAProxy,
Docker, Linux auth, and service log sources. All emit normalized
`SecurityEvent` objects. Collectors are disabled by default and
require explicit opt-in (`DOCKER_COLLECTOR_ENABLED`, `AUTH_COLLECTOR_ENABLED`,
`SERVICE_LOG_COLLECTOR_ENABLED`). No automatic action from a single
collector signal; detection and policy remain the authoritative
enforcement boundary.

## Docker Integration

- Read-only Docker events (`docker events`, `docker inspect`) only.
- No container mutation; socket access controlled via compose overrides,
  not exposed to external networks.
- Bounded event history and truncated metadata.
- Normalized events feed existing engines; no service-specific hardcodes.

## Service Monitoring

Dashboard extended with services and system overview: container status,
service health, warnings, last events, calculated risk. Data comes from
live API endpoints, not demo/fake data.

## Auth Monitoring

Configurable parsers (`AuthParser`) for Vaultwarden, Nextcloud, Gitea,
and generic Linux auth.log / journald. Rules are configurable data,
not embedded service logic. Brute-force detection uses existing
threshold/window rules.
