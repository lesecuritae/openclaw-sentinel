# Integrity and supply-chain intelligence

Sentinel records read-only integrity findings separately from IP risk profiles. The
`IntegrityEngine` compares Docker container snapshots (including image IDs/digests,
ports and privilege), hashes configured important files with SHA-256, and parses
JSON vulnerability reports such as `pip-audit` output. Findings are emitted as
`integrity` events through normalization, detection and risk calculation so they
are visible in the event stream, while the service permanently uses the
infrastructure identity (`unknown`) and never creates a block or challenge.

Enable the periodic collector with `INTEGRITY_COLLECTOR_ENABLED=true`. Configure
`INTEGRITY_FILE_PATHS` as a comma-separated list and optionally set
`INTEGRITY_PACKAGE_REPORT` to a local JSON report. Docker inventory uses the same
read-only Docker API endpoint as the Docker collector.

The API endpoint `GET /api/v1/integrity` and MCP tools
`security.get_integrity` / `security.get_integrity_summary` expose findings and
summary data. The System Integrity dashboard is available at `/integrity`.
