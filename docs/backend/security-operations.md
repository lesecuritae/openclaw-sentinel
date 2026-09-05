# Security operations

The operations layer defines `administrator`, `analyst` and `viewer` roles.
Requests may provide `X-Sentinel-Role`; administrator is the compatibility
default for existing API-key deployments. Configuration writes and exports
require administrator, while analyst access covers incidents, policies,
actions, reports and audit data. Viewer access is read-only dashboard access.

Configuration is schema-validated before atomic import, exportable, and
backup-able. Audit entries record the user, action, timestamp and before/after
states. Daily reports combine event counts, incidents, risk profiles and action
history. MCP exposes `security.get_audit_log`, `security.generate_report` and
`security.export_config`.
