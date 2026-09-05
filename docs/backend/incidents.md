# Incident management

Security events with a high or critical assessment are recorded as incidents.
An incident keeps its source, affected component, current risk score, factors,
recommendations and an append-only timeline. Statuses are `neu`, `analysiert`,
`bestätigt` and `geschlossen`; status updates are available through the API and
do not invoke policy or response actions.

The dashboard is available at `/incidents`. MCP exposes
`security.get_incidents`, `security.explain_incident` and
`security.get_incident_history`. This layer prepares the data needed by future
challenge, HAProxy policy and response automation phases.
