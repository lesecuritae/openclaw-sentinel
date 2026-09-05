# Response safety

Production runs with `RESPONSE_DRY_RUN=true` by default. Policy tests and action
previews return the matching deterministic rule, reason, bounded duration and
intended action without invoking an adapter. The policy tester is available in
the Policies dashboard, `POST /api/v1/policies/test`, and MCP preview tools.

Trusted IPs, networks and devices are recorded with a reason and optional
expiry. A matching trusted entity suppresses response actions while preserving
the event and incident evidence. Response audit rows include the rule, result
and expiry timestamp; block, challenge and rate-limit actions are bounded to
30 minutes and require re-evaluation after expiry.
