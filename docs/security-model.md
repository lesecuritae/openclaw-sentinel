# Security model

Sentinel is not a firewall. It is a security intelligence layer connecting observations, risk
analysis, policy and independently configured enforcement systems.

- Automatic actions are disabled by default and require explicit provider configuration.
- Only the policy engine selects `ALLOW`, `CHALLENGE`, or `BLOCK`.
- Unknown or invalid source addresses cannot trigger an IP action.
- HAProxy changes use a narrowly configured runtime ACL and require no restart.
- Challenge handling is delegated to an external provider such as Anubis; Sentinel builds no
  CAPTCHA.
- LLM output is advisory and never enters the action execution path.
- API authentication is optional for local development but required before network exposure.
- Inputs and LLM context must be considered hostile. Secrets belong in environment variables or
  an external secret manager and are never returned by API/MCP tools.

See [SECURITY.md](../SECURITY.md) for private vulnerability reporting.
