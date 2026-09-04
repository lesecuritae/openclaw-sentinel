# Contributing

Thank you for helping improve OpenClaw Sentinel. Discuss substantial features in an issue before
implementation. Keep changes focused, provider-neutral, configurable, and independently tested.

1. Fork the repository and create a topic branch.
2. Install development dependencies with `pip install -e '.[test]'`.
3. Run `ruff check .`, `pytest`, and `docker compose config`.
4. Add tests and documentation for behavioral or configuration changes.
5. Open a pull request using the template and describe security implications.

Never commit secrets, private infrastructure details, personal data, captured production events,
or proprietary threat feeds. Security vulnerabilities must be reported privately according to
[SECURITY.md](SECURITY.md). Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

By submitting a contribution, you agree that it is licensed under Apache License 2.0.
