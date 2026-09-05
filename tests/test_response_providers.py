import pytest

from actions.anubis import AnubisChallengeAdapter
from actions.haproxy import HAProxyActionAdapter


class Runtime:
    def __init__(self):
        self.commands = []

    async def command(self, command):
        self.commands.append(command)
        return "ok"


@pytest.mark.asyncio
async def test_haproxy_expiry_and_rollback():
    runtime = Runtime()
    adapter = HAProxyActionAdapter(runtime, "/acl", enabled=True)
    result = await adapter.block("192.0.2.1", "2030-01-01T00:30:00+00:00")
    assert result.applied and "expires_at" in result.detail
    await adapter.unblock("192.0.2.1")
    assert runtime.commands == ["add acl /acl 192.0.2.1", "del acl /acl 192.0.2.1"]


@pytest.mark.asyncio
async def test_anubis_failure_is_reported():
    adapter = AnubisChallengeAdapter("http://127.0.0.1:1")
    result = await adapter.challenge("192.0.2.2")
    assert not result.applied and "failed" in result.detail
