import pytest

from actions.haproxy import HAProxyActionAdapter
from collectors.haproxy.collector import HAProxyCollector


class Runtime:
    async def command(self, command):
        if command == "show sess":
            return "0x1: proto=tcp src=1.2.3.4:12345 fe=public be=web\n"
        return (
            "# pxname,svname,scur,stot,hrsp_4xx,hrsp_5xx,ereq,econ,eresp\n"
            "web,BACKEND,1,2,0,0,0,0,0\n"
        )


@pytest.mark.asyncio
async def test_collector_parses_session():
    events = await HAProxyCollector(Runtime()).collect()
    assert events[0].ip == "1.2.3.4"
    assert events[0].service == "public"


@pytest.mark.asyncio
async def test_action_rejects_command_injection():
    with pytest.raises(ValueError):
        await HAProxyActionAdapter(Runtime(), "/acl", True).block("1.2.3.4\nshow info")
