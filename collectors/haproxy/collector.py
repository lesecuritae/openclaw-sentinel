import asyncio
import csv
import io
import logging
import re
from collections.abc import Awaitable, Callable

from collectors.haproxy.runtime import HAProxyRuntimeClient
from core.models import SecurityEvent
from core.normalizer import EventNormalizer

log = logging.getLogger(__name__)
SRC = re.compile(r"\bsrc=([^\s:]+)(?::\d+)?")
SERVICE = re.compile(r"\b(?:fe|frontend)=([^\s]+)")


class HAProxyCollector:
    def __init__(self, runtime: HAProxyRuntimeClient, interval: float = 5.0):
        self.runtime, self.interval = runtime, interval
        self.normalizer = EventNormalizer()
        self._previous: dict[tuple[str, str], dict[str, int]] = {}

    async def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        sessions, stats = await asyncio.gather(
            self.runtime.command("show sess"), self.runtime.command("show stat")
        )
        for line in sessions.splitlines():
            ip = SRC.search(line)
            if ip:
                service = SERVICE.search(line)
                events.append(
                    self.normalizer.normalize(
                        {
                            "ip": ip.group(1),
                            "service": service.group(1) if service else "unknown",
                            "event_type": "active_session",
                            "metadata": {"runtime": "show sess"},
                        },
                        source="haproxy",
                    )
                )
        rows = list(csv.DictReader(io.StringIO(stats.lstrip("# "))))
        counters = ("hrsp_4xx", "hrsp_5xx", "ereq", "econ", "eresp")
        for row in rows:
            key = (row.get("pxname", "unknown"), row.get("svname", "unknown"))
            current = {name: int(row.get(name) or 0) for name in counters}
            previous = self._previous.get(key, current)
            for name in counters:
                delta = max(0, current[name] - previous[name])
                if delta:
                    events.append(
                        self.normalizer.normalize(
                            {
                                "ip": "unknown",
                                "service": key[0],
                                "event_type": "proxy_error",
                                "severity": "medium",
                                "metadata": {
                                    "counter": name,
                                    "count": delta,
                                    "backend": key[1],
                                    "status_family": name.removeprefix("hrsp_"),
                                },
                            },
                            source="haproxy",
                        )
                    )
            self._previous[key] = current
        return events

    async def run(self, emit: Callable[[SecurityEvent], Awaitable[None]]) -> None:
        while True:
            try:
                for event in await self.collect():
                    await emit(event)
            except (OSError, TimeoutError, ValueError) as exc:
                log.warning("HAProxy collection failed: %s", exc)
            await asyncio.sleep(self.interval)
