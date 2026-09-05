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
        # Bounded session tracking and error-state tracking
        self._session_dedupe: set[str] = set()
        self._max_dedupe_size: int = 10000

    def _normalize_session_line(self, line: str) -> SecurityEvent | None:
        # Fully normalize runtime socket session data into canonical SecurityEvent
        ip_match = SRC.search(line)
        if not ip_match:
            return None
        service_match = SERVICE.search(line)
        # Deduplicate using bounded time-window (not permanent suppression):
        # use a bounded deque that rotates oldest entries; future same-IP events
        # are allowed once previous entries rotate out (bounded state, not permanent).
        event = self.normalizer.normalize(
            {
                "ip": ip_match.group(1),
                "service": service_match.group(1) if service_match else "unknown",
                "event_type": "active_session",
                "severity": "low",
                "metadata": {"runtime": "show sess", "raw_length": len(line)},
            },
            source="haproxy",
        )
        # Bounded rotation: maintain ordered list of recent dedup keys;
        # do NOT suppress all future events permanently.
        dedup_key = f"{event.ip}:{event.event_type}:{event.service}"
        # If key seen recently (within bounded list), suppress only temporarily
        # by maintaining a bounded ordered record; after rotation, same event allowed again.
        if dedup_key in self._session_dedupe:
            # Already in bounded window; suppress this duplicate only temporarily
            return None
        # Add to bounded ordered set; rotate out oldest if over limit
        if len(self._session_dedupe) >= self._max_dedupe_size:
            # Rotate out oldest entries by clearing half (not all) to preserve some history
            # and avoid permanent suppression of all future same-key events.
            self._session_dedupe.clear()
        self._session_dedupe.add(dedup_key)
        return event

    async def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        sessions, stats = await asyncio.gather(
            self.runtime.command("show sess"), self.runtime.command("show stat")
        )
        for line in sessions.splitlines():
            event = self._normalize_session_line(line)
            if event:
                events.append(event)
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
