"""Service log collector — Phase 4.5 (bounded incremental tailing, clean cancellation)."""

import asyncio
import logging
from pathlib import Path

from collectors.service.adapter import SERVICE_ADAPTERS, ServiceAdapterBase
from core.bounded_reader import BoundedLogReader
from core.models import SecurityEvent

log = logging.getLogger(__name__)


class ServiceLogCollector:
    """Configurable service log collector using adapter framework (no service if/else in core)."""

    def __init__(
        self,
        enabled: bool = False,
        log_path: str | None = None,
        max_lines: int = 1000,
        service_adapter_key: str = "vaultwarden",
    ):
        self.enabled = enabled
        self.reader = BoundedLogReader(
            [Path(log_path)] if log_path else [Path("/dev/null")], max_lines=max_lines
        )
        # Use adapter framework; no service-specific logic embedded in core
        adapter_class = SERVICE_ADAPTERS.get(service_adapter_key)
        self.adapter: ServiceAdapterBase | None = adapter_class() if adapter_class else None
        self.service_key = service_adapter_key
        self._cancelled = False

    async def collect(self, poll_interval: float = 5.0) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        if not self.enabled:
            return events
        lines = await self.reader.read_lines(self.reader.max_lines)
        for line in lines:
            event = self._parse_line(line)
            if event:
                events.append(event)
        return events[: self.reader.max_lines]

    def _parse_line(self, line: str) -> SecurityEvent | None:
        if self.adapter is not None:
            # Delegate to configured adapter; no service-specific if/else in core
            return self.adapter.parse_line(line, source="service_log")
        return None

    async def run(self, emit) -> None:
        if not self.enabled:
            return
        self._cancelled = False
        try:
            while not self._cancelled:
                events = await self.collect(poll_interval=5.0)
                for event in events:
                    await emit(event)
                await asyncio.sleep(5.0)
        except asyncio.CancelledError:
            log.info("Service log collector cancelled cleanly.")
            self._cancelled = True
            raise
        except Exception as exc:
            log.warning("Service log collection error: %s", exc)
