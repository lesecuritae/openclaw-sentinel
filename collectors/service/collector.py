"""Service log collector — Phase 4.5 (bounded incremental tailing, clean cancellation)."""
import asyncio
import logging
from pathlib import Path

from collectors.auth.adapter import AuthParser
from core.models import SecurityEvent

log = logging.getLogger(__name__)


class BoundedLogReader:
    def __init__(self, path: Path | None = None, max_lines: int = 1000):
        self.path = path
        self.max_lines = max_lines
        self._offset = 0

    async def tail_incremental(self, poll_interval: float = 5.0) -> list[str]:
        lines: list[str] = []
        if self.path is None or not self.path.exists():
            return lines
        try:
            with self.path.open("r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._offset)
                new_lines = f.read().splitlines()
                self._offset = f.tell()
                lines.extend(new_lines[: self.max_lines])
        except Exception as exc:
            log.warning("Failed to read %s: %s", self.path, exc)
        return lines[: self.max_lines]


class ServiceLogCollector:
    """Configurable service log collector (read-only, opt-in, bounded incremental tailing)."""

    def __init__(
        self,
        enabled: bool = False,
        log_path: str | None = None,
        max_lines: int = 1000,
        parser: AuthParser | None = None,
    ):
        self.enabled = enabled
        self.reader = BoundedLogReader(Path(log_path) if log_path else None, max_lines=max_lines)
        self.parser = parser or AuthParser()
        self._cancelled = False

    async def collect(self, poll_interval: float = 5.0) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        if not self.enabled:
            return events
        lines = await self.reader.tail_incremental(poll_interval)
        for line in lines:
            event = self._parse_line(line)
            if event:
                events.append(event)
        return events[: self.reader.max_lines]

    def _parse_line(self, line: str) -> SecurityEvent | None:
        return self.parser.parse_line(line, source="service_log")

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
