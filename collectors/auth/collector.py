"""Linux auth / journald collector — Phase 4.5 (bounded incremental tailing)."""
import asyncio
import logging
from pathlib import Path

from collectors.auth.adapter import AuthParser
from core.models import SecurityEvent

log = logging.getLogger(__name__)


class BoundedLogReader:
    """Injectable bounded log reader for testability."""

    def __init__(self, paths: list[Path], max_lines: int = 1000):
        self.paths = paths
        self.max_lines = max_lines
        self._offsets: dict[str, int] = {str(p): 0 for p in paths}

    async def tail_incremental(self, poll_interval: float = 5.0) -> list[str]:
        lines: list[str] = []
        for p in self.paths:
            if not p.exists():
                continue
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as f:
                    f.seek(self._offsets[str(p)])
                    new_lines = f.read().splitlines()
                    self._offsets[str(p)] = f.tell()
                    lines.extend(new_lines[: self.max_lines])
            except Exception as exc:
                log.warning("Failed to read %s: %s", p, exc)
        return lines[: self.max_lines]


class LinuxAuthCollector:
    """Configurable auth log collector (read-only, opt-in, bounded tailing, clean cancel)."""

    def __init__(
        self, enabled: bool = False,
        log_paths: list[str] | None = None,
        max_lines: int = 500,
        parser: AuthParser | None = None,
    ):
        self.enabled = enabled
        self.log_paths = log_paths or ["/var/log/auth.log"]
        self.reader = BoundedLogReader(
            [Path(p) for p in (log_paths or ["/var/log/auth.log"])], max_lines=max_lines
        )
        self.parser = parser or AuthParser()
        self._cancelled = False

    async def collect(self, poll_interval: float = 5.0) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        if not self.enabled:
            return events
        lines = await self.reader.tail_incremental(poll_interval)
        for line in lines:
            # Configurable parsing delegated to adapter; bounded line processing.
            event = self._parse_line(line)
            if event:
                events.append(event)
        return events[: self.reader.max_lines]

    def _parse_line(self, line: str) -> SecurityEvent | None:
        return self.parser.parse_line(line, source="linux_auth")

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
            log.info("Linux auth collector cancelled cleanly.")
            self._cancelled = True
            raise
        except Exception as exc:
            log.warning("Linux auth collection error: %s", exc)
