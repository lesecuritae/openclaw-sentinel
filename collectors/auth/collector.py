"""Linux auth / journald collector — Phase 4.5 (bounded incremental tailing)."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from collectors.auth.adapter import EXPECTED_COUNTRIES, EXPECTED_LOGIN_HOURS, AuthParser
from core.bounded_reader import BoundedLogReader
from core.models import SecurityEvent

log = logging.getLogger(__name__)


class JournaldReader:
    """Actual journald read-only subprocess reader using create_subprocess_exec with
    journalctl JSON output --after-cursor --no-pager, timeout/cancel support."""

    def __init__(
        self,
        cursor: str | None = None,
        max_lines: int = 500,
        timeout: float = 30.0,
    ):
        self.cursor = cursor
        self.max_lines = max_lines
        self.timeout = timeout
        self._cancelled = False

    async def read_lines(self, max_lines: int = 500) -> list[str]:
        if self._cancelled:
            return []
        limit = min(max_lines, self.max_lines)
        cmd = ["journalctl", "--output=json", "--no-pager", "-n", str(limit)]
        if self.cursor:
            cmd[3:3] = ["--after-cursor", self.cursor]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if proc.returncode != 0:
                log.warning(
                    "Journalctl failed (return %s): %s",
                    proc.returncode,
                    stderr.decode("utf-8", errors="replace"),
                )
                return []
            lines: list[str] = []
            for raw in stdout.decode("utf-8", errors="replace").splitlines()[:limit]:
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                if entry.get("_CURSOR"):
                    self.cursor = str(entry["_CURSOR"])
                message = entry.get("MESSAGE")
                if isinstance(message, str):
                    lines.append(message)
            return lines
        except TimeoutError:
            log.warning("Journalctl read timed out after %ss", self.timeout)
            return []
        except Exception as exc:
            log.warning("Journalctl subprocess error: %s", exc)
            return []

    def cancel(self) -> None:
        self._cancelled = True


class LinuxAuthCollector:
    """Configurable auth collector using shared BoundedLogReader (read-only, bounded,
    clean cancel, transient errors handled without permanent kill)."""

    def __init__(
        self,
        enabled: bool = False,
        log_paths: list[str] | None = None,
        max_lines: int = 500,
        parser: AuthParser | None = None,
        reader: Any = None,
    ):
        self.enabled = enabled
        self.log_paths = log_paths or ["/var/log/auth.log"]
        # Use the shared core bounded reader for file-based incremental reading
        paths = [Path(p) for p in (log_paths or ["/var/log/auth.log"])]
        self.reader = reader or BoundedLogReader(paths, max_lines=max_lines)
        self.parser = parser or AuthParser()
        self._cancelled = False
        # Injectable read-only interface for journald or other bounded sources
        self._injected_reader: Any = None
        self._journal_reader: JournaldReader | None = None

    def inject_reader(self, reader: Any) -> None:
        """Inject a read-only bounded reader interface (e.g., journald wrapper)."""
        self._injected_reader = reader
        if isinstance(reader, JournaldReader):
            self._journal_reader = reader

    def inject_journald_reader(
        self,
        cursor: str | None = None,
        max_lines: int = 500,
        timeout: float = 30.0,
    ) -> None:
        self._journal_reader = JournaldReader(cursor=cursor, max_lines=max_lines, timeout=timeout)
        self._injected_reader = self._journal_reader

    async def collect(self, poll_interval: float = 5.0) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        if not self.enabled:
            return events
        try:
            if self._journal_reader is not None:
                lines = await self._journal_reader.read_lines(self.reader.max_lines)
            elif self._injected_reader is not None:
                lines = await self._injected_reader.read_lines(self.reader.max_lines)
            else:
                lines = await self.reader.read_lines(self.reader.max_lines)
            for line in lines:
                event = self._parse_line(line)
                if event:
                    events.append(event)
        except Exception as exc:
            # Transient errors handled without permanently killing collector
            log.warning("Auth collection transient error (collector continues): %s", exc)
        return events[: self.reader.max_lines]

    def _parse_line(self, line: str) -> SecurityEvent | None:
        event = self.parser.parse_line(line, source="linux_auth")
        if event:
            # Use configured UTC hours and structured country only.
            event.metadata.setdefault("expected_hours", EXPECTED_LOGIN_HOURS)
            event.metadata.setdefault("expected_countries", EXPECTED_COUNTRIES)
        return event

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
            if self._journal_reader is not None:
                self._journal_reader.cancel()
            raise
        except Exception as exc:
            log.warning("Linux auth collection error (collector continues): %s", exc)
