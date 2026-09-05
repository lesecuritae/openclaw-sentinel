"""Bounded binary log reader: binary readline(size_limit) + byte offsets."""
import asyncio
import logging
import os
import stat
from pathlib import Path

log = logging.getLogger(__name__)


class BoundedLogReader:
    """Reads up to max_lines / max_bytes per call; leaves bytes for next call.
    Partial lines preserved until newline; oversized lines discarded via a
    bounded discard state. Inode/truncation resets partial state. No dedup."""

    def __init__(
        self,
        paths: list[Path],
        max_lines: int = 1000,
        max_bytes: int = 512 * 1024,
        size_limit: int = 8192,
    ):
        if min(max_lines, max_bytes, size_limit) <= 0:
            raise ValueError("reader limits must be positive")
        self.paths = list(dict.fromkeys(paths))
        self._next_path = 0
        self.discarded_lines = 0
        self.max_lines = max_lines
        self.max_bytes = max_bytes
        self.size_limit = size_limit
        self._state: dict[str, dict] = {}
        for p in self.paths:
            key = self._key_for(p)
            self._state.setdefault(key, {
                "inode": None,
                "offset": 0,
                "partial_bytes": b"",
                "discard_state": None,
            })

    def _key_for(self, p: Path) -> str:
        # The configured path is stable across symlink replacement / rotation.
        return str(p.absolute())

    def read_incremental(self, max_lines: int | None = None) -> list[str]:
        results: list[str] = []
        line_limit = self.max_lines if max_lines is None else min(max_lines, self.max_lines)
        if line_limit <= 0:
            return results
        bytes_left = self.max_bytes
        count = len(self.paths)
        start = self._next_path
        for index in range(count):
            if len(results) >= line_limit or bytes_left <= 0:
                break
            path_index = (start + index) % count
            self._next_path = (path_index + 1) % count
            p = self.paths[path_index]
            state = self._state[self._key_for(p)]
            try:
                # A configured FIFO/device must not block the collector event loop.
                fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    identity = (info.st_dev, info.st_ino)
                    if state["inode"] != identity or info.st_size < state["offset"]:
                        state.update(inode=identity, offset=0, partial_bytes=b"",
                                     discard_state=None)
                    stream.seek(state["offset"])
                    while len(results) < line_limit and bytes_left > 0:
                        chunk = stream.readline(min(self.size_limit, bytes_left))
                        if not chunk:
                            break
                        bytes_left -= len(chunk)
                        state["offset"] = stream.tell()
                        complete = chunk.endswith(b"\n")
                        if state["discard_state"]:
                            if complete:
                                state["discard_state"] = None
                            continue
                        combined = state["partial_bytes"] + chunk
                        if len(combined) > self.size_limit:
                            self.discarded_lines += 1
                            state["partial_bytes"] = b""
                            state["discard_state"] = None if complete else "discarding"
                            continue
                        if complete:
                            results.append(combined[:-1].removesuffix(b"\r").decode(
                                "utf-8", errors="replace"
                            ))
                            state["partial_bytes"] = b""
                        else:
                            state["partial_bytes"] = combined
            except OSError as exc:
                log.warning("Cannot read configured log %s: %s", p, type(exc).__name__)
        return results

    async def read_lines(self, max_lines: int = 500) -> list[str]:
        return await asyncio.to_thread(self.read_incremental, max_lines)
