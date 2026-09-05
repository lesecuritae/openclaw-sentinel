from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from pathlib import Path

from collectors.docker.collector import DockerEventsClient
from engine.integrity import IntegrityEngine


class IntegrityCollector:
    """Periodic, read-only snapshots for local supply-chain integrity."""

    def __init__(
        self,
        api_url: str = "",
        file_paths: list[str] | None = None,
        package_report: str = "",
        interval: float = 60.0,
    ):
        self.api_url, self.file_paths = api_url, file_paths or []
        self.package_report, self.interval = package_report, interval
        self.engine = IntegrityEngine()
        self.previous_containers: dict = {}
        self.previous_files: dict[str, str] = {}

    async def snapshot(self, emit: Callable[[object], Awaitable[object]]) -> None:
        if self.api_url:
            try:
                rows = await DockerEventsClient(self.api_url).inventory()
                current = {}
                for row in rows:
                    name = str((row.get("Names") or [row.get("Id", "unknown")])[0]).lstrip("/")
                    current[name] = {
                        "image": row.get("Image"),
                        "digest": row.get("ImageID"),
                        "ports": row.get("Ports", []),
                    }
                for finding in self.engine.docker_changes(self.previous_containers, current):
                    await emit(finding)
                self.previous_containers = current
            except Exception:
                pass
        if self.file_paths:
            for finding in self.engine.file_changes(self.previous_files, self.file_paths):
                await emit(finding)
            self.previous_files = {
                path: digest for path in self.file_paths if (digest := self.engine.hash_file(path))
            }
        if self.package_report and Path(self.package_report).is_file():
            try:
                for finding in self.engine.package_findings(Path(self.package_report).read_text()):
                    await emit(finding)
            except (OSError, ValueError, json.JSONDecodeError):
                pass

    async def run(self, emit: Callable[[object], Awaitable[object]]) -> None:
        while True:
            await self.snapshot(emit)
            await asyncio.sleep(self.interval)
