"""Docker event collector — Phase 4.5. Real read-only event processing."""
import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from core.models import SecurityEvent, Severity
from core.normalizer import EventNormalizer

log = logging.getLogger(__name__)


class DockerEventsClient:
    """Read-only Docker Events API client intended for a restricted socket proxy."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.since = int(time.time())
        self.container_state: dict[str, tuple[str, str]] = {}

    async def read_events(self, timeout: float) -> list[dict]:
        until = int(time.time() + timeout)
        params = {
            "since": self.since,
            "until": until,
            "filters": json.dumps(
                {
                    "type": ["container", "image"],
                    "event": ["create", "die", "restart", "start", "update", "pull", "tag"],
                }
            ),
        }
        async with httpx.AsyncClient(base_url=self.base_url, timeout=timeout + 2) as client:
            response = await client.get("/events", params=params)
            response.raise_for_status()
            events = [json.loads(line) for line in response.text.splitlines() if line.strip()]
            for event in events:
                if event.get("Type") != "container" or event.get("Action") not in {
                    "create",
                    "start",
                    "update",
                }:
                    continue
                container_id = event.get("Actor", {}).get("ID")
                if not container_id:
                    continue
                inspect = await client.get(f"/containers/{container_id}/json")
                if inspect.is_success:
                    self._enrich(event, inspect.json())
        self.since = until
        return events

    def _enrich(self, event: dict, inspect: dict) -> None:
        container_id = event["Actor"]["ID"]
        image = str(inspect.get("Image") or "")
        ports = json.dumps(inspect.get("NetworkSettings", {}).get("Ports", {}), sort_keys=True)
        previous = self.container_state.get(container_id)
        self.container_state[container_id] = (image, ports)
        attributes = event["Actor"].setdefault("Attributes", {})
        attributes["privileged"] = bool(inspect.get("HostConfig", {}).get("Privileged"))
        if attributes["privileged"]:
            event["event_type"] = "docker_privileged"
        elif previous and previous[0] != image:
            event["event_type"] = "docker_image_change"
        elif previous and previous[1] != ports:
            event["event_type"] = "docker_port_change"


class DockerEventCollector:
    """Modular Docker collector (read-only, opt-in, bounded, injectable stream)."""

    def __init__(
        self, enabled: bool = False, stream_client: Any = None, api_url: str = ""
    ):
        self.enabled = enabled
        self.stream_client = stream_client or (DockerEventsClient(api_url) if api_url else None)
        self.normalizer = EventNormalizer()

    async def collect(self, timeout: float = 30.0) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        if not self.enabled:
            return events
        # Read-only event retrieval with bounded timeout.
        # Real production: connect to docker events API (filtered, time-bound).
        raw_events = await self._stream_events(timeout)
        for raw in raw_events:
            event = self._normalize(raw)
            if event:
                events.append(event)
        return events[:100]  # bounded

    async def _stream_events(self, timeout: float) -> list[dict]:
        # Injectable stream for testability; production plugs docker SDK events.
        if self.stream_client is not None:
            return await self.stream_client.read_events(timeout=timeout)
        raise RuntimeError("Docker collector enabled without DOCKER_API_URL")

    def _normalize(self, raw: dict) -> SecurityEvent | None:
        attributes = raw.get("Actor", {}).get("Attributes", {}) or raw.get("attributes", {})
        action = str(raw.get("Action") or raw.get("action") or "unknown").lower()
        event_type = raw.get("event_type") or {
            "create": "docker_create_unknown",
            "restart": "docker_restart",
            "die": "docker_crash",
            "pull": "docker_image_change",
            "tag": "docker_image_change",
        }.get(action, f"docker_{action}")
        # Configurable mapping; no service-specific hardcodes beyond event types.
        severity_map = {
            "docker_restart": Severity.MEDIUM,
            "docker_crash": Severity.HIGH,
            "docker_create_unknown": Severity.MEDIUM,
            "docker_image_change": Severity.LOW,
            "docker_port_change": Severity.LOW,
            "docker_privileged": Severity.HIGH,
        }
        return self.normalizer.normalize(
            {
                "source": "docker",
                "ip": raw.get("container_ip", "unknown"),
                "service": raw.get("container_name") or attributes.get("name")
                or raw.get("image") or attributes.get("image") or "docker",
                "event_type": event_type,
                "path": raw.get("path"),
                "method": raw.get("method"),
                "user_agent": None,
                "severity": str(severity_map.get(event_type, Severity.INFO)).lower(),
                "metadata": {
                    "action": action,
                    "actor_id": raw.get("Actor", {}).get("ID")
                    or raw.get("actor", {}).get("id"),
                    "scope": raw.get("scope") or raw.get("scope", "local"),
                    "time": raw.get("time"),
                    "image": raw.get("image") or attributes.get("image"),
                    "privileged": attributes.get("privileged"),
                    # Sensitive fields explicitly excluded: no passwords, keys, tokens.
                },
            },
            source="docker",
        )

    async def run(self, emit: Callable[[SecurityEvent], Awaitable[None]]) -> None:
        if not self.enabled:
            return
        while True:
            try:
                events = await self.collect(timeout=30.0)
                for event in events:
                    await emit(event)
            except Exception as exc:
                log.warning("Docker collection failed: %s", exc)
            await asyncio.sleep(5.0)
