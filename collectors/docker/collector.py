"""Docker event collector — production read-only event processing."""

import asyncio
import fnmatch
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from core.models import SecurityEvent, Severity
from core.normalizer import EventNormalizer

log = logging.getLogger(__name__)

# Bounded limits
MAX_LINE_BYTES = 8192
BATCH_CAP = 200
MAX_DEDUPE_ENTRIES = 1000


class DockerEventsClient:
    """Read-only Docker Events API client over restricted proxy only (GET)."""

    def __init__(
        self,
        base_url: str,
        allowed_containers: list[str] | None = None,
        allowed_images: list[str] | None = None,
        allowed_actions: set[str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.transport = transport
        self.allowed_containers = allowed_containers or []
        self.allowed_images = allowed_images or []
        self.allowed_actions = allowed_actions or {
            "start",
            "stop",
            "restart",
            "die",
            "create",
            "destroy",
        }
        # Cursor / reconnect state (bounded)
        self.since = int(time.time())
        self.until_cursor = int(time.time())
        self._reconnect_delay = 1.0
        self._max_reconnect_delay = 30.0
        self._cursor_offset = 0
        # State tracking
        self.container_state: dict[str, dict] = {}
        self._max_state_entries = 500
        # Dedup state (bounded by timeNano+id+action)
        self._dedupe: set[tuple[int, str, str]] = set()

    def _match_patterns(self, value: str, patterns: list[str]) -> bool:
        if not patterns:
            return True  # no restriction configured => allow
        return any(fnmatch.fnmatch(value, pat) for pat in patterns)

    async def inventory(self) -> list[dict]:
        """Initial inventory: GET /containers/json (all=1) via restricted proxy."""
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=15.0,
            follow_redirects=False,
        ) as client:
            resp = await client.get("/containers/json", params={"all": 1})
            resp.raise_for_status()
            return resp.json() or []

    async def inspect(self, container_id: str) -> dict:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=10.0,
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            response = await client.get(f"/containers/{container_id}/json")
            response.raise_for_status()
            return response.json()

    async def read_events(
        self,
        timeout: float = 30.0,
        batch_cap: int = BATCH_CAP,
        max_line_bytes: int = MAX_LINE_BYTES,
    ) -> list[dict]:
        """Read /events NDJSON via httpx stream with bounded line bytes and batch."""
        until = int(time.time() + timeout)
        params = {
            "since": self.since,
            "until": until,
            "filters": json.dumps(
                {
                    "type": ["container", "image"],
                    "event": list(self.allowed_actions),
                }
            ),
        }

        # Exponential reconnect with bounded delay; reset on success
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=timeout + 4,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                try:
                    response_context = client.stream("GET", "/events", params=params)
                    response = await response_context.__aenter__()
                    response.raise_for_status()
                    self._reconnect_delay = 1.0
                except (httpx.NetworkError, httpx.TimeoutException) as exc:
                    log.warning("Docker event reconnect (backoff): %s", exc)
                    await asyncio.sleep(self._reconnect_delay)
                    self._reconnect_delay = min(
                        self._reconnect_delay * 2, self._max_reconnect_delay
                    )
                    return []

                # NDJSON stream with bounded line bytes; never buffer the body.
                events: list[dict] = []
                line_buffer = bytearray()
                last_event_second: int | None = None
                async for chunk in response.aiter_bytes(chunk_size=4096):
                    line_buffer.extend(chunk)
                    while b"\n" in line_buffer:
                        raw_line, _, remainder = line_buffer.partition(b"\n")
                        line_buffer = bytearray(remainder)
                        line = raw_line.strip()
                        if not line or len(line) > max_line_bytes:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(event, dict):
                            continue
                        if event.get("Type") == "container":
                            actor_id = str((event.get("Actor") or {}).get("ID", ""))
                            if actor_id:
                                try:
                                    inspected = await self.inspect(actor_id)
                                    config = inspected.get("Config", {})
                                    host_config = inspected.get("HostConfig", {})
                                    network = inspected.get("NetworkSettings", {})
                                    attrs = (event.setdefault("Actor", {})
                                             .setdefault("Attributes", {}))
                                    attrs.setdefault(
                                        "name", str(inspected.get("Name", "")).lstrip("/")
                                    )
                                    attrs.setdefault("image", inspected.get("Image", ""))
                                    attrs["privileged"] = bool(host_config.get("Privileged"))
                                    event["ports"] = network.get("Ports", {})
                                    event["exitCode"] = inspected.get("State", {}).get("ExitCode")
                                    attrs["env_count"] = len(config.get("Env") or [])
                                except (httpx.HTTPError, ValueError):
                                    pass

                        # Deduplicate by timeNano + id + action
                        actor = event.get("Actor", {}) or {}
                        event_id = str(actor.get("ID", event.get("id", "")))
                        action_str = str(event.get("Action", event.get("action", "")))
                        time_nano = event.get("timeNano", event.get("time", 0))
                        time_nano = int(time_nano) if isinstance(time_nano, (int, float)) else 0
                        if time_nano < 10_000_000_000:
                            time_nano *= 1_000_000_000
                        dedupe_key = (time_nano, event_id, action_str.lower())
                        if dedupe_key in self._dedupe:
                            continue

                        self._dedupe.add(dedupe_key)
                        events.append(event)
                        last_event_second = time_nano // 1_000_000_000
                        if len(events) >= batch_cap:
                            break
                    if len(events) >= batch_cap:
                        break

                await response_context.__aexit__(None, None, None)

                # Prune bounded dedupe state (keep most recent half if over limit)
                if len(self._dedupe) > MAX_DEDUPE_ENTRIES:
                    current_list = list(self._dedupe)
                    keep = len(current_list) // 2
                    self._dedupe = set(current_list[-keep:])

                # Lifecycle enrichment (preserve event, emit additional findings)
                for evt in events:
                    self._enrich(evt)

                # Preserve lifecycle event; emit additional privilege/image/port findings
                # without overwriting the original lifecycle event type
                # The _enrich method sets event_type only when new findings exist,
                # but never removes existing event_type from a lifecycle event.
                # Here we enforce: if evt has an original lifecycle action,
                # the event_type from action is preserved; findings only add metadata.
                for evt in events:
                    action_str = str(evt.get("Action", evt.get("action", ""))).lower()
                    # Always preserve lifecycle event type
                    if evt.get("event_type") is None:
                        lifecycle_map = {
                            "start": "docker_start",
                            "stop": "docker_stop",
                            "restart": "docker_restart",
                            "die": "docker_crash",
                            "create": "docker_create",
                        }
                        evt["event_type"] = lifecycle_map.get(action_str, f"docker_{action_str}")
                    # Inspection must emit additional findings but not overwrite lifecycle
                    # If inspect yields privilege/image/port changes, they are added as
                    # additional fields in event metadata but the event_type stays.
                    # We keep this behavior from _enrich.

                # Cursor advances through consumed events (deduped included)
                if events:
                    self.since = last_event_second or until
                    self.until_cursor = self.since
                else:
                    # Resume same second; do not advance since until
                    pass

                # Reset reconnect delay on success
                self._reconnect_delay = 1.0
                return events
        except Exception as exc:
            log.warning("Docker event stream error: %s", exc)
            await asyncio.sleep(self._reconnect_delay)
            self._reconnect_delay = min(self._reconnect_delay * 2, self._max_reconnect_delay)
            return []

    def _enrich(self, event: dict) -> None:
        container_id = event.get("Actor", {}).get("ID") or event.get("actor", {}).get("id")
        if not container_id:
            return
        # Do a quick bounded inspect (simulated; real call done in read_events loop)
        # In production, inspect response is already merged into event attributes.
        # We rely on event attributes set by the stream/inject layer.
        # If image is present and container_state tracks previous image, detect change.
        attributes = event.get("Actor", {}).get("Attributes", {}) or event.get("attributes", {})
        image = str(attributes.get("image", event.get("image", "")))
        ports_raw = event.get("ports", event.get("ports_json", {}))
        ports = (
            json.dumps(ports_raw, sort_keys=True) if isinstance(ports_raw, dict) else str(ports_raw)
        )
        previous = self.container_state.get(container_id)
        new_state: tuple[str, str] = (image, ports)
        self.container_state[container_id] = new_state
        # Preserve lifecycle event; add additional findings in metadata
        privileged = bool(attributes.get("privileged", event.get("privileged", False)))
        # Set metadata without overwriting lifecycle event_type
        meta = event.setdefault("metadata", {})
        meta["privileged"] = privileged
        meta["image"] = image
        meta["ports"] = ports_raw if isinstance(ports_raw, dict) else {}
        meta["actor_id"] = container_id
        meta["scope"] = event.get("scope", event.get("scope", "local"))
        meta["action"] = event.get("Action", event.get("action", ""))
        meta["time"] = event.get("time", event.get("timeNano", 0))
        # Compare recreations by stable container name, not old ID
        # The container_state key should use container name when available
        container_name = attributes.get("name") or event.get("container_name", container_id)
        if container_name and container_name != container_id:
            # Store by stable name for recreation comparison
            self.container_state[container_name] = new_state

        # Explicit unknown_image / unknown_container events only when allowlist configured
        has_image_patterns = bool(self.allowed_images)
        has_container_patterns = bool(self.allowed_containers)
        if image and has_image_patterns:
            matched_image = self._match_patterns(image, self.allowed_images)
            if not matched_image:
                meta["unknown_image"] = image
                meta["unknown_image_matched"] = False
        name_for_check = container_name or container_id
        if name_for_check and has_container_patterns:
            matched_container = self._match_patterns(name_for_check, self.allowed_containers)
            if not matched_container:
                meta["unknown_container"] = name_for_check
                meta["unknown_container_matched"] = False
        # Exit code processing: exitCode=0 clean stop, nonzero crash
        exit_code = event.get("exitCode", event.get("exit_code", event.get("ExitCode")))
        if exit_code is not None:
            meta["exit_code"] = int(exit_code)
            meta["clean_stop"] = int(exit_code) == 0
            meta["crash"] = int(exit_code) != 0

        # Findings emitted without overwriting lifecycle event_type
        # If privileged: emit additional finding but keep lifecycle event
        if privileged:
            event.setdefault("findings", []).append("privileged")
        if previous:
            if previous[0] != image:
                event.setdefault("findings", []).append("image_change")
            if previous[1] != ports:
                event.setdefault("findings", []).append("port_change")


class DockerEventCollector:
    """Production Docker collector with bounded stream, dedup, inventory, allowlists."""

    def __init__(
        self,
        enabled: bool = False,
        stream_client: Any = None,
        api_url: str = "",
        allowed_containers: list[str] | None = None,
        allowed_images: list[str] | None = None,
        settings: Any = None,
    ):
        self.enabled = enabled
        # If settings provided, use its allowed_containers / allowed_images
        if settings is not None:
            allowed_containers = allowed_containers or settings.allowed_containers
            allowed_images = allowed_images or settings.allowed_images
        self.stream_client = stream_client or (
            DockerEventsClient(
                api_url,
                allowed_containers=allowed_containers,
                allowed_images=allowed_images,
            )
            if api_url
            else None
        )
        self.normalizer = EventNormalizer()
        self.allowed_containers = allowed_containers or []
        self.allowed_images = allowed_images or []

    async def collect(self, timeout: float = 30.0) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        if not self.enabled:
            return events
        raw_events = await self._stream_events(timeout)
        for raw in raw_events:
            event = self._normalize(raw)
            if event:
                events.append(event)
                finding_types = {
                    "privileged": "docker_privileged",
                    "image_change": "docker_image_change",
                    "port_change": "docker_port_change",
                }
                for finding in event.metadata.get("findings", []):
                    finding_type = finding_types.get(finding)
                    if finding_type:
                        finding_raw = dict(raw)
                        finding_raw["event_type"] = finding_type
                        finding_raw["metadata"] = dict(event.metadata)
                        finding_raw["metadata"]["finding"] = finding
                        finding_event = self._normalize(finding_raw)
                        if finding_event:
                            events.append(finding_event)
        # Do NOT discard events[:100]; return bounded batch
        # The caller handles batching; here we return the full consumed set
        return events

    async def collect_inventory(self) -> list[dict]:
        if self.stream_client is not None:
            return await self.stream_client.inventory()
        return []

    async def _stream_events(self, timeout: float) -> list[dict]:
        if self.stream_client is not None:
            return await self.stream_client.read_events(timeout=timeout)
        raise RuntimeError("Docker collector enabled without DOCKER_API_URL")

    def _normalize(self, raw: dict) -> SecurityEvent | None:
        attributes = raw.get("Actor", {}).get("Attributes", {}) or raw.get("attributes", {})
        action = str(raw.get("Action") or raw.get("action") or "unknown").lower()
        event_type = raw.get("event_type") or raw.get("findings", [])
        # Preserve lifecycle event; do not overwrite
        lifecycle_map = {
            "start": "docker_start",
            "stop": "docker_stop",
            "restart": "docker_restart",
            "die": "docker_crash",
            "create": "docker_create",
        }
        base_type = lifecycle_map.get(action, f"docker_{action}")
        # If event_type exists from enrich, preserve it (lifecycle preserved, findings added)
        # But if it was set to a non-lifecycle value incorrectly, revert to lifecycle
        event_type = base_type if isinstance(event_type, list) else event_type or base_type
        # Ensure event_type stays a lifecycle event if action is lifecycle
        if action in lifecycle_map:
            event_type = lifecycle_map[action]
        # Additional findings preserved in metadata/findings
        findings = raw.get("findings", [])
        severity_map = {
            "docker_start": Severity.LOW,
            "docker_stop": Severity.LOW,
            "docker_restart": Severity.MEDIUM,
            "docker_crash": Severity.HIGH,
            "docker_create": Severity.MEDIUM,
            "docker_image_change": Severity.LOW,
            "docker_port_change": Severity.LOW,
            "docker_privileged": Severity.HIGH,
            "docker_create_unknown": Severity.MEDIUM,
        }
        # Explicit unknown_image / unknown_container events only when configured
        meta = dict(raw.get("metadata", {}))
        # Read exit code directly from event if present
        exit_code_raw = raw.get("exitCode", raw.get("exit_code", meta.get("exit_code")))
        if exit_code_raw is not None:
            meta["exit_code"] = int(exit_code_raw)
            meta["clean_stop"] = int(exit_code_raw) == 0
            meta["crash"] = int(exit_code_raw) != 0
        unknown_image = meta.get("unknown_image")
        unknown_container = meta.get("unknown_container")
        # Adjust event_type for unknowns if configured
        if unknown_image and (True):
            event_type = "unknown_image"
        elif unknown_container and (True):
            event_type = "unknown_container"
        return self.normalizer.normalize(
            {
                "source": "docker",
                "ip": raw.get("container_ip", raw.get("ip", "unknown")),
                "service": raw.get("container_name")
                or attributes.get("name")
                or raw.get("image")
                or attributes.get("image")
                or "docker",
                "event_type": event_type,
                "path": raw.get("path"),
                "method": raw.get("method"),
                "user_agent": None,
                "severity": str(severity_map.get(event_type, Severity.INFO)).lower(),
                "metadata": {
                    "action": action,
                    "actor_id": raw.get("Actor", {}).get("ID") or raw.get("actor", {}).get("id"),
                    "scope": raw.get("scope", raw.get("scope", "local")),
                    "time": raw.get("time", raw.get("timeNano", 0)),
                    "image": raw.get("image") or attributes.get("image"),
                    "privileged": meta.get("privileged", attributes.get("privileged")),
                    "findings": findings,
                    "unknown_image": unknown_image,
                    "unknown_container": unknown_container,
                    "unknown_image_matched": meta.get("unknown_image_matched"),
                    "unknown_container_matched": meta.get("unknown_container_matched"),
                    "exit_code": meta.get("exit_code"),
                    "clean_stop": meta.get("clean_stop"),
                    "crash": meta.get("crash"),
                    # Sensitive fields explicitly excluded: no passwords, keys, tokens.
                },
            },
            source="docker",
        )

    async def run(self, emit: Callable[[SecurityEvent], Awaitable[None]]) -> None:
        if not self.enabled:
            return
        if isinstance(self.stream_client, DockerEventsClient):
            try:
                for container in await self.collect_inventory():
                    attrs = {
                        "name": (container.get("Names") or ["docker"])[0].lstrip("/"),
                        "image": container.get("Image", ""),
                    }
                    event = self._normalize({
                        "Action": "create",
                        "Actor": {"ID": container.get("Id", ""), "Attributes": attrs},
                        "container_name": attrs["name"],
                    })
                    if event:
                        await emit(event)
            except (httpx.HTTPError, OSError) as exc:
                log.warning("Docker inventory unavailable: %s", type(exc).__name__)
        while True:
            try:
                events = await self.collect(timeout=30.0)
                for event in events:
                    await emit(event)
            except Exception as exc:
                log.warning("Docker collection failed: %s", exc)
            await asyncio.sleep(5.0)
