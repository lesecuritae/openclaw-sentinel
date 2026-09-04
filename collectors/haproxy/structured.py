import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from core.models import SecurityEvent
from core.normalizer import EventNormalizer

log = logging.getLogger(__name__)


class HAProxyStructuredEventDecoder:
    """Decode one JSON event emitted by an HAProxy log-format or SPOE forwarder."""

    required = {"ip", "method", "path", "status"}

    def __init__(self):
        self.normalizer = EventNormalizer()

    def decode(self, payload: bytes | str) -> SecurityEvent:
        text = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end < start:
            raise ValueError("structured HAProxy event contains no JSON object")
        raw: dict[str, Any] = json.loads(text[start : end + 1])
        missing = self.required - raw.keys()
        if missing:
            raise ValueError(f"structured HAProxy event missing: {', '.join(sorted(missing))}")
        raw.setdefault("source", "haproxy")
        raw.setdefault("event_type", "request")
        raw["status"] = int(raw["status"])
        return self.normalizer.normalize(raw, source="haproxy")


class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[bytes]):
        self.queue = queue

    def datagram_received(self, data: bytes, _addr) -> None:
        self.queue.put_nowait(data)


class HAProxyRequestCollector:
    def __init__(self, host: str = "0.0.0.0", port: int = 1514):
        self.host, self.port = host, port
        self.decoder = HAProxyStructuredEventDecoder()

    async def run(self, emit: Callable[[SecurityEvent], Awaitable[None]]) -> None:
        queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=10_000)
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramProtocol(queue), local_addr=(self.host, self.port)
        )
        try:
            while True:
                try:
                    await emit(self.decoder.decode(await queue.get()))
                except (ValueError, json.JSONDecodeError) as exc:
                    log.warning("Invalid structured HAProxy event: %s", exc)
        finally:
            transport.close()
